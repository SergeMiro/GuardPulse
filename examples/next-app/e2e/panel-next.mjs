// End-to-end check on a real Next.js app in local Chrome (browser: local): `next dev` with
// ShieldTrail from shieldtrail/node, the dev panel added in the root layout.
// Run from the repo root: npm run test:next
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { readFile, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright-core';

const DIR = fileURLToPath(new URL('..', import.meta.url));
const PORT = 3100;
const APP = `http://localhost:${PORT}`;
const PANEL = 'http://127.0.0.1:4320';
const SHOTS = process.env.SHOTS_DIR;
const policyPath = `${DIR}shieldtrail.policy.json`;
const policyBefore = await readFile(policyPath, 'utf8');

const dev = spawn('npx', ['next', 'dev', '--port', String(PORT), '--hostname', '127.0.0.1'], { cwd: DIR, env: { ...process.env, NODE_ENV: 'development' }, stdio: ['ignore', 'pipe', 'pipe'], detached: true });
let log = '';
dev.stdout.on('data', (d) => (log += d));
dev.stderr.on('data', (d) => (log += d));

async function waitFor(url, ms = 60_000) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    try {
      if ((await fetch(url)).ok) return;
    } catch {}
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error(`${url} did not answer in time\n${log}`);
}

const browser = await chromium.launch({ channel: 'chrome' });
const page = await browser.newPage({ viewport: { width: 1280, height: 820 } });
const errors = [];
page.on('pageerror', (e) => errors.push(e.message));
const shadow = (sel, opts) => page.locator('#shieldtrail-devtools').locator(sel, opts);
try {
  await waitFor(`${APP}/`);
  // the panel server starts with the first request that loads the guard
  await page.goto(`${APP}/support`);
  await waitFor(`${PANEL}/panel.js`);

  // 1. home: no agent, no shield
  await page.goto(`${APP}/`);
  await page.waitForTimeout(2500);
  assert.equal(await shadow('.badge').count(), 0, 'no shield on a page without agents');

  // 2. support: the hidden instruction is obeyed, the exfiltration is blocked inside Next's own fetch
  await page.goto(`${APP}/support`);
  assert.match(await page.locator('#verdict').innerText(), /Blocked by ShieldTrail: .*exfil-after-injection/);
  await shadow('.badge').waitFor({ timeout: 10_000 });
  await shadow('.badge').click();
  const card = await shadow('.card').innerText();
  assert.match(card, /support-bot — Answer ticket #4521/);
  assert.match(card, /POST exfil\.attacker\.dev/);
  if (SHOTS) await page.screenshot({ path: `${SHOTS}/next-support.png` });

  // 3. refund: the API route waits until the step is approved in the panel
  await page.goto(`${APP}/refund`);
  await page.getByRole('button', { name: 'Refund 40 EUR' }).click();
  await shadow('.badge.pulse').waitFor({ timeout: 10_000 });
  assert.match(await page.locator('#status').innerText(), /Waiting for approval/);
  await shadow('.badge').click();
  await shadow('[role=tab]', { hasText: 'Approvals' }).click();
  if (SHOTS) await page.screenshot({ path: `${SHOTS}/next-ask.png` });
  await shadow('button', { hasText: 'Allow once' }).click();
  await page.locator('#status', { hasText: 'Refund done: re_77_40' }).waitFor({ timeout: 10_000 });

  // 4. full dashboard lists both tasks
  await page.goto(`${PANEL}/`);
  await page.locator('#shieldtrail-devtools .item', { hasText: 'billing-bot' }).waitFor({ timeout: 10_000 });
  assert.ok(await page.locator('#shieldtrail-devtools .item', { hasText: 'support-bot' }).count());

  assert.deepEqual(errors, [], 'no page errors');
  console.log('next.js e2e: all checks passed (browser: local)');
} catch (err) {
  console.error(err, '\n--- next dev log ---\n', log.slice(-3000));
  if (SHOTS) await page.screenshot({ path: `${SHOTS}/next-failure.png` });
  process.exitCode = 1;
} finally {
  await browser.close();
  // npx starts next, which starts next-server: stop the whole group
  try {
    process.kill(-dev.pid, 'SIGTERM');
  } catch {}
  // the panel may have written rule switches: leave the example as it was
  if ((await readFile(policyPath, 'utf8')) !== policyBefore) await writeFile(policyPath, policyBefore);
  process.exit(process.exitCode ?? 0);
}
