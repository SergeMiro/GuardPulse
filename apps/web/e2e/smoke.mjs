// Smoke test of the built static site: node apps/web/e2e/smoke.mjs [screenshotDir]
// Serves apps/web/out under /ShieldTrail (like GitHub Pages) and drives local Chrome. browser: local
import { createReadStream, existsSync, statSync } from 'node:fs';
import { createServer } from 'node:http';
import { extname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright-core';

const OUT = fileURLToPath(new URL('../out', import.meta.url));
const shots = process.argv[2];
const TYPES = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml', '.woff2': 'font/woff2', '.txt': 'text/plain', '.json': 'application/json' };

const server = createServer((req, res) => {
  const path = decodeURIComponent(new URL(req.url, 'http://x').pathname).replace(/^\/ShieldTrail/, '');
  let file = join(OUT, path);
  if (!file.startsWith(OUT) || !existsSync(file)) return res.writeHead(404).end();
  if (statSync(file).isDirectory()) file = join(file, 'index.html');
  res.writeHead(200, { 'content-type': TYPES[extname(file)] ?? 'application/octet-stream' });
  createReadStream(file).pipe(res);
}).listen(0, '127.0.0.1');
await new Promise((r) => server.once('listening', r));
const base = `http://127.0.0.1:${server.address().port}/ShieldTrail`;

const browser = await chromium.launch({ channel: 'chrome' });
const errors = [];
const check = (cond, msg) => { if (!cond) throw new Error(`FAIL: ${msg}`); console.log(`ok  ${msg}`); };
try {
  for (const width of [1280, 390]) {
    const page = await browser.newPage({ viewport: { width, height: 900 } });
    page.on('pageerror', (e) => errors.push(e.message));

    await page.goto(`${base}/`);
    check(await page.getByRole('heading', { level: 1 }).textContent().then((t) => t.includes('whole attack chain')), `landing renders (${width}px)`);
    check(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1), `no horizontal scroll on landing (${width}px)`);
    if (shots) await page.screenshot({ path: `${shots}/landing-${width}.png`, fullPage: width > 400 ? false : false });

    await page.goto(`${base}/demo/`);
    await page.locator('.react-flow__node-event').first().waitFor();
    check((await page.locator('.react-flow__node-event').count()) >= 6, `demo graph renders the chain nodes (${width}px)`);
    check(await page.locator('.gp-node.a-block').count() === 1, `demo enforce run shows one blocked node (${width}px)`);
    check((await page.locator('.kpi b').first().textContent()) === 'BLOCKED', `demo outcome is BLOCKED (${width}px)`);
    check(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1), `no horizontal scroll on demo (${width}px)`);
    if (shots) await page.screenshot({ path: `${shots}/demo-${width}.png`, fullPage: true });

    if (width > 400) {
      await page.getByRole('button', { name: /Without/ }).click();
      await page.getByRole('button', { name: /Run the attack/ }).click();
      await page.locator('.st-leaked').waitFor({ timeout: 10000 });
      await page.locator('.kpi b', { hasText: 'LEAKED' }).waitFor();
      check(await page.locator('.leak-box').textContent().then((t) => t.includes('4111 1111 1111 1111')), 'without ShieldTrail the cards leak');

      await page.getByRole('button', { name: /Shadow/ }).click();
      await page.getByRole('button', { name: /Run the attack/ }).click();
      await page.locator('.gp-node.a-would_block').waitFor({ timeout: 10000 });
      check(true, 'shadow mode shows would_block on the egress node');

      await page.goto(`${base}/dashboard/`);
      await page.locator('.chain-row').first().waitFor();
      check((await page.locator('.chain-row').count()) >= 4, 'dashboard lists demo chains');
      await page.locator('.react-flow__node-event').first().waitFor();
      check(true, 'dashboard renders the selected chain graph');
      if (shots) await page.screenshot({ path: `${shots}/dashboard-${width}.png`, fullPage: true });
    }
    await page.close();
  }
  check(errors.length === 0, `no page errors${errors.length ? `: ${errors.join(' | ')}` : ''}`);
} finally {
  await browser.close();
  server.close();
}
