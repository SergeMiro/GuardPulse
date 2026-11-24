import { mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { runCli } from '../src/cli.js';
import { startCollector } from '../src/collector.js';
import { renderReport } from '../src/index.js';
import { recordAttack, recordPartnerCall } from './helpers/scenario.js';

describe('HTML report', () => {
  it('rates risk, lists the chain with advice, what blocking would stop, and escapes everything', async () => {
    const { guard } = await recordAttack();
    const events = await guard.store.list();
    events[1].target = '<script>alert(1)</script>';
    const html = renderReport(events, { generatedAt: new Date('2026-11-24T10:00:00Z') });
    expect(html).toContain('Overall risk: <span class="sev" style="background:#cf2631">CRITICAL</span>');
    expect(html).toContain('WOULD BLOCK</span> support-bot — Summarise ticket #42');
    expect(html).toContain('<td>exfil-after-injection</td><td>1</td>');
    expect(html).toContain('Advice:');
    expect(html).not.toContain('<script>');
    expect(html).toContain('&lt;script&gt;');
  });

  it('is available from the CLI (--html) and the collector (/v1/report.html)', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'st-'));
    const { guard } = await recordPartnerCall();
    const events = join(dir, 'events.jsonl');
    await writeFile(events, (await guard.store.list()).map((e) => JSON.stringify(e)).join('\n'));
    const out = join(dir, 'report.html');
    expect(await runCli(['report', events, '--html', out], () => {})).toBe(0);
    expect(await readFile(out, 'utf8')).toContain('<h2>Alerts</h2>');

    const { server, url } = await startCollector({ port: 0 });
    try {
      const res = await fetch(`${url}/v1/report.html`);
      expect(res.headers.get('content-type')).toContain('text/html');
      expect(res.headers.get('content-security-policy')).toContain("default-src 'none'");
      expect(await res.text()).toContain('No task needs attention.');
    } finally {
      server.close();
    }
  });
});
