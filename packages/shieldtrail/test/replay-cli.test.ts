import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { runCli } from '../src/cli.js';
import { defaultRules, replay, shadowReport } from '../src/index.js';
import { recordAttack, recordPartnerCall } from './helpers/scenario.js';

describe('replay', () => {
  it('reproduces recorded decisions under the same policy', async () => {
    const { guard } = await recordAttack();
    const result = replay(await guard.store.list(), { mode: 'shadow', allowedDomains: ['api.acme.com'] });
    expect(result.changed).toEqual([]);
    expect(result.events.at(-1)!.labels).toEqual(expect.arrayContaining(['tainted', 'egress', 'sensitive']));
  });

  it('shows what switching to enforce would stop', async () => {
    const { guard } = await recordAttack();
    const result = replay(await guard.store.list(), { mode: 'enforce', allowedDomains: ['api.acme.com'] });
    expect(result.changed).toEqual([expect.objectContaining({ kind: 'http', before: 'would_block', after: 'block' })]);
    // would_block → block is a change but not a newly stopped call: shadow mode already predicted it
    expect(result.newlyStopped).toEqual([]);
    expect(shadowReport(await guard.store.list()).wouldBlock).toEqual([{ ruleId: 'exfil-after-injection', count: 1, targets: ['https://collector.evil.io/drop'] }]);
  });

  it('a stricter rule turns an allowed call into a stop, and the diff says so', async () => {
    const { guard } = await recordPartnerCall();
    const strict = [{ id: 'no-unknown-egress', match: { kind: 'http' as const, labels: ['egress' as const] }, action: 'block' as const }, ...defaultRules];
    const result = replay(await guard.store.list(), { mode: 'enforce', rules: strict, allowedDomains: ['api.acme.com'] });
    expect(result.newlyStopped).toEqual([expect.objectContaining({ target: 'https://api.partner.io/invoices', before: 'alert', after: 'block', ruleId: 'no-unknown-egress' })]);
    const relaxed = replay(await guard.store.list(), { mode: 'enforce', allowedDomains: ['api.acme.com', '*.partner.io'] });
    expect(relaxed.changed).toEqual([expect.objectContaining({ before: 'alert', after: 'allow' })]);
  });
});

describe('cli', () => {
  it('replay exits 1 when the new policy would stop recorded traffic, report summarises shadow mode', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'gp-'));
    const { guard } = await recordPartnerCall();
    const events = join(dir, 'events.jsonl');
    await writeFile(events, (await guard.store.list()).map((e) => JSON.stringify(e)).join('\n'));
    const strict = join(dir, 'strict.json');
    await writeFile(strict, JSON.stringify({ mode: 'enforce', allowedDomains: ['api.acme.com'], rules: [{ id: 'no-unknown-egress', match: { kind: 'http', labels: ['egress'] }, action: 'block' }] }));
    const lax = join(dir, 'lax.json');
    await writeFile(lax, JSON.stringify({ mode: 'enforce', allowedDomains: ['*.partner.io'] }));

    const lines: string[] = [];
    expect(await runCli(['replay', events, '--policy', strict], (l) => lines.push(l))).toBe(1);
    expect(lines.join('\n')).toMatch(/\+ STOP {2}http https:\/\/api\.partner\.io\/invoices {2}\(alert → block, rule no-unknown-egress\)/);
    expect(await runCli(['replay', events, '--policy', lax], () => {})).toBe(0);

    const report: string[] = [];
    expect(await runCli(['report', events, '--json'], (l) => report.push(l))).toBe(0);
    expect(JSON.parse(report[0])).toMatchObject({ events: 2, traces: 1, alerts: [{ ruleId: 'unknown-domain', count: 1 }] });
    expect(await runCli([], () => {})).toBe(2);
  });
});
