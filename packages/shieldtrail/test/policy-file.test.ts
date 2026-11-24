import { mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it, vi } from 'vitest';
import { runCli } from '../src/cli.js';
import { auditRules, defaultRules, parsePolicy, PolicyError, type Rule } from '../src/index.js';
import { createGuard, loadPolicy, savePolicy } from '../src/node.js';
import { recordAttack, recordPartnerCall } from './helpers/scenario.js';

const tmp = () => mkdtemp(join(tmpdir(), 'st-policy-'));

describe('parsePolicy', () => {
  it('expands "defaults" where it stands and keeps custom rules around it', () => {
    const p = parsePolicy({ mode: 'enforce', rules: [{ id: 'mine', match: { kind: 'http' }, action: 'alert' }, 'defaults'] });
    expect(p.rules!.map((r) => r.id)).toEqual(['mine', ...defaultRules.map((r) => r.id)]);
  });

  it('names the exact place of a mistake', () => {
    expect(() => parsePolicy({ mode: 'strict' })).toThrow('mode must be one of off, shadow, enforce');
    expect(() => parsePolicy({ rules: [{ id: 'a', match: {}, action: 'deny' }] })).toThrow('rules[0] (a): action must be one of allow, alert, block');
    expect(() => parsePolicy({ rules: [{ id: 'a', match: { labels: ['tained'] }, action: 'block' }] })).toThrow('rules[0] (a).match: labels must be a list of');
    expect(() => parsePolicy({ rules: [{ id: 'a', match: { after: { kindd: 'http' } }, action: 'block' }] })).toThrow('rules[0] (a).match.after: unknown key "kindd"');
    expect(() => parsePolicy({ rules: [{ id: 'exfil-after-injection', match: {}, action: 'block' }, 'defaults'] })).toThrow('used twice');
    expect(() => parsePolicy({ budget: { maxToolCalls: -1 } })).toThrow('budget.maxToolCalls must be a positive number');
    expect(() => parsePolicy([])).toThrow(PolicyError);
  });
});

describe('policy file', () => {
  it('createGuard reads shieldtrail.policy.json; code options win over the file', async () => {
    const dir = await tmp();
    const file = join(dir, 'shieldtrail.policy.json');
    savePolicy({ mode: 'enforce', allowedDomains: ['api.acme.com'], rules: [{ id: 'no-partner', match: { kind: 'http', target: '*partner.io*' }, action: 'block' }] }, file);
    expect(JSON.parse(await readFile(file, 'utf8')).mode).toBe('enforce');

    const net = vi.fn(async () => new Response('ok'));
    const guard = createGuard({ policyFile: file, fetch: net as unknown as typeof fetch });
    expect(guard.policy).toMatchObject({ mode: 'enforce', allowedDomains: ['api.acme.com'] });
    const trace = guard.startTrace({ agent: 'bot' });
    await expect(trace.fetch('https://api.partner.io/x')).rejects.toThrow('rule no-partner');
    await trace.fetch('https://api.acme.com/ok');
    expect(net).toHaveBeenCalledOnce();

    expect(createGuard({ policyFile: file, mode: 'shadow' }).policy.mode).toBe('shadow');
    expect(createGuard({ policyFile: false }).policy.rules).toBe(defaultRules);
  });

  it('a missing default file is fine, a missing explicit file and a broken file are errors', async () => {
    const dir = await tmp();
    const cwd = process.cwd();
    process.chdir(dir);
    try {
      expect(loadPolicy()).toBeUndefined();
    } finally {
      process.chdir(cwd);
    }
    expect(() => loadPolicy(join(dir, 'nope.json'))).toThrow('file not found');
    const bad = join(dir, 'bad.json');
    await writeFile(bad, '{"rules": [{"id": "x"}]}');
    expect(() => loadPolicy(bad)).toThrow(/bad\.json: rules\[0\] \(x\): action/);
    expect(() => savePolicy({ mode: 'nope' as 'off' }, join(dir, 'never.json'))).toThrow(PolicyError);
  });

  it('setPolicy changes a running guard, including turning on sequence rules', async () => {
    const guard = createGuard({ policyFile: false, mode: 'shadow' });
    const rule: Rule = { id: 'forward-after-inbox', match: { kind: 'tool_call', target: 'email.send', after: { target: 'email.inbox' } }, action: 'block', mode: 'enforce' };
    guard.setPolicy({ rules: [rule, ...defaultRules] });
    const trace = guard.startTrace({ agent: 'mail' });
    await trace.tool('email.inbox', {}, () => []);
    await expect(trace.tool('email.send', { to: 'x@evil.io' }, () => 'sent')).rejects.toThrow('forward-after-inbox');
  });
});

describe('auditRules', () => {
  it('tells active, shadowed and unused rules apart, on the same engine as replay', async () => {
    const { guard } = await recordAttack();
    const rules: Rule[] = [
      ...defaultRules,
      { id: 'late-egress-block', match: { kind: 'http', labels: ['egress'] }, action: 'block' },
      { id: 'never', match: { kind: 'tool_call', target: 'payments.*' }, action: 'block' },
    ];
    const stats = auditRules(await guard.store.list(), { mode: 'shadow', rules, allowedDomains: ['api.acme.com'] });
    const by = Object.fromEntries(stats.map((s) => [s.ruleId, s]));
    expect(by['exfil-after-injection']).toMatchObject({ verdict: 'active', decided: 1 });
    expect(by['late-egress-block']).toMatchObject({ verdict: 'shadowed', shadowedBy: 'exfil-after-injection', decided: 0 });
    expect(by.never).toMatchObject({ verdict: 'unused', matched: 0 });
  });

  it('check validates the file and reports per rule; replay reads the same file', async () => {
    const dir = await tmp();
    const { guard } = await recordPartnerCall();
    const events = join(dir, 'events.jsonl');
    await writeFile(events, (await guard.store.list()).map((e) => JSON.stringify(e)).join('\n'));
    const policy = join(dir, 'p.json');
    await writeFile(policy, JSON.stringify({ allowedDomains: ['api.acme.com'], rules: ['defaults', { id: 'partner-block', match: { kind: 'http', target: '*partner.io*' }, action: 'block' }] }));

    const lines: string[] = [];
    expect(await runCli(['check', events, '--policy', policy], (l) => lines.push(l))).toBe(0);
    expect(lines.join('\n')).toMatch(/shadowed partner-block {2}matches 1× but "unknown-domain" always decides first/);
    expect(lines.join('\n')).toMatch(/active {3}unknown-domain {2}decided 1×/);

    const ok: string[] = [];
    expect(await runCli(['check', '--policy', policy], (l) => ok.push(l))).toBe(0);
    expect(ok[0]).toMatch(/✓ policy is valid: 9 rules/);

    const broken = join(dir, 'broken.json');
    await writeFile(broken, '{"mode":"loud"}');
    const err: string[] = [];
    expect(await runCli(['check', '--policy', broken], (l) => err.push(l))).toBe(1);
    expect(err[0]).toMatch(/✗ .*broken\.json: mode must be one of/);
  });
});
