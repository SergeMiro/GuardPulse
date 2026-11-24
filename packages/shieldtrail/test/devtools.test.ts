import { mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it, vi } from 'vitest';
import { createGuard, devtoolsUrl } from '../src/node.js';

const policy = {
  mode: 'enforce',
  rules: [{ id: 'refund-needs-human', description: 'Refunds need a human', match: { kind: 'tool_call', target: 'payments.refund' }, action: 'ask' }, 'defaults'],
};

describe('dev panel server', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'st-dev-'));
  const file = join(dir, 'shieldtrail.policy.json');
  await writeFile(file, JSON.stringify(policy, null, 2));
  const guard = createGuard({ policyFile: file, devtools: { port: 0 }, interceptFetch: false });
  const url = (await devtoolsUrl())!;
  const page = { origin: 'http://localhost:5173' };
  const get = (path: string, origin = page.origin) => fetch(url + path, { headers: { origin } });
  const post = (path: string, body: unknown, origin = page.origin) => fetch(url + path, { method: 'POST', headers: { origin, 'content-type': 'application/json' }, body: JSON.stringify(body) });

  it('serves the panel script and the full dashboard', async () => {
    expect(url).toMatch(/^http:\/\/127\.0\.0\.1:\d+$/);
    const js = await get('/panel.js');
    expect(js.headers.get('content-type')).toContain('javascript');
    expect(await js.text()).toContain('shieldtrail-devtools');
    const html = await (await get('/')).text();
    expect(html).toContain('<script src="/panel.js" data-full>');
  });

  it('accepts any localhost page, refuses other sites', async () => {
    expect((await get('/v1/page', 'http://127.0.0.1:8080')).status).toBe(200);
    expect((await get('/v1/page', 'https://evil.example')).status).toBe(403);
    expect((await post('/v1/halt', {}, 'https://evil.example')).status).toBe(403);
  });

  it('shows the page activity and lets the panel answer an ask step', async () => {
    const since = Date.now();
    const trace = guard.startTrace({ agent: 'support', task: 'refund' });
    const run = vi.fn(() => 'refunded');
    const result = trace.tool('payments.refund', { amount: 40 }, run);

    let state: { pending: Array<{ id: string; ruleId: string }>; chains: unknown[]; mode: string } = { pending: [], chains: [], mode: '' };
    await vi.waitFor(async () => {
      state = await (await get(`/v1/page?since=${since}`)).json();
      expect(state.pending).toHaveLength(1);
    });
    expect(state).toMatchObject({ mode: 'enforce', pending: [{ ruleId: 'refund-needs-human' }] });
    expect(run).not.toHaveBeenCalled();

    expect((await post(`/v1/pending/${state.pending[0].id}`, { approved: 'yes' })).status).toBe(400);
    expect((await post(`/v1/pending/${state.pending[0].id}`, { approved: true })).status).toBe(200);
    await expect(result).resolves.toBe('refunded');
    expect((await post(`/v1/pending/${state.pending[0].id}`, { approved: true })).status).toBe(404);

    const after = await (await get(`/v1/page?since=${since}`)).json();
    const step = after.chains[0].events.find((e: { kind: string }) => e.kind === 'tool_call');
    expect(step.decision).toMatchObject({ action: 'allow', approval: { approved: true, by: 'dev panel' } });
    // only what happened since the page was requested
    expect((await (await get(`/v1/page?since=${Date.now() + 60_000}`)).json()).chains).toEqual([]);
  });

  it('switches a rule mode live and writes only ruleModes to the policy file', async () => {
    const before = await (await get('/v1/policy')).json();
    expect(before.rules.find((r: { id: string }) => r.id === 'secret-egress')).toMatchObject({ action: 'block', mode: 'enforce', audit: { verdict: 'unused' } });

    expect((await post('/v1/policy/rule', { id: 'secret-egress', mode: 'shadow' })).status).toBe(200);
    expect(guard.policy.rules.find((r) => r.id === 'secret-egress')!.mode).toBe('shadow');
    const saved = JSON.parse(await readFile(file, 'utf8'));
    expect(saved).toEqual({ ...policy, ruleModes: { 'secret-egress': 'shadow' } });

    expect((await post('/v1/policy/rule', { id: 'nope', mode: 'shadow' })).status).toBe(404);
    expect((await post('/v1/policy/rule', { id: 'secret-egress', mode: 'loud' })).status).toBe(400);
    // the next start reads the switch back
    expect(createGuard({ policyFile: file, devtools: false }).policy.rules.find((r) => r.id === 'secret-egress')!.mode).toBe('shadow');
  });

  it('kill switch from the panel', async () => {
    expect(await (await post('/v1/halt', { reason: 'incident 42' })).json()).toEqual({ halted: 'incident 42' });
    expect(guard.halted).toBe('incident 42');
    await expect(guard.startTrace({ agent: 'x' }).tool('anything', {}, () => 1)).rejects.toThrow('kill-switch');
    expect(await (await post('/v1/resume', {})).json()).toEqual({ halted: null });
  });

  it('a hot-reloaded module gets the same server and keeps the history', async () => {
    const before = (await guard.store.list()).length;
    const reloaded = createGuard({ policyFile: file, devtools: { port: 0 }, interceptFetch: false });
    expect(await devtoolsUrl()).toBe(url);
    expect(reloaded.store).toBe(guard.store);
    expect(reloaded.interactive).toBe(true);
    await reloaded.startTrace({ agent: 'after-reload' }).event('ping');
    const all = await (await get('/v1/page?since=0')).json();
    expect(all.chains.some((c: { actor: string }) => c.actor === 'after-reload')).toBe(true);
    expect((await guard.store.list()).length).toBeGreaterThan(before);
  });

  it('is off outside development unless asked for', () => {
    const env = process.env.NODE_ENV;
    process.env.NODE_ENV = 'production';
    try {
      expect(createGuard({ policyFile: false }).interactive).toBe(false);
    } finally {
      process.env.NODE_ENV = env;
    }
  });
});
