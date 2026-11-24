import { describe, expect, it, vi } from 'vitest';
import { createGuard, GuardBlockedError, replay } from '../src/index.js';

const ok = (async () => new Response('ok')) as typeof fetch;

describe('task budgets', () => {
  it('stops a retry loop and a task with too many calls', async () => {
    const guard = createGuard({ mode: 'enforce', budget: { maxCallsPerTool: 3 } });
    const trace = guard.startTrace({ agent: 'bot' });
    for (let i = 0; i < 3; i++) await trace.tool('search', { q: 'x' }, () => []);
    await expect(trace.tool('search', { q: 'x' }, () => [])).rejects.toThrow('rule budget-exceeded');

    const other = guard.startTrace({ agent: 'bot', budget: { maxToolCalls: 2 } });
    await other.tool('a', {}, () => 1);
    await other.tool('b', {}, () => 1);
    await expect(other.tool('c', {}, () => 1)).rejects.toThrow(/2 tool calls|budget/);
    expect(replay(await guard.store.list(), { mode: 'enforce' }).changed).toEqual([]);
  });

  it('flags a task running longer than its time budget', async () => {
    vi.useFakeTimers({ now: 0 });
    try {
      const guard = createGuard({ mode: 'shadow', fetch: ok });
      const trace = guard.startTrace({ agent: 'bot', budget: { maxDurationMs: 60_000 } });
      await trace.tool('a', {}, () => 1);
      vi.setSystemTime(61_000);
      await trace.fetch('https://api.x.io');
      const last = (await trace.chain()).events.at(-1)!;
      expect(last.labels).toContain('over_budget');
      expect(last.decision?.action).toBe('would_block');
    } finally {
      vi.useRealTimers();
    }
  });
});

describe('per-task allowed domains', () => {
  it('extends the global allow-list for one task only', async () => {
    const guard = createGuard({ allowedDomains: ['api.acme.com'], fetch: ok });
    const billing = guard.startTrace({ agent: 'billing', allowedDomains: ['api.stripe.com'] });
    await billing.fetch('https://api.stripe.com/v1/charges');
    const other = guard.startTrace({ agent: 'support' });
    await other.fetch('https://api.stripe.com/v1/charges');
    expect((await billing.chain()).events[1].labels).not.toContain('egress');
    expect((await other.chain()).events[1].labels).toContain('egress');
  });
});

describe('kill switch', () => {
  it('blocks every tool call and request of every agent, whatever the mode, until resume()', async () => {
    const network = vi.fn(ok);
    const guard = createGuard({ mode: 'off', fetch: network as unknown as typeof fetch });
    const trace = guard.startTrace({ agent: 'bot' });
    guard.halt('incident #42');
    expect(guard.halted).toBe('incident #42');
    await expect(trace.fetch('https://api.acme.com')).rejects.toBeInstanceOf(GuardBlockedError);
    await expect(guard.startTrace({ agent: 'other' }).tool('x', {}, () => 1)).rejects.toThrow('Kill switch: incident #42');
    expect(network).not.toHaveBeenCalled();
    guard.resume();
    await expect(trace.fetch('https://api.acme.com')).resolves.toBeDefined();
    // replay shows the halt as it happened instead of reporting the blocked calls as "newly allowed"
    expect(replay(await guard.store.list(), { mode: 'off' }).changed).toEqual([]);
  });
});
