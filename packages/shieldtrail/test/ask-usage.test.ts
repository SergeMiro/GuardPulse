import { describe, expect, it, vi } from 'vitest';
import { createGuard, defaultRules, parsePolicy, replay, type Rule } from '../src/index.js';

const askRefund: Rule = { id: 'refund-needs-human', description: 'Refunds over the counter need a human', match: { kind: 'tool_call', target: 'payments.refund' }, action: 'ask' };
const rules = [askRefund, ...defaultRules];

describe("action 'ask'", () => {
  it('runs the step when the approve hook says yes, and records who approved', async () => {
    const approve = vi.fn(async () => ({ approved: true, by: 'alice (slack)' }));
    const guard = createGuard({ mode: 'enforce', rules, approve });
    const trace = guard.startTrace({ agent: 'support' });
    const run = vi.fn(() => 'refunded');
    await expect(trace.tool('payments.refund', { amount: 900 }, run)).resolves.toBe('refunded');
    expect(approve).toHaveBeenCalledWith(expect.objectContaining({ ruleId: 'refund-needs-human', event: expect.objectContaining({ target: 'payments.refund' }) }));
    const step = (await trace.chain()).events.find((e) => e.kind === 'tool_call')!;
    expect(step.decision).toMatchObject({ action: 'allow', ruleId: 'refund-needs-human', approval: { approved: true, by: 'alice (slack)' } });
    expect(step.decision!.reason).toContain('approved by alice (slack)');
  });

  it('blocks on no, on a failing hook, on timeout, and when nobody can answer', async () => {
    const cases: Array<[string, Parameters<typeof createGuard>[0], RegExp]> = [
      ['no', { approve: () => false }, /denied by approve hook/],
      ['hook throws', { approve: () => Promise.reject(new Error('slack down')), onError: () => {} }, /denied by approve hook failed/],
      ['timeout', { approve: () => new Promise<boolean>(() => {}), approvalTimeoutMs: 20 }, /no answer in time/],
      ['nobody', {}, /no approver is set up/],
    ];
    for (const [, opts, reason] of cases) {
      const guard = createGuard({ mode: 'enforce', rules, ...opts });
      const run = vi.fn();
      await expect(guard.startTrace({ agent: 'support' }).tool('payments.refund', {}, run)).rejects.toThrow(reason);
      expect(run).not.toHaveBeenCalled();
      expect(guard.pending.size).toBe(0);
    }
  });

  it('the dev panel answers through guard.pending / guard.answer', async () => {
    const guard = createGuard({ mode: 'enforce', rules });
    guard.interactive = true;
    const trace = guard.startTrace({ agent: 'support' });
    const result = trace.tool('payments.refund', { amount: 50 }, () => 'ok');
    await vi.waitFor(() => expect(guard.pending.size).toBe(1));
    const [id] = guard.pending.keys();
    expect(guard.answer(id, true, 'dev panel')).toBe(true);
    expect(guard.answer(id, false)).toBe(false); // already answered
    await expect(result).resolves.toBe('ok');
  });

  it('shadow mode never waits: the step runs and is recorded as would_block; replay keeps answered steps as they were', async () => {
    const shadow = createGuard({ mode: 'shadow', rules });
    const t = shadow.startTrace({ agent: 'support' });
    await t.tool('payments.refund', {}, () => 'ok');
    expect((await t.chain()).events.at(-1)!.decision).toMatchObject({ action: 'would_block', ruleId: 'refund-needs-human' });

    const live = createGuard({ mode: 'enforce', rules, approve: () => true });
    const t2 = live.startTrace({ agent: 'support' });
    await t2.tool('payments.refund', {}, () => 'ok');
    const same = replay(await live.store.list(), { mode: 'enforce', rules });
    expect(same.changed).toEqual([]);
    // a new 'ask' rule on recorded traffic is a stop the release gate must see
    const shadowEvents = await shadow.store.list();
    const before = replay(shadowEvents, { mode: 'enforce', rules: defaultRules });
    expect(before.newlyStopped).toEqual([]);
    expect(replay(before.events, { mode: 'enforce', rules }).newlyStopped).toEqual([expect.objectContaining({ after: 'ask', ruleId: 'refund-needs-human' })]);
  });

  it('is accepted in the policy file', () => {
    expect(parsePolicy({ rules: [{ id: 'x', match: { kind: 'tool_call' }, action: 'ask' }] }).rules![0].action).toBe('ask');
  });
});

describe('token and spend budgets', () => {
  it('takes OpenAI, Anthropic and AI SDK usage shapes, and stops the next action once over budget', async () => {
    const net = vi.fn(async () => new Response('ok'));
    const guard = createGuard({ mode: 'enforce', allowedDomains: ['api.acme.com'], budget: { maxTokens: 1000, maxCostUsd: 0.5 }, fetch: net as unknown as typeof fetch });
    const trace = guard.startTrace({ agent: 'researcher' });
    await trace.usage({ prompt_tokens: 300, completion_tokens: 100 }); // OpenAI
    await trace.usage({ input_tokens: 200, output_tokens: 100 }, { model: 'claude', costUsd: 0.1 }); // Anthropic
    await trace.fetch('https://api.acme.com/a'); // 700 tokens: fine
    await trace.usage({ inputTokens: 250, outputTokens: 100 }); // AI SDK → 1050
    await expect(trace.fetch('https://api.acme.com/b')).rejects.toThrow('budget-exceeded');
    expect(net).toHaveBeenCalledOnce();
    const last = (await trace.chain()).events.at(-1)!;
    expect(last.findings.find((f) => f.type === 'budget.exceeded')!.message).toContain('1050 model tokens (budget 1000)');

    const spend = createGuard({ mode: 'enforce', budget: { maxCostUsd: 0.5 }, allowedDomains: ['api.acme.com'], fetch: net as unknown as typeof fetch });
    const t2 = spend.startTrace({ agent: 'researcher' });
    await t2.usage(undefined, { costUsd: 0.6 });
    await expect(t2.tool('search', {}, () => 1)).rejects.toThrow('budget-exceeded');
    expect((await t2.chain()).events.at(-1)!.findings.map((f) => f.message).join()).toContain('$0.60 spent on the model (budget $0.5)');

    // replay sees the same spend from the stored usage events
    expect(replay(await guard.store.list(), { mode: 'enforce' }).changed).toEqual([]);
  });
});
