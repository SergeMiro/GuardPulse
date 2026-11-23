import { describe, expect, it } from 'vitest';
import { runScenario } from '../src/scenario.js';

describe('demo scenario', () => {
  it('without ShieldTrail the customer data reaches the attacker', async () => {
    const r = await runScenario('off');
    expect(r.leaked).toHaveLength(1);
    expect(r.leaked[0].body).toContain('4111 1111 1111 1111');
    expect(r.steps.at(-2)!.status).toBe('leaked');
    expect(r.steps.map((s) => s.key)).toEqual(['ticket', 'attachment', 'injection', 'query', 'exfil', 'reply']);
  });

  it('shadow mode lets it through but says ShieldTrail would have blocked it', async () => {
    const r = await runScenario('shadow');
    expect(r.leaked).toHaveLength(1);
    expect(r.chain!.wouldBlock).toBe(true);
    expect(r.report!.wouldBlock[0].ruleId).toBe('exfil-after-injection');
  });

  it('enforce mode blocks the exfiltration, keeps the app working and saves the chain', async () => {
    const r = await runScenario('enforce');
    expect(r.leaked).toEqual([]);
    expect(r.steps.map((s) => s.status)).toEqual(['ok', 'alert', 'alert', 'alert', 'blocked', 'ok']);
    // every step points at the event it produced, so the page can highlight it in the graph
    const ids = new Set(r.chain!.events.map((e) => e.id));
    expect(r.steps.every((s) => s.eventId && ids.has(s.eventId))).toBe(true);
    expect(r.chain!.events.find((e) => e.id === r.steps[4].eventId)!.decision?.action).toBe('block');
    const chain = r.chain!;
    expect(chain.blocked).toBe(true);
    expect(chain.severity).toBe('critical');
    expect(chain.edges.filter((e) => e.type !== 'sequence').length).toBeGreaterThanOrEqual(2);
    expect(r.drift.map((f) => f.type)).toEqual(expect.arrayContaining(['drift.new_tool', 'drift.new_domain']));
  });
});
