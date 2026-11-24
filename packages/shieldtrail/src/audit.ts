import { defaultRules, matchRule } from './policy.js';
import { replay, type ReplayOptions } from './replay.js';
import type { GuardEvent } from './types.js';

export interface RuleStat {
  ruleId: string;
  /** Events the rule's pattern matched. */
  matched: number;
  /** Events where this rule made the decision (first match wins). */
  decided: number;
  /**
   * active: makes decisions. shadowed: matches traffic but an earlier rule always decides first, so
   * it never has any effect. unused: matched nothing in the recorded traffic.
   */
  verdict: 'active' | 'shadowed' | 'unused';
  /** For a shadowed rule: the rule that took its decisions most often. */
  shadowedBy?: string;
  /** A few targets it decided (or matched, when shadowed). */
  examples: string[];
}

/**
 * Checks a policy against recorded traffic: which rules work, which never fire, and which are
 * hidden behind an earlier rule. The same replay engine as `replay`, so the answer is exact.
 */
export function auditRules(recorded: GuardEvent[], opts: ReplayOptions = {}): RuleStat[] {
  const rules = opts.rules ?? defaultRules;
  const { events } = replay(recorded, opts);
  const stats = rules.map((r) => ({ ruleId: r.id, matched: 0, decided: 0, by: new Map<string, number>(), examples: new Set<string>() }));
  const history = new Map<string, GuardEvent[]>();
  for (const e of events) {
    const past = history.get(e.traceId) ?? [];
    rules.forEach((rule, i) => {
      if (!matchRule(rule.match, e, past).ok) return;
      const s = stats[i];
      s.matched++;
      const decider = e.decision?.ruleId;
      if (decider === rule.id) s.decided++;
      else if (decider) s.by.set(decider, (s.by.get(decider) ?? 0) + 1);
      if (s.examples.size < 3) s.examples.add(e.target);
    });
    past.push(e);
    history.set(e.traceId, past);
  }
  return stats.map(({ by, examples, ...s }) => {
    const verdict = s.matched === 0 ? 'unused' : s.decided === 0 ? 'shadowed' : 'active';
    const shadowedBy = verdict === 'shadowed' ? [...by].sort((a, b) => b[1] - a[1])[0]?.[0] : undefined;
    return { ...s, verdict, ...(shadowedBy ? { shadowedBy } : {}), examples: [...examples] };
  });
}
