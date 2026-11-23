import { Analyzer } from './analyzer.js';
import { defaultRules } from './policy.js';
import type { Action, GuardEvent, Mode, Rule } from './types.js';

export interface ReplayOptions {
  mode?: Mode;
  rules?: Rule[];
  allowedDomains?: string[];
}

export interface ReplayDecision {
  eventId: string;
  traceId: string;
  kind: GuardEvent['kind'];
  target: string;
  before?: Action;
  after: Action;
  ruleId?: string;
}

export interface ReplayResult {
  events: GuardEvent[];
  decisions: ReplayDecision[];
  /** Decisions that differ from what was recorded. */
  changed: ReplayDecision[];
  /** Recorded as allowed/alerted, would now be stopped (block or would_block). */
  newlyStopped: ReplayDecision[];
  /** Recorded as stopped, would now pass. */
  newlyAllowed: ReplayDecision[];
}

const stops = (a?: Action) => a === 'block' || a === 'would_block';

/**
 * Re-runs recorded events through a (new) policy from a clean state, so a rule change can be
 * checked against real traffic before it ships.
 */
export function replay(recorded: GuardEvent[], opts: ReplayOptions = {}): ReplayResult {
  const analyzer = new Analyzer({ policy: { mode: opts.mode ?? 'enforce', rules: opts.rules ?? defaultRules }, allowedDomains: opts.allowedDomains ?? [] });
  const events: GuardEvent[] = [];
  const decisions: ReplayDecision[] = [];
  for (const old of [...recorded].sort((a, b) => a.seq - b.seq)) {
    const { taintFrom, sensitiveFrom, host, ...data } = old.data;
    const fresh = analyzer.process({ ...old, data, labels: [], findings: [], decision: undefined }, { ...data, prior: old });
    events.push(fresh);
    decisions.push({ eventId: old.id, traceId: old.traceId, kind: old.kind, target: old.target, before: old.decision?.action, after: fresh.decision!.action, ruleId: fresh.decision?.ruleId });
  }
  const changed = decisions.filter((d) => d.before !== d.after);
  return {
    events,
    decisions,
    changed,
    newlyStopped: changed.filter((d) => stops(d.after) && !stops(d.before)),
    newlyAllowed: changed.filter((d) => stops(d.before) && !stops(d.after)),
  };
}

export interface ShadowReport {
  events: number;
  traces: number;
  /** What enforce mode would have stopped, grouped by rule. */
  wouldBlock: Array<{ ruleId: string; count: number; targets: string[] }>;
  alerts: Array<{ ruleId: string; count: number; targets: string[] }>;
  blocked: number;
}

/** "What would ShieldTrail have blocked?" — the report to read before switching a rule to enforce. */
export function shadowReport(events: GuardEvent[]): ShadowReport {
  const group = (action: Action) => {
    const by = new Map<string, { ruleId: string; count: number; targets: Set<string> }>();
    for (const e of events) {
      if (e.decision?.action !== action) continue;
      const id = e.decision.ruleId ?? 'unknown';
      const g = by.get(id) ?? { ruleId: id, count: 0, targets: new Set<string>() };
      g.count++;
      g.targets.add(e.target);
      by.set(id, g);
    }
    return [...by.values()].sort((a, b) => b.count - a.count).map((g) => ({ ...g, targets: [...g.targets].slice(0, 5) }));
  };
  return {
    events: events.length,
    traces: new Set(events.map((e) => e.traceId)).size,
    wouldBlock: group('would_block'),
    alerts: group('alert'),
    blocked: events.filter((e) => e.decision?.action === 'block').length,
  };
}
