import { globMatch, maxSeverity, severityRank } from './detectors.js';
import type { Decision, GuardEvent, PolicyConfig, Rule, RuleMatch } from './types.js';

/** Live tool arguments, attached by the analyzer for the duration of one evaluation (never serialised). */
export const RAW_ARGS = Symbol('shieldtrail.rawArgs');

function argsOf(event: GuardEvent): Record<string, unknown> | undefined {
  const raw = (event as unknown as Record<symbol, unknown>)[RAW_ARGS] ?? event.data.args;
  if (raw && typeof raw === 'object') return raw as Record<string, unknown>;
  if (typeof raw !== 'string') return undefined;
  try {
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === 'object' ? parsed : undefined;
  } catch {
    return undefined; // stored args are truncated past 500 chars
  }
}

function argsMatch(patterns: Record<string, string>, event: GuardEvent): boolean {
  const args = argsOf(event);
  if (!args) return false;
  return Object.entries(patterns).every(([key, pattern]) => {
    const value = args[key];
    if (value === undefined) return false;
    // arrays (several recipients…): the rule fires if ANY element matches; with '!', if any element falls outside
    const items = (Array.isArray(value) ? value : [value]).map((v) => (typeof v === 'string' ? v : JSON.stringify(v)));
    if (items.length === 0) return false;
    return pattern.startsWith('!') ? items.some((t) => !globMatch(pattern.slice(1), t)) : items.some((t) => globMatch(pattern, t));
  });
}

/**
 * Does `event` match? For sequence rules (`after`), `history` holds the earlier events of the same
 * trace, oldest first; the result then names the earlier event that completed the pattern.
 */
export function matchRule(match: RuleMatch, event: GuardEvent, history: GuardEvent[] = [], end = history.length): { ok: boolean; causeId?: string } {
  if (!matches({ ...match, after: undefined }, event)) return { ok: false };
  if (!match.after) return { ok: true };
  for (let i = end - 1; i >= 0; i--) {
    if (matchRule(match.after, history[i], history, i).ok) return { ok: true, causeId: history[i].id };
  }
  return { ok: false };
}

/** True when some rule needs the earlier steps of a task (sequence rules). */
export const usesSequence = (rules: Rule[]) => rules.some((r) => r.match.after !== undefined);

export function matches(match: RuleMatch, event: GuardEvent): boolean {
  if (match.after) return false; // needs history: use matchRule
  if (match.args && !argsMatch(match.args, event)) return false;
  if (match.kind && ![match.kind].flat().includes(event.kind)) return false;
  if (match.target && ![match.target].flat().some((g) => globMatch(g, event.target))) return false;
  if (match.labels && !match.labels.every((l) => event.labels.includes(l))) return false;
  if (match.notLabels?.some((l) => event.labels.includes(l))) return false;
  if (match.minSeverity) {
    const top = maxSeverity(event.findings.map((f) => f.severity));
    if (!top || severityRank(top) < severityRank(match.minSeverity)) return false;
  }
  return true;
}

/** First matching rule wins, so put `allow` exceptions before broad `block` rules. */
export function evaluate(event: GuardEvent, config: PolicyConfig, history: GuardEvent[] = []): Decision {
  let causeId: string | undefined;
  const rule = config.rules.find((r) => {
    const m = matchRule(r.match, event, history);
    causeId = m.causeId;
    return m.ok;
  });
  if (!rule) return { action: 'allow', reason: 'no rule matched' };
  const base = { ruleId: rule.id, reason: rule.description ?? rule.id, recommendation: rule.recommendation, ...(causeId ? { causeId } : {}) };
  const mode = rule.mode ?? config.mode;
  if (rule.action !== 'block' || mode === 'off') return { action: rule.action === 'block' ? 'alert' : rule.action, ...base };
  return { action: mode === 'enforce' ? 'block' : 'would_block', ...base };
}

/** The attack-chain rules ShieldTrail ships with. */
/**
 * The attack-chain rules ShieldTrail ships with. Two protections sit above any rule set and block
 * in every mode: the kill switch and planted canaries ('canary-leak').
 */
export const defaultRules: Rule[] = [
  {
    id: 'exfil-after-injection',
    description: 'Outbound request to an unknown domain from a trace that ingested a prompt injection',
    match: { kind: 'http', labels: ['tainted', 'egress'] },
    action: 'block',
    recommendation: 'Treat the source document as hostile, rotate any credential the agent could read, and add the domain to a deny-list.',
  },
  {
    id: 'secret-egress',
    description: 'Secrets or personal data sent to a domain outside the allow-list',
    match: { kind: 'http', labels: ['sensitive', 'egress'] },
    action: 'block',
    recommendation: 'Redact the payload before it leaves the app, or add the destination to allowedDomains if it is legitimate.',
  },
  {
    id: 'budget-exceeded',
    description: 'Task went over its tool-call or time budget',
    match: { labels: ['over_budget'] },
    action: 'block',
    recommendation: 'Look for a retry loop or a hijacked agent in the chain; raise the budget only if the task really needs it.',
  },
  {
    id: 'tool-after-injection',
    description: 'Tool outside the task scope called after a prompt injection',
    match: { kind: 'tool_call', labels: ['tainted', 'unexpected_tool'] },
    // alert by default: allowedTools lists are rarely complete, so blocking here breaks apps; switch to block once tuned
    action: 'alert',
    recommendation: 'Restrict allowedTools for this task, then turn this rule into a block.',
  },
  {
    id: 'unknown-domain',
    description: 'Request to a domain outside the allow-list',
    match: { kind: 'http', labels: ['egress'] },
    action: 'alert',
    recommendation: 'Confirm the domain is expected, then add it to allowedDomains.',
  },
  {
    id: 'unexpected-tool',
    description: 'Tool not declared for this task',
    match: { kind: 'tool_call', labels: ['unexpected_tool'] },
    action: 'alert',
  },
  {
    id: 'injection-seen',
    description: 'Prompt injection in untrusted content',
    match: { kind: 'context', labels: ['injection'] },
    action: 'alert',
  },
];
