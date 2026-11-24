import { globMatch, maxSeverity, severityRank } from './detectors.js';
import type { Decision, GuardEvent, Policy, PolicyConfig, Rule, RuleMatch } from './types.js';

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
  const stopping = rule.action === 'block' || rule.action === 'ask';
  if (!stopping || mode === 'off') return { action: stopping ? 'alert' : rule.action, ...base };
  if (mode !== 'enforce') return { action: 'would_block', ...base };
  return { action: rule.action, ...base };
}

/**
 * The attack-chain rules ShieldTrail ships with. Two protections sit above any rule set and block
 * in every mode: the kill switch and planted canaries ('canary-leak').
 */
export const defaultRules: Rule[] = [
  {
    id: 'secret-wrong-domain',
    description: 'A secret is being sent to a domain it does not belong to',
    match: { kind: 'http', labels: ['secret_leak'] },
    action: 'block',
    recommendation: 'Find the step that put the secret in the request (prompt injection, logging, a wrong base URL), and rotate the secret if the request was not blocked.',
  },
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

const MODES = ['off', 'shadow', 'enforce'];
const RULE_ACTIONS = ['allow', 'alert', 'block', 'ask'];
const KINDS = ['task', 'context', 'tool_call', 'http', 'error', 'app'];
const LABELS = ['untrusted', 'injection', 'sensitive', 'tainted', 'egress', 'unexpected_tool', 'drift', 'canary', 'over_budget', 'secret_leak'];
const SEVERITY = ['low', 'medium', 'high', 'critical'];
const MATCH_KEYS = ['kind', 'target', 'labels', 'notLabels', 'args', 'after', 'minSeverity'];

export class PolicyError extends Error {
  name = 'PolicyError';
}

const isObj = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);

function checkMatch(m: unknown, at: string): void {
  const fail = (msg: string) => {
    throw new PolicyError(`${at}: ${msg}`);
  };
  if (!isObj(m)) fail('must be an object');
  const match = m as Record<string, unknown>;
  for (const k of Object.keys(match)) if (!MATCH_KEYS.includes(k)) fail(`unknown key "${k}" (expected one of ${MATCH_KEYS.join(', ')})`);
  const list = (v: unknown) => (Array.isArray(v) ? v : [v]);
  if (match.kind !== undefined && !list(match.kind).every((k) => KINDS.includes(k as string))) fail(`kind must be one of ${KINDS.join(', ')}`);
  if (match.target !== undefined && !list(match.target).every((t) => typeof t === 'string')) fail('target must be a glob or a list of globs');
  for (const key of ['labels', 'notLabels'] as const) {
    const v = match[key];
    if (v !== undefined && !(Array.isArray(v) && v.every((l) => LABELS.includes(l)))) fail(`${key} must be a list of: ${LABELS.join(', ')}`);
  }
  if (match.args !== undefined && !(isObj(match.args) && Object.values(match.args).every((v) => typeof v === 'string'))) fail('args must map argument names to glob strings');
  if (match.minSeverity !== undefined && !SEVERITY.includes(match.minSeverity as string)) fail(`minSeverity must be one of ${SEVERITY.join(', ')}`);
  if (match.after !== undefined) checkMatch(match.after, `${at}.after`);
}

/**
 * Validates a policy (the parsed `shieldtrail.policy.json`) and returns it ready to use. Errors name
 * the exact place, e.g. `rules[2].match.labels`. In `rules`, the string "defaults" stands for the
 * built-in rules, so a file can add its own rules before or after them.
 */
export function parsePolicy(input: unknown): Policy {
  if (!isObj(input)) throw new PolicyError('policy must be a JSON object');
  const out: Policy = {};
  if (input.mode !== undefined) {
    if (!MODES.includes(input.mode as string)) throw new PolicyError(`mode must be one of ${MODES.join(', ')}`);
    out.mode = input.mode as Policy['mode'];
  }
  if (input.allowedDomains !== undefined) {
    if (!(Array.isArray(input.allowedDomains) && input.allowedDomains.every((d) => typeof d === 'string'))) throw new PolicyError('allowedDomains must be a list of domain globs');
    out.allowedDomains = input.allowedDomains as string[];
  }
  if (input.budget !== undefined) {
    if (!isObj(input.budget)) throw new PolicyError('budget must be an object');
    for (const [k, v] of Object.entries(input.budget)) {
      if (!['maxToolCalls', 'maxCallsPerTool', 'maxDurationMs', 'maxTokens', 'maxCostUsd'].includes(k)) throw new PolicyError(`budget: unknown key "${k}"`);
      if (!(typeof v === 'number' && v > 0)) throw new PolicyError(`budget.${k} must be a positive number`);
    }
    out.budget = input.budget as Policy['budget'];
  }
  if (input.rules !== undefined) {
    if (!Array.isArray(input.rules)) throw new PolicyError('rules must be a list');
    const rules: Rule[] = [];
    input.rules.forEach((r, i) => {
      if (r === 'defaults') return void rules.push(...defaultRules);
      const at = `rules[${i}]`;
      if (!isObj(r)) throw new PolicyError(`${at}: must be a rule object or "defaults"`);
      if (typeof r.id !== 'string' || !r.id) throw new PolicyError(`${at}: id is required`);
      if (!RULE_ACTIONS.includes(r.action as string)) throw new PolicyError(`${at} (${r.id}): action must be one of ${RULE_ACTIONS.join(', ')}`);
      if (r.mode !== undefined && !MODES.includes(r.mode as string)) throw new PolicyError(`${at} (${r.id}): mode must be one of ${MODES.join(', ')}`);
      checkMatch(r.match, `${at} (${r.id}).match`);
      rules.push(r as unknown as Rule);
    });
    const seen = new Set<string>();
    for (const r of rules) {
      if (seen.has(r.id)) throw new PolicyError(`rule id "${r.id}" is used twice`);
      seen.add(r.id);
    }
    out.rules = rules;
  }
  return out;
}
