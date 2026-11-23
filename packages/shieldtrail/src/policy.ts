import { globMatch, maxSeverity, severityRank } from './detectors.js';
import type { Decision, GuardEvent, PolicyConfig, Rule, RuleMatch } from './types.js';

export function matches(match: RuleMatch, event: GuardEvent): boolean {
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
export function evaluate(event: GuardEvent, config: PolicyConfig): Decision {
  const rule = config.rules.find((r) => matches(r.match, event));
  if (!rule) return { action: 'allow', reason: 'no rule matched' };
  const reason = rule.description ?? rule.id;
  const mode = rule.mode ?? config.mode;
  if (rule.action !== 'block' || mode === 'off') {
    return { action: rule.action === 'block' ? 'alert' : rule.action, ruleId: rule.id, reason, recommendation: rule.recommendation };
  }
  return { action: mode === 'enforce' ? 'block' : 'would_block', ruleId: rule.id, reason, recommendation: rule.recommendation };
}

/** The attack-chain rules ShieldTrail ships with. */
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
