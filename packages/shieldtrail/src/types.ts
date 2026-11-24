export type EventKind = 'task' | 'context' | 'tool_call' | 'http' | 'error' | 'app';

export type Label =
  | 'untrusted' // came from outside the app (document, web page, email, tool output)
  | 'injection' // contains instructions aimed at the agent
  | 'sensitive' // carries secrets or personal data
  | 'tainted' // happened after an injection entered the same trace
  | 'egress' // leaves the app towards a domain not on the allow-list
  | 'unexpected_tool' // tool not declared for the task
  | 'drift' // differs from the learned baseline
  | 'canary' // a planted honeytoken is leaving the app
  | 'over_budget' // the task exceeded its call or time budget
  | 'secret_leak'; // a real secret is going to a domain it is not meant for

export type Severity = 'low' | 'medium' | 'high' | 'critical';

/** 'ask' only lives while a human decides; the recorded decision is then allow or block, with `approval`. */
export type Action = 'allow' | 'alert' | 'block' | 'would_block' | 'ask';

export type Mode = 'off' | 'shadow' | 'enforce';

export interface Finding {
  type: string;
  severity: Severity;
  message: string;
  evidence?: Record<string, unknown>;
  /** A rule the operator can paste into the policy to act on this finding. */
  suggestedRule?: Rule;
}

export interface Decision {
  action: Action;
  ruleId?: string;
  /** For sequence rules: the earlier event that completed the pattern. */
  causeId?: string;
  reason: string;
  recommendation?: string;
  /** Set when a rule with action 'ask' put the step in front of a human. */
  approval?: { approved: boolean; by: string; at: number };
}

export interface GuardEvent {
  id: string;
  seq: number;
  ts: number;
  traceId: string;
  parentId?: string;
  kind: EventKind;
  /** Agent or service that produced the event. */
  actor: string;
  /** Tool name, URL, document source, error type… */
  target: string;
  data: Record<string, unknown>;
  labels: Label[];
  findings: Finding[];
  decision?: Decision;
}

export interface RuleMatch {
  kind?: EventKind | EventKind[];
  /** Glob(s) on event.target, `*` matches anything. */
  target?: string | string[];
  /** All of these labels must be present. */
  labels?: Label[];
  /** None of these labels may be present. */
  notLabels?: Label[];
  /**
   * Tool arguments, one glob per argument (`*` = anything). Prefix with `!` to require that the
   * value does NOT match, e.g. `{ to: '!*@acme.com' }` = an address outside acme.com.
   */
  args?: Record<string, string>;
  /** Sequence rule: an earlier event of the same task must match this too (can be nested). */
  after?: RuleMatch;
  /** Matches when the event carries a finding at or above this severity. */
  minSeverity?: Severity;
}

export interface Rule {
  id: string;
  description?: string;
  match: RuleMatch;
  /** 'ask': in enforce mode the step waits for a human (dev panel or your `approve` hook); no answer = blocked. */
  action: 'allow' | 'alert' | 'block' | 'ask';
  /** Overrides the global mode for this rule, e.g. enforce one rule while the rest stays in shadow. */
  mode?: Mode;
  recommendation?: string;
}

/** Limits for one task: a looping or hijacked agent burns money and calls before anyone notices. */
export interface Budget {
  /** Total tool calls in the task. */
  maxToolCalls?: number;
  /** Calls of the same tool in the task (retry loops). */
  maxCallsPerTool?: number;
  /** Wall-clock time from the start of the task. */
  maxDurationMs?: number;
  /** Model tokens (input + output) reported with trace.usage(). */
  maxTokens?: number;
  /** Model spend reported with trace.usage({ ..., costUsd }). */
  maxCostUsd?: number;
}

/** What `shieldtrail.policy.json` holds; the SDK, `replay`, `check` and the dashboard read the same file. */
export interface Policy {
  mode?: Mode;
  rules?: Rule[];
  allowedDomains?: string[];
  budget?: Budget;
  /**
   * Per-rule mode switches, e.g. `{ "secret-egress": "enforce" }`: block with one rule while the rest
   * only watch. Works for built-in rules too. The dev panel's observe / block toggle writes here.
   */
  ruleModes?: Record<string, Mode>;
}

/** A real secret and the only domains it may be sent to (e.g. the Stripe key → api.stripe.com). */
export interface BoundSecret {
  /** Shown in findings instead of the value, e.g. 'STRIPE_KEY'. */
  name?: string;
  /** The secret itself; unset or short values (< 8 chars) are ignored, so a missing env var is harmless. */
  value: string | undefined;
  /** Domain globs the secret belongs to. */
  domains: string[];
}

export interface PolicyConfig {
  mode: Mode;
  rules: Rule[];
}
