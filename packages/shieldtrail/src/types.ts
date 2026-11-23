export type EventKind = 'task' | 'context' | 'tool_call' | 'http' | 'error' | 'app';

export type Label =
  | 'untrusted' // came from outside the app (document, web page, email, tool output)
  | 'injection' // contains instructions aimed at the agent
  | 'sensitive' // carries secrets or personal data
  | 'tainted' // happened after an injection entered the same trace
  | 'egress' // leaves the app towards a domain not on the allow-list
  | 'unexpected_tool' // tool not declared for the task
  | 'drift'; // differs from the learned baseline

export type Severity = 'low' | 'medium' | 'high' | 'critical';

export type Action = 'allow' | 'alert' | 'block' | 'would_block';

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
  reason: string;
  recommendation?: string;
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
  /** Matches when the event carries a finding at or above this severity. */
  minSeverity?: Severity;
}

export interface Rule {
  id: string;
  description?: string;
  match: RuleMatch;
  action: 'allow' | 'alert' | 'block';
  /** Overrides the global mode for this rule, e.g. enforce one rule while the rest stays in shadow. */
  mode?: Mode;
  recommendation?: string;
}

export interface PolicyConfig {
  mode: Mode;
  rules: Rule[];
}
