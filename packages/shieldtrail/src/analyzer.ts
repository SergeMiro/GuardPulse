import { detectInjection, detectSensitive, globMatch, highEntropyParts, hostOf, toText } from './detectors.js';
import { evaluate, RAW_ARGS, usesSequence } from './policy.js';
import type { BoundSecret, Budget, Finding, GuardEvent, Label, PolicyConfig } from './types.js';

interface TraceState {
  allowedTools?: string[];
  taintFrom?: string;
  sensitiveFrom: string[];
  lastId?: string;
  /** Earlier events of the trace, for sequence rules (bounded). */
  history: GuardEvent[];
  /** Extra allowed domains for this task only. */
  domains?: string[];
  budget?: Budget;
  startTs?: number;
  toolCalls: number;
  perTool: Map<string, number>;
}

export interface AnalyzerOptions {
  policy: PolicyConfig;
  /** Domains the app is expected to talk to; anything else is egress. Globs allowed. */
  allowedDomains: string[];
  /** Extra detectors run on every event, e.g. the Security Autopilot baseline. */
  observers?: Array<(event: GuardEvent) => Finding[]>;
  /** Planted honeytokens (see createCanary): seeing one in an outbound request or tool call is a leak. */
  canaries?: string[];
  /** Real secrets with the domains they belong to; sending one anywhere else is a leak. */
  secrets?: BoundSecret[];
  /**
   * Treat the big AI APIs (OpenAI, Anthropic, Gemini…) as expected destinations, default true: an
   * agent sends what it read to its model on every step, and that is not exfiltration.
   */
  aiProviders?: boolean;
  /** Per-trace state kept for at most this many traces (least recently used dropped), default 10 000. */
  maxTraces?: number;
}

/** Raw values used only for detection; the event itself stores redacted copies. */
export interface RawPayload {
  text?: unknown;
  body?: unknown;
  /** True when the request carries a body that cannot be inspected (Blob, stream…). */
  opaqueBody?: boolean;
  /** Request headers as text: only checked for canaries, never stored. */
  headers?: string;
  url?: string;
  /** Tool arguments as passed (matched by `args` rules, never stored). */
  args?: unknown;
  result?: unknown;
  /**
   * Replay: the recorded event. Content findings (injection, secrets, drift) are taken from it
   * instead of re-detected, because stored text is redacted and truncated.
   */
  prior?: GuardEvent;
}

/** Model APIs an agent talks to on every step. */
export const AI_PROVIDER_DOMAINS = [
  'api.openai.com', '*.openai.azure.com', 'api.anthropic.com', 'generativelanguage.googleapis.com', '*-aiplatform.googleapis.com',
  'api.mistral.ai', 'api.groq.com', 'openrouter.ai', 'api.cohere.com', 'api.deepseek.com', 'api.x.ai', 'api.together.xyz',
  'bedrock-runtime.*.amazonaws.com',
];

const REDACTED = /\[REDACTED:[a-z_]+\]/;
const SERIOUS_REDACTED = /\[REDACTED:(?!email)[a-z_]+\]/;
const priorFindings = (prior: GuardEvent, test: (type: string) => boolean) => prior.findings.filter((f) => test(f.type));

function queryOf(url: string): string {
  const i = url.indexOf('?');
  return i < 0 ? '' : url.slice(i + 1);
}

/**
 * Attack Chain Intelligence: keeps per-trace state (did an injection enter? did the agent touch
 * sensitive data?) and labels each new event with what it means in the light of what came before.
 */
export class Analyzer {
  private traces = new Map<string, TraceState>();
  /** Kill switch: when set, every tool call and outbound request is blocked, whatever the mode. */
  halted?: string;

  constructor(readonly options: AnalyzerOptions) {}

  /** History is only kept when some rule needs it (re-read each time: the policy can change live). */
  private get keepHistory(): boolean {
    return usesSequence(this.options.policy.rules);
  }

  private state(traceId: string): TraceState {
    let st = this.traces.get(traceId);
    if (st) this.traces.delete(traceId); // re-insert: Map order doubles as LRU order
    else st = { sensitiveFrom: [], history: [], toolCalls: 0, perTool: new Map() };
    this.traces.set(traceId, st);
    if (this.traces.size > (this.options.maxTraces ?? 10_000)) this.traces.delete(this.traces.keys().next().value!);
    return st;
  }

  private liveSecrets(): Array<BoundSecret & { value: string }> {
    return (this.options.secrets ?? []).filter((x): x is BoundSecret & { value: string } => typeof x.value === 'string' && x.value.length >= 8);
  }

  /** Replaces known secret values in text that is about to be stored. */
  scrub(text: string): string {
    let out = text;
    for (const x of this.liveSecrets()) out = out.split(x.value).join(`[REDACTED:${x.name ?? 'secret'}]`);
    return out;
  }

  /** Labels the event, attaches findings and the policy decision. Mutates and returns it. */
  process(event: GuardEvent, raw: RawPayload = event.data): GuardEvent {
    const st = this.state(event.traceId);
    const prior = raw.prior;
    event.parentId ??= st.lastId;
    st.lastId = event.id;
    const add = (label: Label) => event.labels.includes(label) || event.labels.push(label);

    switch (event.kind) {
      case 'task':
        st.allowedTools = Array.isArray(event.data.allowedTools) ? (event.data.allowedTools as string[]) : undefined;
        st.domains = Array.isArray(event.data.allowedDomains) ? (event.data.allowedDomains as string[]) : undefined;
        st.budget = event.data.budget && typeof event.data.budget === 'object' ? (event.data.budget as Budget) : undefined;
        st.startTs = event.ts;
        st.toolCalls = 0; // several tasks can share one trace id (one OTel trace)
        st.perTool.clear();
        break;
      case 'context': {
        if (event.data.untrusted !== false) add('untrusted');
        const injection =
          event.data.untrusted === false ? [] : prior ? priorFindings(prior, (t) => t === 'prompt_injection') : detectInjection(String(raw.text ?? ''));
        if (injection.length) {
          add('injection');
          event.findings.push(...injection);
          st.taintFrom ??= event.id;
        }
        break;
      }
      case 'tool_call':
        if (st.allowedTools && !st.allowedTools.some((g) => globMatch(g, event.target))) {
          add('unexpected_tool');
          event.findings.push({
            type: 'tool.unexpected',
            severity: st.taintFrom ? 'high' : 'medium',
            message: `Tool "${event.target}" is not in the task scope (${st.allowedTools.join(', ')})`,
          });
        }
        break;
      case 'http': {
        const url = raw.url ?? event.target;
        const host = hostOf(url);
        event.data.host = host;
        // a secret bound to a domain also declares that domain as a normal destination
        const allowed = [...this.options.allowedDomains, ...(st.domains ?? []), ...this.liveSecrets().flatMap((x) => x.domains), ...(this.options.aiProviders === false ? [] : AI_PROVIDER_DOMAINS)];
        if (!allowed.some((g) => globMatch(g, host))) {
          add('egress');
          event.findings.push({ type: 'egress.unknown_domain', severity: 'low', message: `First-party allow-list does not cover ${host}` });
        }
        const outgoing = `${url} ${raw.headers ?? ''} ${toText(raw.body)}`;
        const misplaced = prior
          ? priorFindings(prior, (t) => t === 'secret.wrong_domain')
          : this.liveSecrets()
              .filter((x) => outgoing.includes(x.value) && !x.domains.some((g) => globMatch(g, host)))
              .map((x): Finding => ({ type: 'secret.wrong_domain', severity: 'critical', message: `Secret ${x.name ?? '(unnamed)'} sent to ${host}; it belongs to ${x.domains.join(', ')}` }));
        if (misplaced.length) {
          add('secret_leak');
          event.findings.push(...misplaced);
        }
        // only where smuggling matters: after an injection or a read of sensitive data
        if (event.labels.includes('egress') && !prior && (st.taintFrom || st.sensitiveFrom.length)) {
          const encoded = highEntropyParts(url);
          if (encoded.length) {
            add('sensitive');
            event.findings.push({ type: 'sensitive.high_entropy', severity: 'medium', message: `Random-looking data in the URL (${encoded.length} part${encoded.length > 1 ? 's' : ''}), a common way to smuggle data out` });
          }
        }
        const query = queryOf(url);
        const hasPayload = (raw.body !== undefined && raw.body !== '') || raw.opaqueBody === true || query !== '';
        const leaked = prior
          ? priorFindings(prior, (t) => t.startsWith('sensitive.'))
          : [...detectSensitive(this.scrub(toText(raw.body))), ...detectSensitive(this.scrub(query))]; // bound secrets are judged by domain above
        const opaqueAfterSecrets = raw.opaqueBody === true && st.sensitiveFrom.length > 0;
        if (leaked.length || opaqueAfterSecrets || (prior ? prior.labels.includes('sensitive') : REDACTED.test(String(raw.body ?? '') + query))) {
          add('sensitive');
          event.findings.push(...leaked);
          if (opaqueAfterSecrets && !leaked.length) {
            event.findings.push({ type: 'sensitive.opaque_body', severity: 'high', message: 'Uninspectable body sent after the agent read sensitive data' });
          }
        }
        // only a request that carries data (body or query string) can move data out
        if (st.sensitiveFrom.length && event.labels.includes('egress') && hasPayload) {
          event.data.sensitiveFrom = [...st.sensitiveFrom];
          event.findings.push({ type: 'exfil.sensitive_trace', severity: 'high', message: 'Outbound request after the agent read sensitive data' });
        }
        break;
      }
    }

    if ((event.kind === 'tool_call' || event.kind === 'http') && st.budget) {
      const over: string[] = [];
      const { maxToolCalls, maxCallsPerTool, maxDurationMs } = st.budget;
      if (event.kind === 'tool_call') {
        st.toolCalls++;
        const n = (st.perTool.get(event.target) ?? 0) + 1;
        st.perTool.set(event.target, n);
        if (maxToolCalls !== undefined && st.toolCalls > maxToolCalls) over.push(`${st.toolCalls} tool calls (budget ${maxToolCalls})`);
        if (maxCallsPerTool !== undefined && n > maxCallsPerTool) over.push(`${n} calls of ${event.target} (budget ${maxCallsPerTool}), likely a loop`);
      }
      if (maxDurationMs !== undefined && st.startTs !== undefined && event.ts - st.startTs > maxDurationMs) {
        over.push(`running for ${Math.round((event.ts - st.startTs) / 1000)} s (budget ${Math.round(maxDurationMs / 1000)} s)`);
      }
      if (over.length) {
        add('over_budget');
        event.findings.push({ type: 'budget.exceeded', severity: 'medium', message: `Task over budget: ${over.join('; ')}` });
      }
    }

    // a planted canary must never leave: check everything going out, even to allowed domains
    if (event.kind === 'http' || event.kind === 'tool_call') {
      const canaries = this.options.canaries ?? [];
      const outgoing = event.kind === 'http' ? `${raw.url ?? event.target} ${raw.headers ?? ''} ${toText(raw.body)}` : toText(raw.args);
      const leaked = prior ? priorFindings(prior, (t) => t === 'canary.leaked') : canaries.some((c) => c && outgoing.includes(c)) ? [{ type: 'canary.leaked', severity: 'critical' as const, message: 'A planted canary token is leaving the app: something is exfiltrating data' }] : [];
      if (leaked.length) {
        add('canary');
        event.findings.push(...leaked);
      }
    }

    if (st.taintFrom && event.kind !== 'task' && event.kind !== 'context') {
      add('tainted');
      event.data.taintFrom = st.taintFrom;
      if (event.labels.includes('egress')) {
        event.findings.push({ type: 'chain.exfiltration', severity: 'critical', message: 'Prompt injection → outbound request to an unknown domain' });
      } else if (event.labels.includes('unexpected_tool')) {
        event.findings.push({ type: 'chain.tool_hijack', severity: 'high', message: 'Prompt injection → tool outside the task scope' });
      }
    }

    const drift = prior ? priorFindings(prior, (t) => t.startsWith('drift.')) : (this.options.observers ?? []).flatMap((observe) => observe(event));
    if (drift.length) {
      add('drift');
      event.findings.push(...drift);
    }

    const holder = event as unknown as Record<symbol, unknown>;
    if (raw.args !== undefined) holder[RAW_ARGS] = raw.args;
    event.decision = evaluate(event, this.options.policy, st.history);
    delete holder[RAW_ARGS];
    // a canary cannot be a false positive: it blocks in every mode, whatever the rules say
    if (event.labels.includes('canary') && event.decision.action !== 'block') {
      event.decision = {
        action: 'block',
        ruleId: 'canary-leak',
        reason: 'A planted canary token is leaving the app',
        recommendation: 'Find which step read the canary (it is in the chain), treat the data next to it as exposed, and rotate the real secrets stored with it.',
      };
    }
    const halted = prior ? (prior.data.halted as string | undefined) : this.halted;
    if (halted && (event.kind === 'tool_call' || event.kind === 'http')) {
      event.data.halted = halted;
      event.findings.push({ type: 'kill_switch', severity: 'high', message: `Kill switch is on: ${halted}` });
      event.decision = { action: 'block', ruleId: 'kill-switch', reason: `Kill switch: ${halted}`, recommendation: 'Call resume() once the incident is understood.' };
    }
    if (this.keepHistory) {
      // slim copy: labels/findings are shared (a tool's result can still label it), raw args kept in memory only
      const slim = { id: event.id, seq: event.seq, ts: event.ts, traceId: event.traceId, kind: event.kind, actor: event.actor, target: event.target, data: { args: event.data.args }, labels: event.labels, findings: event.findings } as GuardEvent;
      if (raw.args !== undefined) (slim as unknown as Record<symbol, unknown>)[RAW_ARGS] = raw.args;
      st.history.push(slim);
      if (st.history.length > 100) st.history.shift();
    }
    // a tool's result arrives after its decision; replay keeps that order so decisions match
    // replay with a recorded completion point: the replayer scans the result at that point instead
    const deferred = prior !== undefined && typeof prior.data.doneSeq === 'number';
    if (event.kind === 'tool_call' && !deferred && (raw.result !== undefined || prior?.labels.some((l) => l === 'sensitive' || l === 'injection'))) {
      this.scanResult(event, raw.result, prior);
    }
    return event;
  }

  /**
   * Called once a tool returned. A web page, an e-mail or a file read by a tool is untrusted
   * content: hidden instructions in it taint the rest of the task, exactly like a document.
   * Secrets or cards in it mark the task as having touched sensitive data.
   */
  scanResult(event: GuardEvent, result: unknown, prior?: GuardEvent): void {
    const injection = prior ? priorFindings(prior, (t) => t === 'prompt_injection') : detectInjection(toText(result));
    if (injection.length) {
      if (!event.labels.includes('injection')) event.labels.push('injection');
      event.findings.push(...injection.map((f) => ({ ...f, message: `Tool output: ${f.message}` })));
      this.state(event.traceId).taintFrom ??= event.id;
    }
    const found = prior ? priorFindings(prior, (t) => t.startsWith('sensitive.')) : detectSensitive(result);
    event.findings.push(...found);
    // a lone email in a ticket is routine; secrets, cards and tokens make the trace sensitive
    const serious = prior
      ? prior.labels.includes('sensitive')
      : found.some((f) => f.severity === 'high' || f.severity === 'critical') || SERIOUS_REDACTED.test(String(result));
    if (!serious) return;
    if (!event.labels.includes('sensitive')) event.labels.push('sensitive');
    this.state(event.traceId).sensitiveFrom.push(event.id);
  }
}
