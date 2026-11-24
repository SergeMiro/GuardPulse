import { Analyzer, type RawPayload } from './analyzer.js';
import { buildChain, type Chain } from './chain.js';
import { redact, toText } from './detectors.js';
import { defaultRules } from './policy.js';
import { type EventStore, MemoryStore } from './store/memory.js';
import type { BoundSecret, Budget, Decision, EventKind, Finding, GuardEvent, Mode, Policy, Rule } from './types.js';

export interface Exporter {
  export(event: GuardEvent): void | Promise<void>;
}

/** The slice of `@opentelemetry/api` ShieldTrail reads, so the package does not depend on it. */
/** A step waiting for a human because a rule said 'ask'. */
export interface ApprovalRequest {
  id: string;
  event: GuardEvent;
  ruleId?: string;
  reason: string;
  since: number;
}

export interface OtelTraceApi {
  getActiveSpan(): { spanContext(): { traceId: string; spanId: string } } | undefined;
}

export interface GuardOptions {
  mode?: Mode;
  rules?: Rule[];
  allowedDomains?: string[];
  store?: EventStore;
  exporters?: Exporter[];
  /** Default limits for every task (a task can set its own). */
  budget?: Budget;
  /**
   * Real secrets and the domains they belong to, e.g. `{ name: 'STRIPE_KEY', value: process.env.STRIPE_KEY, domains: ['api.stripe.com'] }`.
   * Sending one anywhere else is blocked (rule secret-wrong-domain); the values are never stored.
   */
  secrets?: BoundSecret[];
  /** Planted fake secrets (createCanary()); any outbound request or tool call carrying one is blocked. */
  canaries?: string[];
  /** Extra detectors, e.g. `baseline.observe` from the Security Autopilot. */
  observers?: Array<(event: GuardEvent) => Finding[]>;
  /** Pass `trace` from `@opentelemetry/api` to reuse the active trace id. */
  otel?: OtelTraceApi;
  /** fetch used by `trace.fetch`, defaults to globalThis.fetch. */
  fetch?: typeof fetch;
  /** Optional LLM (or anything) that writes an incident summary for a chain. */
  analyst?: (chain: Chain) => Promise<string>;
  /**
   * Who answers rules with action 'ask' outside the dev panel, e.g. a Slack message with two buttons.
   * Return true to let the step run. No answer before `approvalTimeoutMs` (default 2 min) = blocked.
   */
  approve?: (request: ApprovalRequest) => boolean | { approved: boolean; by?: string } | Promise<boolean | { approved: boolean; by?: string }>;
  approvalTimeoutMs?: number;
  onEvent?: (event: GuardEvent) => void;
  /** Store/exporter failures land here instead of breaking the app. */
  onError?: (error: unknown) => void;
}

export interface TraceOptions {
  agent: string;
  task?: string;
  /** Tools this task is expected to use. Globs allowed. Omit to skip the scope check. */
  allowedTools?: string[];
  /** Domains allowed for this task on top of the global allow-list. */
  allowedDomains?: string[];
  /** Limits for this task; overrides the guard's default budget. */
  budget?: Budget;
  traceId?: string;
}

export class GuardBlockedError extends Error {
  constructor(
    readonly decision: Decision,
    readonly event: GuardEvent,
  ) {
    super(`ShieldTrail blocked ${event.kind} ${event.target} (rule ${decision.ruleId}): ${decision.reason}`);
    this.name = 'GuardBlockedError';
  }
}

/** fetch bodies as inspectable text when possible; Blob and streams cannot be read without consuming them. */
function bodyText(body: RequestInit['body']): { text?: string; opaque: boolean } {
  if (body === undefined || body === null) return { opaque: false };
  if (typeof body === 'string') return { text: body, opaque: false };
  if (body instanceof URLSearchParams) return { text: body.toString(), opaque: false };
  if (body instanceof ArrayBuffer || ArrayBuffer.isView(body)) return { text: new TextDecoder().decode(body as ArrayBuffer), opaque: false };
  if (typeof FormData !== 'undefined' && body instanceof FormData) {
    const parts: string[] = [];
    body.forEach((v, k) => parts.push(`${k}=${typeof v === 'string' ? v : '[file]'}`));
    return { text: parts.join('&'), opaque: false };
  }
  return { opaque: true };
}

function headerText(headers: RequestInit['headers']): string | undefined {
  if (!headers) return undefined;
  const parts: string[] = [];
  new Headers(headers).forEach((value, key) => parts.push(`${key}: ${value}`));
  return parts.join('\n');
}

/** Set by `shieldtrail/node` (AsyncLocalStorage): which trace the running code belongs to. */
export interface TraceContext {
  run<T>(trace: Trace, fn: () => T): T;
  /** Runs fn outside any trace (so the fetch wrapper lets the call through). */
  exit<T>(fn: () => T): T;
  get(): Trace | undefined;
}
let context: TraceContext | undefined;
export const setTraceContext = (c: TraceContext) => void (context = c);
/** The trace the running code belongs to (inside trace.run / trace.tool), when shieldtrail/node is loaded. */
export const currentTrace = (): Trace | undefined => context?.get();

const hex = (bytes: number) => Array.from(crypto.getRandomValues(new Uint8Array(bytes)), (b) => b.toString(16).padStart(2, '0')).join('');

export class ShieldTrail {
  readonly analyzer: Analyzer;
  readonly store: EventStore;
  private seq = 0;
  /** Steps waiting for a human, by event id. */
  readonly pending = new Map<string, ApprovalRequest & { settle: (approved: boolean, by: string) => void }>();
  /** True while someone can answer in the dev panel; set by shieldtrail/node. */
  interactive = false;

  /** Sequence number of the most recent event. */
  get lastSeq(): number {
    return this.seq;
  }

  constructor(readonly options: GuardOptions = {}) {
    this.store = options.store ?? new MemoryStore();
    this.analyzer = new Analyzer({
      policy: { mode: options.mode ?? 'shadow', rules: options.rules ?? defaultRules },
      allowedDomains: options.allowedDomains ?? [],
      observers: options.observers,
      canaries: options.canaries,
      secrets: options.secrets,
    });
  }

  /** redact() that also removes the bound secrets' exact values: use it for anything stored. */
  redact(value: unknown, max?: number, opts?: { keep?: string[] }): string {
    return redact(this.analyzer.scrub(toText(value)), max, opts);
  }

  /** Answers a pending 'ask' step (dev panel, admin endpoint). False when it is no longer pending. */
  answer(id: string, approved: boolean, by = 'operator'): boolean {
    const p = this.pending.get(id);
    if (!p) return false;
    p.settle(approved, by);
    return true;
  }

  /** Puts an 'ask' step in front of a human and turns the answer into the final decision. */
  async requestApproval(event: GuardEvent): Promise<Decision> {
    const asked = event.decision!;
    const hook = this.options.approve;
    const final = (approved: boolean, by: string, why: string): Decision => ({
      ...asked,
      action: approved ? 'allow' : 'block',
      reason: `${asked.reason} — ${why}`,
      approval: { approved, by, at: Date.now() },
    });
    if (!hook && !this.interactive) return final(false, 'nobody', 'needs approval and no approver is set up (pass `approve`, or run the dev panel)');
    const { approved, by } = await new Promise<{ approved: boolean; by: string }>((resolve) => {
      let done = false;
      const settle = (ok: boolean, who: string) => {
        if (done) return;
        done = true;
        clearTimeout(timer);
        this.pending.delete(event.id);
        resolve({ approved: ok, by: who });
      };
      const timer = setTimeout(() => settle(false, 'timeout'), this.options.approvalTimeoutMs ?? 120_000);
      (timer as { unref?: () => void }).unref?.();
      const request: ApprovalRequest = { id: event.id, event, ruleId: asked.ruleId, reason: asked.reason, since: Date.now() };
      this.pending.set(event.id, { ...request, settle });
      if (hook) {
        Promise.resolve()
          .then(() => hook(request))
          .then(
            (r) => (typeof r === 'boolean' ? settle(r, 'approve hook') : settle(r.approved, r.by ?? 'approve hook')),
            (err) => {
              this.options.onError?.(err);
              settle(false, 'approve hook failed');
            },
          );
      }
    });
    return final(approved, by, approved ? `approved by ${by}` : by === 'timeout' ? 'no answer in time' : `denied by ${by}`);
  }

  /** The policy in force (mode, rules, allowed domains, default budget). */
  get policy(): Required<Omit<Policy, 'ruleModes'>> {
    const { policy, allowedDomains } = this.analyzer.options;
    return { mode: policy.mode, rules: policy.rules, allowedDomains, budget: this.options.budget ?? {} };
  }

  /** Changes the policy of a running guard, e.g. after the dashboard switched a rule to enforce. */
  setPolicy(next: Policy): void {
    const o = this.analyzer.options;
    o.policy = { mode: next.mode ?? o.policy.mode, rules: next.rules ?? o.policy.rules };
    if (next.allowedDomains) o.allowedDomains = next.allowedDomains;
    if (next.budget) this.options.budget = next.budget;
  }

  /** Kill switch: from now on every tool call and outbound request of every agent is blocked. */
  halt(reason = 'stopped by operator'): void {
    this.analyzer.halted = reason;
  }

  resume(): void {
    this.analyzer.halted = undefined;
  }

  get halted(): string | undefined {
    return this.analyzer.halted;
  }

  startTrace(opts: TraceOptions): Trace {
    const traceId = opts.traceId ?? this.options.otel?.getActiveSpan()?.spanContext().traceId ?? hex(16);
    return new Trace(this, traceId, opts);
  }

  /** Builds an event with an id and sequence number; not yet analysed or recorded. */
  newEvent(traceId: string, kind: EventKind, actor: string, target: string, data: Record<string, unknown>): GuardEvent {
    return { id: hex(8), seq: ++this.seq, ts: Date.now(), traceId, kind, actor, target, data, labels: [], findings: [] };
  }

  /** Analyse + record an event coming from elsewhere (OTel bridge, webhook, another process). */
  async ingest(event: GuardEvent, raw?: RawPayload): Promise<GuardEvent> {
    this.analyzer.process(event, raw);
    await this.record(event);
    return event;
  }

  async record(event: GuardEvent): Promise<void> {
    try {
      await this.store.add(event);
    } catch (err) {
      this.options.onError?.(err);
    }
    this.options.onEvent?.(event);
    await Promise.all(
      (this.options.exporters ?? []).map(async (x) => {
        try {
          await x.export(event);
        } catch (err) {
          this.options.onError?.(err);
        }
      }),
    );
  }

  async chain(traceId: string): Promise<Chain> {
    return buildChain(await this.store.list(traceId));
  }

  async chains(limit = 50): Promise<Chain[]> {
    const ids = await this.store.traces(limit);
    return Promise.all(ids.map((id) => this.chain(id)));
  }

  /** Incident summary: the analyst hook when configured, the deterministic narrative otherwise. */
  async explain(traceId: string): Promise<string> {
    const chain = await this.chain(traceId);
    return this.options.analyst ? this.options.analyst(chain) : chain.narrative.join('\n');
  }
}

export class Trace {
  private started = false;

  constructor(
    readonly guard: ShieldTrail,
    readonly traceId: string,
    readonly opts: TraceOptions,
  ) {}

  private async begin(): Promise<void> {
    if (this.started) return;
    this.started = true;
    const { task, allowedTools, allowedDomains } = this.opts;
    const budget = this.opts.budget ?? this.guard.options.budget;
    await this.guard.ingest(this.guard.newEvent(this.traceId, 'task', this.opts.agent, task ?? 'task', { task, allowedTools, allowedDomains, budget }));
  }

  private async gate(event: GuardEvent, raw: RawPayload): Promise<void> {
    this.guard.analyzer.process(event, raw);
    if (event.decision?.action === 'ask') event.decision = await this.guard.requestApproval(event);
    if (event.decision?.action === 'block') {
      await this.guard.record(event);
      throw new GuardBlockedError(event.decision, event);
    }
  }

  /** Content the agent reads: documents, web pages, emails, tool output. Untrusted by default. */
  async context(input: { source: string; text: string; untrusted?: boolean }): Promise<GuardEvent> {
    await this.begin();
    const event = this.guard.newEvent(this.traceId, 'context', this.opts.agent, input.source, {
      text: this.guard.redact(input.text, 500),
      untrusted: input.untrusted ?? true,
    });
    await this.gate(event, { text: input.text });
    await this.guard.record(event);
    return event;
  }

  /**
   * Runs `fn` as part of this task: with `shieldtrail/node`, every fetch inside it (OpenAI, Stripe,
   * your own APIs) goes through the policy without wrapping each call.
   */
  run<T>(fn: () => T): T {
    if (!context) throw new Error("trace.run() needs createGuard from 'shieldtrail/node' (it uses AsyncLocalStorage)");
    return context.run(this, fn);
  }

  /** Runs a tool call through the policy; `run` is never called when the call is blocked. */
  async tool<T>(name: string, args: unknown, run: () => T | Promise<T>): Promise<T> {
    await this.begin();
    // e-mail addresses stay readable in arguments so 'args' rules (to: '*@acme.com') replay exactly
    const event = this.guard.newEvent(this.traceId, 'tool_call', this.opts.agent, name, { args: this.guard.redact(args, 4000, { keep: ['email'] }) });
    await this.gate(event, { args });
    let result: T;
    try {
      result = await (context ? context.run(this, run) : run()); // fetches made by the tool belong to the task
    } catch (err) {
      event.data.error = this.guard.redact((err as Error)?.message ?? err, 500);
      await this.guard.record(event);
      throw err;
    }
    // events created while the tool ran come before its result: replay scans it at the same point
    event.data.doneSeq = this.guard.lastSeq;
    // the tool already ran: analysis problems must never turn its success into a failure
    try {
      event.data.result = this.guard.redact(result, 500);
      this.guard.analyzer.scanResult(event, result);
    } catch (err) {
      this.guard.options.onError?.(err);
    }
    await this.guard.record(event);
    return result;
  }

  /** fetch through ShieldTrail; the request never leaves when the policy blocks it. */
  async fetch(input: string | URL | Request, init: RequestInit = {}): Promise<Response> {
    await this.begin();
    const req = typeof Request !== 'undefined' && input instanceof Request ? input : undefined;
    const url = req ? req.url : String(input);
    // a Request's own body is a stream: it cannot be read without consuming it
    const { text: body, opaque } = init.body === undefined && req?.body ? { text: undefined, opaque: true } : bodyText(init.body);
    const headers = init.headers ?? req?.headers;
    const event = this.guard.newEvent(this.traceId, 'http', this.opts.agent, this.guard.redact(url), {
      method: (init.method ?? req?.method ?? 'GET').toUpperCase(),
      body: opaque ? '[uninspectable body]' : this.guard.redact(body, 500),
    });
    await this.gate(event, { body, opaqueBody: opaque, url, headers: headerText(headers) });
    try {
      const send = () => (this.guard.options.fetch ?? globalThis.fetch)(input, init);
      // outside the trace context: the global fetch wrapper must not check this call a second time
      const res = await (context ? context.exit(send) : send());
      event.data.status = res.status;
      return res;
    } catch (err) {
      event.data.error = this.guard.redact((err as Error)?.message ?? err, 500);
      throw err;
    } finally {
      await this.guard.record(event);
    }
  }

  /**
   * Model usage after an LLM call, for token and spend budgets. Takes the provider's usage object as
   * it is: OpenAI (prompt_tokens / completion_tokens), Anthropic (input_tokens / output_tokens) and the
   * Vercel AI SDK (inputTokens / outputTokens). Cost is yours to pass: prices change too often to ship.
   */
  async usage(usage: Record<string, unknown> | undefined, extra: { model?: string; costUsd?: number } = {}): Promise<GuardEvent> {
    await this.begin();
    const u = usage ?? {};
    const num = (...keys: string[]) => {
      for (const k of keys) if (typeof u[k] === 'number' && Number.isFinite(u[k])) return u[k] as number;
      return 0;
    };
    const data = {
      model: extra.model ?? (typeof u.model === 'string' ? u.model : undefined),
      inputTokens: num('input_tokens', 'prompt_tokens', 'inputTokens', 'promptTokens'),
      outputTokens: num('output_tokens', 'completion_tokens', 'outputTokens', 'completionTokens'),
      costUsd: extra.costUsd ?? num('costUsd'),
    };
    return this.guard.ingest(this.guard.newEvent(this.traceId, 'app', this.opts.agent, 'llm.usage', data));
  }

  async error(err: unknown): Promise<GuardEvent> {
    await this.begin();
    const e = err as Error;
    const event = this.guard.newEvent(this.traceId, 'error', this.opts.agent, e?.name ?? 'Error', { message: this.guard.redact(e?.message ?? String(err), 500) });
    return this.guard.ingest(event);
  }

  /** Any other app event worth correlating (auth, payment, deploy…). */
  async event(target: string, data: Record<string, unknown> = {}): Promise<GuardEvent> {
    await this.begin();
    return this.guard.ingest(this.guard.newEvent(this.traceId, 'app', this.opts.agent, target, data));
  }

  chain(): Promise<Chain> {
    return this.guard.chain(this.traceId);
  }
}

export const createGuard = (options?: GuardOptions) => new ShieldTrail(options);
