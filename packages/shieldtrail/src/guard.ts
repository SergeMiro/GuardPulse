import { Analyzer, type RawPayload } from './analyzer.js';
import { buildChain, type Chain } from './chain.js';
import { redact } from './detectors.js';
import { defaultRules } from './policy.js';
import { type EventStore, MemoryStore } from './store/memory.js';
import type { Decision, EventKind, Finding, GuardEvent, Mode, Rule } from './types.js';

export interface Exporter {
  export(event: GuardEvent): void | Promise<void>;
}

/** The slice of `@opentelemetry/api` ShieldTrail reads, so the package does not depend on it. */
export interface OtelTraceApi {
  getActiveSpan(): { spanContext(): { traceId: string; spanId: string } } | undefined;
}

export interface GuardOptions {
  mode?: Mode;
  rules?: Rule[];
  allowedDomains?: string[];
  store?: EventStore;
  exporters?: Exporter[];
  /** Extra detectors, e.g. `baseline.observe` from the Security Autopilot. */
  observers?: Array<(event: GuardEvent) => Finding[]>;
  /** Pass `trace` from `@opentelemetry/api` to reuse the active trace id. */
  otel?: OtelTraceApi;
  /** fetch used by `trace.fetch`, defaults to globalThis.fetch. */
  fetch?: typeof fetch;
  /** Optional LLM (or anything) that writes an incident summary for a chain. */
  analyst?: (chain: Chain) => Promise<string>;
  onEvent?: (event: GuardEvent) => void;
  /** Store/exporter failures land here instead of breaking the app. */
  onError?: (error: unknown) => void;
}

export interface TraceOptions {
  agent: string;
  task?: string;
  /** Tools this task is expected to use. Globs allowed. Omit to skip the scope check. */
  allowedTools?: string[];
  traceId?: string;
}

export class GuardBlockedError extends Error {
  constructor(
    readonly decision: Decision,
    readonly event: GuardEvent,
  ) {
    super(`ShieldTrail blocked ${event.kind} ${event.target}: ${decision.reason}`);
    this.name = 'GuardBlockedError';
  }
}

const hex = (bytes: number) => Array.from(crypto.getRandomValues(new Uint8Array(bytes)), (b) => b.toString(16).padStart(2, '0')).join('');

export class ShieldTrail {
  readonly analyzer: Analyzer;
  readonly store: EventStore;
  private seq = 0;

  constructor(readonly options: GuardOptions = {}) {
    this.store = options.store ?? new MemoryStore();
    this.analyzer = new Analyzer({
      policy: { mode: options.mode ?? 'shadow', rules: options.rules ?? defaultRules },
      allowedDomains: options.allowedDomains ?? [],
      observers: options.observers,
    });
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
    const { task, allowedTools } = this.opts;
    await this.guard.ingest(this.guard.newEvent(this.traceId, 'task', this.opts.agent, task ?? 'task', { task, allowedTools }));
  }

  private async gate(event: GuardEvent, raw: RawPayload): Promise<void> {
    this.guard.analyzer.process(event, raw);
    if (event.decision?.action === 'block') {
      await this.guard.record(event);
      throw new GuardBlockedError(event.decision, event);
    }
  }

  /** Content the agent reads: documents, web pages, emails, tool output. Untrusted by default. */
  async context(input: { source: string; text: string; untrusted?: boolean }): Promise<GuardEvent> {
    await this.begin();
    const event = this.guard.newEvent(this.traceId, 'context', this.opts.agent, input.source, {
      text: redact(input.text, 500),
      untrusted: input.untrusted ?? true,
    });
    await this.gate(event, { text: input.text });
    await this.guard.record(event);
    return event;
  }

  /** Runs a tool call through the policy; `run` is never called when the call is blocked. */
  async tool<T>(name: string, args: unknown, run: () => T | Promise<T>): Promise<T> {
    await this.begin();
    const event = this.guard.newEvent(this.traceId, 'tool_call', this.opts.agent, name, { args: redact(args, 500) });
    await this.gate(event, {});
    try {
      const result = await run();
      event.data.result = redact(result, 500);
      this.guard.analyzer.scanResult(event, result);
      return result;
    } catch (err) {
      event.data.error = String((err as Error)?.message ?? err);
      throw err;
    } finally {
      await this.guard.record(event);
    }
  }

  /** fetch through ShieldTrail; the request never leaves when the policy blocks it. */
  async fetch(input: string | URL, init: RequestInit = {}): Promise<Response> {
    await this.begin();
    const url = String(input);
    const body = typeof init.body === 'string' ? init.body : init.body ? '[binary body]' : undefined;
    const event = this.guard.newEvent(this.traceId, 'http', this.opts.agent, url, {
      method: (init.method ?? 'GET').toUpperCase(),
      body: redact(body, 500),
    });
    await this.gate(event, { body });
    try {
      const res = await (this.guard.options.fetch ?? globalThis.fetch)(input, init);
      event.data.status = res.status;
      return res;
    } catch (err) {
      event.data.error = String((err as Error)?.message ?? err);
      throw err;
    } finally {
      await this.guard.record(event);
    }
  }

  async error(err: unknown): Promise<GuardEvent> {
    await this.begin();
    const e = err as Error;
    const event = this.guard.newEvent(this.traceId, 'error', this.opts.agent, e?.name ?? 'Error', { message: redact(e?.message ?? String(err), 500) });
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
