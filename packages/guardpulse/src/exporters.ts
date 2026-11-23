import { maxSeverity, severityRank } from './detectors.js';
import type { Exporter } from './guard.js';
import type { GuardEvent } from './types.js';

/** Default filter: only what a human should look at (a finding or a non-allow decision). */
export const notable = (e: GuardEvent) => e.findings.length > 0 || (e.decision !== undefined && e.decision.action !== 'allow');

export interface WebhookOptions {
  url: string;
  headers?: Record<string, string>;
  filter?: (e: GuardEvent) => boolean;
  fetch?: typeof fetch;
}

export function webhookExporter(opts: WebhookOptions): Exporter {
  const filter = opts.filter ?? notable;
  return {
    async export(event) {
      if (!filter(event)) return;
      const res = await (opts.fetch ?? globalThis.fetch)(opts.url, {
        method: 'POST',
        headers: { 'content-type': 'application/json', ...opts.headers },
        body: JSON.stringify({ source: 'guardpulse', event }),
      });
      if (!res.ok) throw new Error(`webhook ${opts.url} answered ${res.status}`);
    },
  };
}

/** Sends every event to a GuardPulse collector so the dashboard can show it. */
export function collectorExporter(baseUrl: string, opts: { token?: string; fetch?: typeof fetch } = {}): Exporter {
  // shortcut: one request per event; batch when event volume makes it matter
  return webhookExporter({
    url: `${baseUrl.replace(/\/$/, '')}/v1/events`,
    headers: opts.token ? { authorization: `Bearer ${opts.token}` } : undefined,
    filter: () => true,
    fetch: opts.fetch,
  });
}

const SEVERITY_SCORE = { low: 3, medium: 5, high: 8, critical: 10 } as const;
const cefHeader = (v: string) => v.replace(/\\/g, '\\\\').replace(/\|/g, '\\|');
const cefValue = (v: string) => v.replace(/\\/g, '\\\\').replace(/=/g, '\\=').replace(/\r?\n/g, '\\n');

/** ArcSight CEF line, readable by most SIEMs (Sentinel, QRadar, Splunk, Gatewatcher…). */
export function toCEF(e: GuardEvent): string {
  const sev = maxSeverity(e.findings.map((f) => f.severity));
  const signature = e.decision?.ruleId ?? e.findings[0]?.type ?? e.kind;
  const name = e.decision?.reason ?? e.findings[0]?.message ?? `${e.kind} ${e.target}`;
  const ext: Record<string, string | number | undefined> = {
    rt: e.ts,
    act: e.decision?.action,
    suser: e.actor,
    request: e.kind === 'http' ? e.target : undefined,
    cs1Label: 'traceId',
    cs1: e.traceId,
    cs2Label: 'target',
    cs2: e.target,
    cs3Label: 'labels',
    cs3: e.labels.join(','),
    msg: e.findings.map((f) => f.message).join('; ') || undefined,
  };
  const extension = Object.entries(ext)
    .filter(([, v]) => v !== undefined && v !== '')
    .map(([k, v]) => `${k}=${cefValue(String(v))}`)
    .join(' ');
  return `CEF:0|GuardPulse|guardpulse|0.1.0|${cefHeader(signature)}|${cefHeader(name)}|${sev ? SEVERITY_SCORE[sev] : 1}|${extension}`;
}

/** Elastic Common Schema document. */
export function toECS(e: GuardEvent): Record<string, unknown> {
  const sev = maxSeverity(e.findings.map((f) => f.severity));
  return {
    '@timestamp': new Date(e.ts).toISOString(),
    message: e.decision?.reason ?? `${e.kind} ${e.target}`,
    event: {
      kind: notable(e) ? 'alert' : 'event',
      category: ['intrusion_detection'],
      action: e.decision?.action,
      outcome: e.decision?.action === 'block' ? 'failure' : 'success',
      severity: sev ? severityRank(sev) + 1 : 0,
    },
    trace: { id: e.traceId },
    rule: e.decision?.ruleId ? { id: e.decision.ruleId, description: e.decision.reason } : undefined,
    url: e.kind === 'http' ? { full: e.target } : undefined,
    user: { name: e.actor },
    labels: Object.fromEntries(e.labels.map((l) => [l, true])),
    guardpulse: { kind: e.kind, target: e.target, findings: e.findings },
  };
}

export function siemExporter(opts: { format: 'cef' | 'ecs'; send: (line: string) => void | Promise<void>; filter?: (e: GuardEvent) => boolean }): Exporter {
  const filter = opts.filter ?? notable;
  return {
    export: (e) => (filter(e) ? opts.send(opts.format === 'cef' ? toCEF(e) : JSON.stringify(toECS(e))) : undefined),
  };
}

/** The slice of an OpenTelemetry Tracer this exporter uses, so `@opentelemetry/api` stays optional. */
export interface OtelTracerLike {
  startSpan(name: string, options?: { attributes?: Record<string, string | number | boolean | string[]>; startTime?: number }): { end(): void };
}

/** One span per event, `guardpulse.*` attributes, so traces show up next to the app's own. */
export function otelExporter(tracer: OtelTracerLike): Exporter {
  return {
    export(e) {
      const attributes: Record<string, string | number | boolean | string[]> = {
        'guardpulse.trace_id': e.traceId,
        'guardpulse.kind': e.kind,
        'guardpulse.actor': e.actor,
        'guardpulse.target': e.target,
        'guardpulse.labels': e.labels,
        'guardpulse.action': e.decision?.action ?? 'allow',
      };
      if (e.decision?.ruleId) attributes['guardpulse.rule'] = e.decision.ruleId;
      const sev = maxSeverity(e.findings.map((f) => f.severity));
      if (sev) attributes['guardpulse.severity'] = sev;
      tracer.startSpan(`guardpulse.${e.kind}`, { attributes, startTime: e.ts }).end();
    },
  };
}
