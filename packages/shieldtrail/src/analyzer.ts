import { detectInjection, detectSensitive, globMatch, hostOf } from './detectors.js';
import { evaluate } from './policy.js';
import type { Finding, GuardEvent, Label, PolicyConfig } from './types.js';

interface TraceState {
  allowedTools?: string[];
  taintFrom?: string;
  sensitiveFrom: string[];
  lastId?: string;
}

export interface AnalyzerOptions {
  policy: PolicyConfig;
  /** Domains the app is expected to talk to; anything else is egress. Globs allowed. */
  allowedDomains: string[];
  /** Extra detectors run on every event, e.g. the Security Autopilot baseline. */
  observers?: Array<(event: GuardEvent) => Finding[]>;
}

/** Raw values used only for detection; the event itself stores redacted copies. */
export interface RawPayload {
  text?: unknown;
  body?: unknown;
  result?: unknown;
}

const REDACTED = /\[REDACTED:[a-z_]+\]/;

/**
 * Attack Chain Intelligence: keeps per-trace state (did an injection enter? did the agent touch
 * sensitive data?) and labels each new event with what it means in the light of what came before.
 */
export class Analyzer {
  private traces = new Map<string, TraceState>();

  constructor(readonly options: AnalyzerOptions) {}

  private state(traceId: string): TraceState {
    let st = this.traces.get(traceId);
    if (!st) this.traces.set(traceId, (st = { sensitiveFrom: [] }));
    return st;
  }

  /** Labels the event, attaches findings and the policy decision. Mutates and returns it. */
  process(event: GuardEvent, raw: RawPayload = event.data): GuardEvent {
    const st = this.state(event.traceId);
    event.parentId ??= st.lastId;
    st.lastId = event.id;
    const add = (label: Label) => event.labels.includes(label) || event.labels.push(label);

    switch (event.kind) {
      case 'task':
        st.allowedTools = event.data.allowedTools as string[] | undefined;
        break;
      case 'context': {
        if (event.data.untrusted !== false) add('untrusted');
        const injection = event.data.untrusted === false ? [] : detectInjection(String(raw.text ?? ''));
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
        if (raw.result !== undefined) this.scanResult(event, raw.result);
        break;
      case 'http': {
        const host = hostOf(event.target);
        event.data.host = host;
        if (!this.options.allowedDomains.some((g) => globMatch(g, host))) {
          add('egress');
          event.findings.push({ type: 'egress.unknown_domain', severity: 'low', message: `First-party allow-list does not cover ${host}` });
        }
        const leaked = detectSensitive(raw.body);
        if (leaked.length || REDACTED.test(String(raw.body ?? ''))) {
          add('sensitive');
          event.findings.push(...leaked);
        }
        // only a request that carries a body can move data out
        if (st.sensitiveFrom.length && event.labels.includes('egress') && raw.body !== undefined && raw.body !== '') {
          event.data.sensitiveFrom = [...st.sensitiveFrom];
          event.findings.push({
            type: 'exfil.sensitive_trace',
            severity: 'high',
            message: `Outbound request after the agent read sensitive data`,
          });
        }
        break;
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

    for (const observe of this.options.observers ?? []) {
      const drift = observe(event);
      if (drift.length) {
        add('drift');
        event.findings.push(...drift);
      }
    }

    event.decision = evaluate(event, this.options.policy);
    return event;
  }

  /** Called once a tool returned: marks the trace as having touched sensitive data. */
  scanResult(event: GuardEvent, result: unknown): void {
    const found = detectSensitive(result);
    event.findings.push(...found);
    // a lone email in a ticket is routine; secrets, cards and tokens make the trace sensitive
    const serious = found.some((f) => f.severity === 'high' || f.severity === 'critical') || /\[REDACTED:(?!email)[a-z_]+\]/.test(String(result));
    if (!serious) return;
    if (!event.labels.includes('sensitive')) event.labels.push('sensitive');
    this.state(event.traceId).sensitiveFrom.push(event.id);
  }
}
