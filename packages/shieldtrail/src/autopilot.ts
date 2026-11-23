import { hostOf } from './detectors.js';
import type { Finding, GuardEvent, Rule } from './types.js';

export interface BaselineOptions {
  /** Rate window, default 60 s. */
  windowMs?: number;
  /** Alert when a window exceeds learned peak × factor, default 3. */
  rateFactor?: number;
  /** Never alert below this many calls per window, default 20. */
  minRate?: number;
}

export interface BaselineSnapshot {
  tools: string[];
  domains: string[];
  errors: string[];
  toolDefs: Record<string, string>;
  peaks: Record<string, number>;
}

/** FNV-1a, enough to notice that a tool definition changed. */
function fingerprint(value: unknown): string {
  let h = 0x811c9dc5;
  for (const ch of JSON.stringify(value) ?? '') h = Math.imul(h ^ ch.charCodeAt(0), 0x01000193) >>> 0;
  return h.toString(16);
}

const shadowBlock = (id: string, description: string, match: Rule['match']): Rule => ({ id, description, match, action: 'block', mode: 'shadow' });

/**
 * Security Autopilot: learns what normal looks like (tools per agent, domains, MCP tool
 * definitions, error types, call rates), then reports drift with evidence and a suggested rule.
 */
export class Baseline {
  learning = true;
  private tools = new Set<string>();
  private domains = new Set<string>();
  private errors = new Set<string>();
  private toolDefs = new Map<string, string>();
  private peaks = new Map<string, number>();
  private windows = new Map<string, { window: number; count: number; reported: boolean }>();

  constructor(private readonly opts: BaselineOptions = {}) {}

  /** Stop learning; from now on anything new is drift. */
  freeze(): this {
    this.learning = false;
    return this;
  }

  snapshot(): BaselineSnapshot {
    return {
      tools: [...this.tools],
      domains: [...this.domains],
      errors: [...this.errors],
      toolDefs: Object.fromEntries(this.toolDefs),
      peaks: Object.fromEntries(this.peaks),
    };
  }

  static from(s: BaselineSnapshot, opts?: BaselineOptions): Baseline {
    const b = new Baseline(opts);
    s.tools.forEach((t) => b.tools.add(t));
    s.domains.forEach((d) => b.domains.add(d));
    s.errors.forEach((e) => b.errors.add(e));
    Object.entries(s.toolDefs).forEach(([k, v]) => b.toolDefs.set(k, v));
    Object.entries(s.peaks).forEach(([k, v]) => b.peaks.set(k, v));
    return b.freeze();
  }

  /** Pass as `observers: [baseline.observe]`. */
  observe = (event: GuardEvent): Finding[] => {
    const findings: Finding[] = [];
    const learn = (set: Set<string>, key: string, finding: () => Finding) => {
      if (set.has(key)) return;
      if (this.learning) set.add(key);
      else findings.push(finding());
    };

    if (event.kind === 'tool_call') {
      const key = `${event.actor} → ${event.target}`;
      learn(this.tools, key, () => ({
        type: 'drift.new_tool',
        severity: 'medium',
        message: `${event.actor} used tool ${event.target} for the first time`,
        evidence: { agent: event.actor, tool: event.target, eventId: event.id },
        suggestedRule: shadowBlock(`review-tool-${event.target}`, `Hold ${event.target} until reviewed`, { kind: 'tool_call', target: event.target }),
      }));
    }

    if (event.kind === 'http') {
      const host = hostOf(event.target);
      learn(this.domains, host, () => ({
        type: 'drift.new_domain',
        severity: 'medium',
        message: `First request to ${host}`,
        evidence: { host, url: event.target, eventId: event.id },
        suggestedRule: shadowBlock(`deny-${host}`, `Deny ${host} until reviewed`, { kind: 'http', target: [`*://${host}`, `*://${host}/*`, `*://${host}:*`] }),
      }));
    }

    if (event.kind === 'error') {
      learn(this.errors, event.target, () => ({
        type: 'drift.new_error',
        severity: 'low',
        message: `New error type ${event.target}`,
        evidence: { error: event.target, message: event.data.message },
      }));
    }

    // MCP tools/list snapshot: a changed description or schema is how a rug-pull looks
    if (event.kind === 'app' && event.target === 'mcp.tools/list') {
      const server = String(event.data.server ?? 'mcp');
      for (const tool of (event.data.tools as Array<{ name: string }> | undefined) ?? []) {
        const key = `${server}.${tool.name}`;
        const fp = fingerprint(tool);
        const known = this.toolDefs.get(key);
        if (known === fp) continue;
        if (this.learning) {
          this.toolDefs.set(key, fp);
          continue;
        }
        findings.push({
          type: known ? 'drift.tool_definition_changed' : 'drift.tool_added',
          severity: known ? 'high' : 'medium',
          message: known ? `MCP tool ${key} changed its description or schema` : `MCP server ${server} now exposes ${tool.name}`,
          evidence: { server, tool: tool.name, before: known, after: fp },
          suggestedRule: shadowBlock(`review-tool-${tool.name}`, `Hold ${tool.name} until its new definition is reviewed`, { kind: 'tool_call', target: [tool.name, key] }),
        });
      }
    }

    if (event.kind !== 'task' && event.kind !== 'context') findings.push(...this.rate(event));
    return findings;
  };

  private rate(event: GuardEvent): Finding[] {
    const key = `${event.kind}:${event.kind === 'http' ? hostOf(event.target) : event.target}`;
    const windowMs = this.opts.windowMs ?? 60_000;
    const window = Math.floor(event.ts / windowMs);
    let w = this.windows.get(key);
    if (!w || w.window !== window) this.windows.set(key, (w = { window, count: 0, reported: false }));
    w.count++;
    if (this.learning) {
      this.peaks.set(key, Math.max(this.peaks.get(key) ?? 0, w.count));
      return [];
    }
    const limit = Math.max(this.opts.minRate ?? 20, (this.peaks.get(key) ?? 0) * (this.opts.rateFactor ?? 3));
    if (w.count <= limit || w.reported) return [];
    w.reported = true;
    return [{ type: 'drift.rate_spike', severity: 'medium', message: `${key} reached ${w.count} calls in ${windowMs / 1000}s (limit ${limit})`, evidence: { key, count: w.count, limit } }];
  }
}
