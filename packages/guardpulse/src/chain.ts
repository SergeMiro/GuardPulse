import { maxSeverity } from './detectors.js';
import type { EventKind, GuardEvent, Label, Severity } from './types.js';

export interface ChainNode {
  id: string;
  kind: EventKind;
  title: string;
  actor: string;
  target: string;
  labels: Label[];
  severity?: Severity;
  action?: string;
}

export interface ChainEdge {
  id: string;
  source: string;
  target: string;
  /** sequence = what happened next; taint = injected instructions flowing on; data = sensitive data flowing out */
  type: 'sequence' | 'taint' | 'data';
}

export interface Chain {
  traceId: string;
  actor: string;
  task?: string;
  startedAt: number;
  events: GuardEvent[];
  nodes: ChainNode[];
  edges: ChainEdge[];
  severity: Severity;
  blocked: boolean;
  wouldBlock: boolean;
  narrative: string[];
}

function title(e: GuardEvent): string {
  switch (e.kind) {
    case 'task':
      return `Task: ${String(e.data.task ?? e.target)}`;
    case 'context':
      return e.labels.includes('injection') ? `Prompt injection in ${e.target}` : `Context from ${e.target}`;
    case 'tool_call':
      return `${e.labels.includes('unexpected_tool') ? 'Unexpected tool' : 'Tool'} ${e.target}`;
    case 'http':
      return `${String(e.data.method ?? 'GET')} ${String(e.data.host ?? e.target)}`;
    case 'error':
      return `Error: ${e.target}`;
    default:
      return e.target;
  }
}

/** Turns the events of one trace into a graph + verdict + human-readable story. */
export function buildChain(events: GuardEvent[]): Chain {
  const sorted = [...events].sort((a, b) => a.seq - b.seq);
  const ids = new Set(sorted.map((e) => e.id));
  const nodes: ChainNode[] = sorted.map((e) => ({
    id: e.id,
    kind: e.kind,
    title: title(e),
    actor: e.actor,
    target: e.target,
    labels: e.labels,
    severity: maxSeverity(e.findings.map((f) => f.severity)),
    action: e.decision?.action,
  }));
  const edges: ChainEdge[] = [];
  for (const e of sorted) {
    if (e.parentId && ids.has(e.parentId)) edges.push({ id: `s:${e.parentId}>${e.id}`, source: e.parentId, target: e.id, type: 'sequence' });
    const taint = e.data.taintFrom as string | undefined;
    if (taint && ids.has(taint) && taint !== e.parentId) edges.push({ id: `t:${taint}>${e.id}`, source: taint, target: e.id, type: 'taint' });
    for (const src of (e.data.sensitiveFrom as string[] | undefined) ?? []) {
      if (ids.has(src)) edges.push({ id: `d:${src}>${e.id}`, source: src, target: e.id, type: 'data' });
    }
  }

  const narrative: string[] = [];
  for (const e of sorted) {
    const notable = e.labels.some((l) => l !== 'untrusted' && l !== 'tainted') || (e.decision && e.decision.action !== 'allow');
    if (!notable) continue;
    let line = title(e);
    const top = e.findings.find((f) => f.severity === maxSeverity(e.findings.map((x) => x.severity)));
    if (top) line += ` — ${top.message}`;
    if (e.decision && e.decision.action !== 'allow') line += ` → GuardPulse: ${e.decision.action.toUpperCase()} (${e.decision.ruleId})`;
    narrative.push(line);
  }

  const task = sorted.find((e) => e.kind === 'task');
  return {
    traceId: sorted[0]?.traceId ?? '',
    actor: sorted[0]?.actor ?? '',
    task: task ? String(task.data.task ?? task.target) : undefined,
    startedAt: sorted[0]?.ts ?? 0,
    events: sorted,
    nodes,
    edges,
    severity: maxSeverity(sorted.flatMap((e) => e.findings.map((f) => f.severity))) ?? 'low',
    blocked: sorted.some((e) => e.decision?.action === 'block'),
    wouldBlock: sorted.some((e) => e.decision?.action === 'would_block'),
    narrative,
  };
}
