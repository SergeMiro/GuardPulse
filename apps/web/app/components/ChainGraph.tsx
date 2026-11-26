'use client';
import { Background, Controls, type Edge, Handle, MarkerType, type Node, type NodeProps, Position, ReactFlow } from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import type { Chain, ChainNode } from 'shieldtrail';
import { useEffect, useMemo, useState } from 'react';

const LANES = ['task', 'context', 'tool_call', 'http', 'other'] as const;
const LANE_TITLE = { task: 'agent', context: 'input', tool_call: 'tools / MCP', http: 'network', other: 'app' };
const laneOf = (kind: string) => (LANES.includes(kind as never) ? kind : 'other') as (typeof LANES)[number];
const EDGE = { taint: '#ff5c7a', data: '#f59e0b', rule: '#a78bfa', sequence: 'var(--edge-seq)' };

const ACTION_STYLE: Record<string, { bg: string; fg: string }> = {
  block: { bg: '#ff5a5f', fg: '#fff' },
  would_block: { bg: '#ffb547', fg: '#1a1206' },
  alert: { bg: 'var(--amber-soft)', fg: 'var(--amber)' },
};

type EventData = { n: ChainNode; vertical: boolean; current: boolean };

function EventNode({ data }: NodeProps<Node<EventData>>) {
  const { n, vertical, current } = data;
  const [inPos, outPos] = vertical ? [Position.Top, Position.Bottom] : [Position.Left, Position.Right];
  const act = n.action && n.action !== 'allow' ? n.action : undefined;
  const cls = ['gp-node', act ? `a-${act}` : '', n.labels.includes('injection') ? 'inj' : '', current ? 'current' : ''].join(' ');
  return (
    <div className={cls}>
      <Handle type="target" position={inPos} style={{ opacity: 0 }} />
      <div className="k">
        <span>{n.kind.replace('_', ' ')}</span>
        {n.severity && <span className={`sev-${n.severity}`}>{n.severity}</span>}
      </div>
      <div className="t">{n.title}</div>
      {n.labels.length > 0 && (
        <div className="labels">
          {n.labels.map((l) => (
            <span key={l} className={`l-${l}`}>{l.replace('_', ' ')}</span>
          ))}
        </div>
      )}
      {act && (
        <span className="act" style={{ background: ACTION_STYLE[act].bg, color: ACTION_STYLE[act].fg }}>
          {act.replace('_', ' ').toUpperCase()}
        </span>
      )}
      <Handle type="source" position={outPos} style={{ opacity: 0 }} />
    </div>
  );
}

function LaneNode({ data }: NodeProps<Node<{ title: string }>>) {
  return <div className="lane">{data.title}</div>;
}

const nodeTypes = { event: EventNode, lane: LaneNode };

/** Narrow screens get a vertical timeline (lanes as columns), so nodes stay readable. */
function useVertical(): boolean {
  const [vertical, setVertical] = useState(false);
  useEffect(() => {
    const mq = window.matchMedia('(max-width: 640px)');
    const update = () => setVertical(mq.matches);
    update();
    mq.addEventListener('change', update);
    return () => mq.removeEventListener('change', update);
  }, []);
  return vertical;
}

/**
 * The attack chain as a graph. `visibleIds` reveals the chain step by step (all nodes when
 * omitted); `currentId` outlines the node of the step being played.
 */
export function ChainGraph({ chain, visibleIds, currentId }: { chain: Chain; visibleIds?: Set<string>; currentId?: string }) {
  const vertical = useVertical();
  const { nodes, edges } = useMemo(() => {
    const used = LANES.filter((lane) => chain.nodes.some((n) => laneOf(n.kind) === lane));
    const lane = (kind: string) => used.indexOf(laneOf(kind));
    const pos = (i: number, kind: string) => (vertical ? { x: lane(kind) * 200, y: i * 125 } : { x: i * 205, y: lane(kind) * 120 });
    const shown = (id: string) => !visibleIds || visibleIds.has(id);
    const nodes: Node[] = [
      ...used.map((l) => ({
        id: `lane-${l}`,
        type: 'lane',
        position: vertical ? { x: lane(l) * 200 + 30, y: -50 } : { x: -150, y: lane(l) * 120 + 28 },
        data: { title: LANE_TITLE[l] },
        draggable: false,
        selectable: false,
      })),
      // not-yet-revealed nodes stay mounted but invisible, so fitView frames the whole chain from the start
      ...chain.nodes.map((n, i) => ({
        id: n.id,
        type: 'event',
        position: pos(i, n.kind),
        style: shown(n.id) ? undefined : { opacity: 0, pointerEvents: 'none' as const },
        data: { n, vertical, current: n.id === currentId },
      })),
    ];
    const edges: Edge[] = chain.edges
      .filter((e) => shown(e.source) && shown(e.target))
      .map((e) => {
        const color = EDGE[e.type];
        return {
          id: e.id,
          source: e.source,
          target: e.target,
          type: e.type === 'sequence' ? 'smoothstep' : 'default',
          animated: e.type !== 'sequence',
          style: { stroke: color, strokeWidth: e.type === 'sequence' ? 1.4 : 2.2 },
          markerEnd: { type: MarkerType.ArrowClosed, color: e.type === 'sequence' ? '#8a8aa8' : color, width: 16, height: 16 },
        };
      });
    return { nodes, edges };
  }, [chain, vertical, visibleIds, currentId]);

  return (
    <ReactFlow
      key={`${chain.traceId}-${vertical}`}
      nodes={nodes}
      edges={edges}
      nodeTypes={nodeTypes}
      fitView
      fitViewOptions={{ padding: 0.12 }}
      minZoom={0.2}
      nodesConnectable={false}
    >
      <Background gap={22} size={1} />
      <Controls showInteractive={false} />
    </ReactFlow>
  );
}
