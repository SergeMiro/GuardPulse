'use client';
import { Background, Controls, type Edge, Handle, MarkerType, type Node, type NodeProps, Position, ReactFlow } from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import type { Chain, ChainNode } from 'guardpulse';
import { useEffect, useMemo, useState } from 'react';

const LANES = ['task', 'context', 'tool_call', 'http', 'other'] as const;
const LANE_TITLE = { task: 'agent', context: 'input', tool_call: 'tools / MCP', http: 'network', other: 'app' };
const laneOf = (kind: string) => (LANES.includes(kind as never) ? kind : 'other') as (typeof LANES)[number];

const ACTION_STYLE: Record<string, { bg: string; fg: string }> = {
  block: { bg: '#ff5a5f', fg: '#fff' },
  would_block: { bg: '#ffb547', fg: '#1a1206' },
  alert: { bg: 'rgba(255,181,71,0.15)', fg: '#ffb547' },
};

function EventNode({ data }: NodeProps<Node<{ n: ChainNode; vertical: boolean }>>) {
  const n = data.n;
  const [inPos, outPos] = data.vertical ? [Position.Top, Position.Bottom] : [Position.Left, Position.Right];
  const act = n.action && n.action !== 'allow' ? n.action : undefined;
  const cls = ['gp-node', `k-${n.kind}`, act ? `a-${act}` : '', n.labels.includes('injection') ? 'inj' : ''].join(' ');
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
          GUARDPULSE: {act.replace('_', ' ').toUpperCase()}
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

export function ChainGraph({ chain }: { chain: Chain }) {
  const vertical = useVertical();
  const { nodes, edges } = useMemo(() => {
    const used = LANES.filter((lane) => chain.nodes.some((n) => laneOf(n.kind) === lane));
    const lane = (kind: string) => used.indexOf(laneOf(kind));
    const pos = (i: number, kind: string) => (vertical ? { x: lane(kind) * 200, y: i * 125 } : { x: i * 205, y: lane(kind) * 120 });
    const nodes: Node[] = [
      ...used.map((l) => ({
        id: `lane-${l}`,
        type: 'lane',
        position: vertical ? { x: lane(l) * 200 + 30, y: -50 } : { x: -150, y: lane(l) * 120 + 28 },
        data: { title: LANE_TITLE[l] },
        draggable: false,
        selectable: false,
      })),
      ...chain.nodes.map((n, i) => ({ id: n.id, type: 'event', position: pos(i, n.kind), data: { n, vertical } })),
    ];
    const edges: Edge[] = chain.edges.map((e) => {
      const color = e.type === 'taint' ? '#ff3d7f' : e.type === 'data' ? '#ffb547' : '#4a4a72';
      return {
        id: e.id,
        source: e.source,
        target: e.target,
        type: e.type === 'sequence' ? 'smoothstep' : 'default',
        animated: e.type !== 'sequence',
        label: e.type === 'sequence' ? undefined : e.type === 'taint' ? 'injected instructions' : 'sensitive data',
        labelStyle: { fill: color, fontFamily: 'var(--mono)', fontSize: 10 },
        labelBgStyle: { fill: '#0c0c16' },
        style: { stroke: color, strokeWidth: e.type === 'sequence' ? 1.4 : 2 },
        markerEnd: { type: MarkerType.ArrowClosed, color, width: 16, height: 16 },
      };
    });
    return { nodes, edges };
  }, [chain, vertical]);

  return (
    <ReactFlow
      key={`${chain.traceId}-${vertical}`}
      nodes={nodes}
      edges={edges}
      nodeTypes={nodeTypes}
      fitView
      fitViewOptions={{ padding: 0.12 }}
      minZoom={0.2}
      proOptions={{ hideAttribution: false }}
      nodesConnectable={false}
    >
      <Background gap={22} size={1} color="#22223a" />
      <Controls showInteractive={false} />
    </ReactFlow>
  );
}
