import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { buildChain } from './chain.js';
import { redact } from './detectors.js';
import { ShieldTrail } from './guard.js';
import { shadowReport } from './replay.js';
import { renderReport } from './report.js';
import { type EventStore, MemoryStore } from './store/memory.js';
import type { EventKind, GuardEvent } from './types.js';

export interface CollectorOptions {
  port?: number;
  /** Default 127.0.0.1: the collector is not meant to face the internet without a token. */
  host?: string;
  store?: EventStore;
  /** Analyses events that arrive without a decision (raw events from other services); its store is used. */
  guard?: ShieldTrail;
  /** When set, every request needs `Authorization: Bearer <token>`. */
  token?: string;
  /** Max request body, default 1 MB. */
  maxBody?: number;
  /**
   * Browser origins allowed to call the collector (CORS). Requests from any other web page are
   * refused, so a site you happen to visit cannot read your traces. Default: the hosted dashboard
   * and a local `next dev`.
   */
  allowOrigins?: string[];
}

export const DEFAULT_ORIGINS = ['https://sergemiro.github.io', 'http://localhost:3000', 'http://127.0.0.1:3000'];

const KINDS = new Set<EventKind>(['task', 'context', 'tool_call', 'http', 'error', 'app']);

const isObject = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
const SEVERITIES = new Set(['low', 'medium', 'high', 'critical']);
const ACTIONS = new Set(['allow', 'alert', 'block', 'would_block']);
const MAX_TS = 8.64e15; // the largest date JavaScript can represent

function validEvent(e: unknown): e is GuardEvent {
  const v = e as GuardEvent;
  return (
    isObject(v) &&
    typeof v.id === 'string' && typeof v.traceId === 'string' && typeof v.target === 'string' &&
    typeof v.actor === 'string' && KINDS.has(v.kind) &&
    Number.isFinite(v.ts) && v.ts >= 0 && v.ts < MAX_TS && Number.isFinite(v.seq) &&
    (v.data === undefined || isObject(v.data)) &&
    (v.labels === undefined || (Array.isArray(v.labels) && v.labels.every((l) => typeof l === 'string'))) &&
    (v.findings === undefined || (Array.isArray(v.findings) && v.findings.every((f) => isObject(f) && typeof f.type === 'string' && SEVERITIES.has(f.severity as string)))) &&
    (v.decision === undefined || (isObject(v.decision) && ACTIONS.has(v.decision.action as string)))
  );
}

/** Events from the network may come from code that never redacted them. */
function redactData(data: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(data)) {
    if (typeof v === 'number' || typeof v === 'boolean' || v === null) out[k] = v;
    else if (Array.isArray(v) && v.every((x) => typeof x === 'string')) out[k] = v.map((x) => redact(x, 500));
    else out[k] = redact(v);
  }
  return out;
}

function readBody(req: IncomingMessage, max: number): Promise<string> {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => {
      size += c.length;
      if (size > max) {
        // drain instead of destroying the socket, so the client still gets the 413
        req.removeAllListeners('data');
        req.resume();
        reject(Object.assign(new Error('body too large'), { status: 413 }));
      } else chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

export async function startCollector(opts: CollectorOptions = {}): Promise<{ server: Server; url: string; store: EventStore }> {
  const guard = opts.guard ?? new ShieldTrail({ store: opts.store ?? new MemoryStore() });
  const store = guard.store;

  const origins = opts.allowOrigins ?? DEFAULT_ORIGINS;

  const send = (res: ServerResponse, status: number, body: unknown, origin?: string) => {
    const headers: Record<string, string> = { 'content-type': 'application/json', vary: 'origin' };
    if (origin) {
      headers['access-control-allow-origin'] = origin;
      headers['access-control-allow-headers'] = 'content-type, authorization';
      // lets the hosted dashboard (https) read a collector on localhost
      headers['access-control-allow-private-network'] = 'true';
    }
    res.writeHead(status, headers);
    res.end(body === undefined ? '' : JSON.stringify(body));
  };

  const server = createServer(async (req, res) => {
    const origin = req.headers.origin;
    // non-browser clients send no Origin; browsers always do on cross-origin calls
    if (origin && !origins.includes(origin)) return send(res, 403, { error: 'origin not allowed' });
    const send_ = (status: number, body: unknown) => send(res, status, body, origin);
    try {
      if (req.method === 'OPTIONS') return send_(204, undefined);
      if (opts.token && req.headers.authorization !== `Bearer ${opts.token}`) return send_(401, { error: 'unauthorized' });
      const url = new URL(req.url ?? '/', 'http://collector');

      if (req.method === 'POST' && url.pathname === '/v1/events') {
        // JSON only: a form or text/plain POST from a web page would skip the CORS preflight
        if (!String(req.headers['content-type'] ?? '').startsWith('application/json')) return send_(415, { error: 'content-type must be application/json' });
        const parsed = JSON.parse(await readBody(req, opts.maxBody ?? 1_000_000));
        const list: unknown[] = Array.isArray(parsed) ? parsed : Array.isArray(parsed?.events) ? parsed.events : [parsed?.event ?? parsed];
        if (!list.every(validEvent)) return send_(400, { error: 'invalid event shape' });
        for (const e of list) {
          const raw = { ...(e.data ?? {}), url: e.target };
          e.labels ??= [];
          e.findings ??= [];
          e.data = redactData(e.data ?? {});
          e.target = redact(e.target, 2000);
          if (e.decision) await store.add(e);
          else await guard.ingest(e, raw); // detect on the raw values, store the redacted ones
        }
        return send_(202, { accepted: list.length });
      }

      if (req.method === 'GET' && url.pathname === '/v1/health') {
        return send_(200, { ok: true, events: (await store.list()).length, traces: (await store.traces(10_000)).length });
      }
      if (req.method === 'GET' && url.pathname === '/v1/report') return send_(200, shadowReport(await store.list()));
      if (req.method === 'GET' && url.pathname === '/v1/report.html') {
        res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'content-security-policy': "default-src 'none'; style-src 'unsafe-inline'", ...(origin ? { 'access-control-allow-origin': origin, vary: 'origin' } : {}) });
        return res.end(renderReport(await store.list()));
      }
      if (req.method === 'GET' && url.pathname === '/v1/chains') {
        const ids = await store.traces(Number(url.searchParams.get('limit') ?? 50));
        const chains = await Promise.all(ids.map(async (id) => buildChain(await store.list(id))));
        return send_(200, chains.map(({ events, nodes, edges, ...summary }) => ({ ...summary, events: events.length })));
      }
      const m = url.pathname.match(/^\/v1\/chains\/([\w-]{1,128})$/);
      if (req.method === 'GET' && m) {
        const events = await store.list(m[1]);
        return events.length ? send_(200, buildChain(events)) : send_(404, { error: 'no such trace' });
      }
      send_(404, { error: 'not found' });
    } catch (err) {
      const status = (err as { status?: number }).status ?? (err instanceof SyntaxError ? 400 : 500);
      send_(status, { error: status === 500 ? 'internal error' : (err as Error).message });
    }
  });

  await new Promise<void>((resolve) => server.listen(opts.port ?? 4319, opts.host ?? '127.0.0.1', resolve));
  const addr = server.address();
  const port = typeof addr === 'object' && addr ? addr.port : opts.port;
  return { server, url: `http://${opts.host ?? '127.0.0.1'}:${port}`, store };
}
