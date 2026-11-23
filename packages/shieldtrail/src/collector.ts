import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { buildChain } from './chain.js';
import { ShieldTrail } from './guard.js';
import { shadowReport } from './replay.js';
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
}

const KINDS = new Set<EventKind>(['task', 'context', 'tool_call', 'http', 'error', 'app']);

function validEvent(e: unknown): e is GuardEvent {
  const v = e as GuardEvent;
  return (
    typeof v === 'object' && v !== null &&
    typeof v.id === 'string' && typeof v.traceId === 'string' && typeof v.target === 'string' &&
    typeof v.actor === 'string' && KINDS.has(v.kind) && typeof v.ts === 'number' && typeof v.seq === 'number'
  );
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

  const send = (res: ServerResponse, status: number, body: unknown) => {
    res.writeHead(status, {
      'content-type': 'application/json',
      'access-control-allow-origin': '*',
      'access-control-allow-headers': 'content-type, authorization',
      // lets the hosted dashboard (https) read a collector on localhost
      'access-control-allow-private-network': 'true',
    });
    res.end(body === undefined ? '' : JSON.stringify(body));
  };

  const server = createServer(async (req, res) => {
    try {
      if (req.method === 'OPTIONS') return send(res, 204, undefined);
      if (opts.token && req.headers.authorization !== `Bearer ${opts.token}`) return send(res, 401, { error: 'unauthorized' });
      const url = new URL(req.url ?? '/', 'http://collector');

      if (req.method === 'POST' && url.pathname === '/v1/events') {
        const parsed = JSON.parse(await readBody(req, opts.maxBody ?? 1_000_000));
        const list: unknown[] = Array.isArray(parsed) ? parsed : Array.isArray(parsed?.events) ? parsed.events : [parsed?.event ?? parsed];
        if (!list.every(validEvent)) return send(res, 400, { error: 'invalid event shape' });
        for (const e of list) {
          if (e.decision) await store.add(e);
          else {
            e.labels ??= [];
            e.findings ??= [];
            e.data ??= {};
            await guard.ingest(e);
          }
        }
        return send(res, 202, { accepted: list.length });
      }

      if (req.method === 'GET' && url.pathname === '/v1/health') {
        return send(res, 200, { ok: true, events: (await store.list()).length, traces: (await store.traces(10_000)).length });
      }
      if (req.method === 'GET' && url.pathname === '/v1/report') return send(res, 200, shadowReport(await store.list()));
      if (req.method === 'GET' && url.pathname === '/v1/chains') {
        const ids = await store.traces(Number(url.searchParams.get('limit') ?? 50));
        const chains = await Promise.all(ids.map(async (id) => buildChain(await store.list(id))));
        return send(res, 200, chains.map(({ events, nodes, edges, ...summary }) => ({ ...summary, events: events.length })));
      }
      const m = url.pathname.match(/^\/v1\/chains\/([\w-]{1,128})$/);
      if (req.method === 'GET' && m) {
        const events = await store.list(m[1]);
        return events.length ? send(res, 200, buildChain(events)) : send(res, 404, { error: 'no such trace' });
      }
      send(res, 404, { error: 'not found' });
    } catch (err) {
      const status = (err as { status?: number }).status ?? (err instanceof SyntaxError ? 400 : 500);
      send(res, status, { error: status === 500 ? 'internal error' : (err as Error).message });
    }
  });

  await new Promise<void>((resolve) => server.listen(opts.port ?? 4319, opts.host ?? '127.0.0.1', resolve));
  const addr = server.address();
  const port = typeof addr === 'object' && addr ? addr.port : opts.port;
  return { server, url: `http://${opts.host ?? '127.0.0.1'}:${port}`, store };
}
