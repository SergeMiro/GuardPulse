import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { auditRules } from './audit.js';
import { buildChain } from './chain.js';
import { redact } from './detectors.js';
import { ShieldTrail } from './guard.js';
import { shadowReport } from './replay.js';
import { PANEL_JS } from './panel-source.js';
import { renderReport } from './report.js';
import { type EventStore, MemoryStore } from './store/memory.js';
import type { EventKind, GuardEvent, Mode } from './types.js';

export interface CollectorOptions {
  port?: number;
  /** Default 127.0.0.1: the collector is not meant to face the internet without a token. */
  host?: string;
  store?: EventStore;
  /**
   * Analyses events that arrive without a decision (raw events from other services); its store is used.
   * A function is read on every request, so a dev server can swap in the guard of a hot-reloaded module.
   */
  guard?: ShieldTrail | (() => ShieldTrail);
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
  /**
   * Dev panel mode: serves the panel script and the full dashboard, lets the panel answer 'ask' steps,
   * switch rule modes and use the kill switch, and accepts any http://localhost:<port> page as origin.
   * Never turn this on for a collector other people can reach.
   */
  devtools?: {
    /** Persists a rule mode switched in the panel (shieldtrail/node writes shieldtrail.policy.json). */
    onRuleMode?: (ruleId: string, mode: Mode) => void;
    /** Every guard of the process: approvals, kill switch and rule switches reach all of them. */
    guards?: () => ShieldTrail[];
  };
}


const DASHBOARD_HTML = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ShieldTrail dashboard</title><style>html,body{margin:0;background:#0a0e1c}</style></head>
<body><script src="/panel.js" data-full></script></body></html>`;

const isLoopbackOrigin = (o: string) => /^https?:\/\/(localhost|127\.0\.0\.1|\[::1\])(:\d+)?$/.test(o);
const MODE_SET = new Set(['off', 'shadow', 'enforce']);

export const DEFAULT_ORIGINS = ['https://sergemiro.github.io', 'http://localhost:3000', 'http://127.0.0.1:3000'];

const LOOPBACK = new Set(['localhost', '127.0.0.1', '[::1]', '::1']);
/**
 * DNS rebinding: a web page can point its own domain at 127.0.0.1 and then talk to the collector as
 * "same origin", skipping CORS. A loopback collector therefore only answers to loopback Host names.
 */
export function hostAllowed(hostHeader: string | undefined, boundHost: string): boolean {
  if (!LOOPBACK.has(boundHost)) return true; // exposed on purpose: the token is the protection
  if (!hostHeader) return false;
  const name = hostHeader.startsWith('[') ? hostHeader.slice(0, hostHeader.indexOf(']') + 1) : hostHeader.split(':')[0];
  return LOOPBACK.has(name.toLowerCase());
}

const KINDS = new Set<EventKind>(['task', 'context', 'tool_call', 'http', 'error', 'app']);

const isObject = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
const SEVERITIES = new Set(['low', 'medium', 'high', 'critical']);
const ACTIONS = new Set(['allow', 'alert', 'block', 'would_block', 'ask']);
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
  const fixed = typeof opts.guard === 'function' ? undefined : (opts.guard ?? new ShieldTrail({ store: opts.store ?? new MemoryStore() }));
  const current = (): ShieldTrail => (typeof opts.guard === 'function' ? opts.guard() : fixed!);
  const dev = opts.devtools;

  // the dev server can approve steps and rewrite the policy: only pages on this machine may call it
  const origins = opts.allowOrigins ?? (dev ? [] : DEFAULT_ORIGINS);
  const originAllowed = (o: string) => origins.includes(o) || (dev !== undefined && isLoopbackOrigin(o));

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
    if (!hostAllowed(req.headers.host, opts.host ?? '127.0.0.1')) return send(res, 421, { error: 'host not allowed' });
    // non-browser clients send no Origin; browsers always do on cross-origin calls
    if (origin && !originAllowed(origin)) return send(res, 403, { error: 'origin not allowed' });
    const send_ = (status: number, body: unknown) => send(res, status, body, origin);
    const guard = current();
    const store = guard.store;
    const everyGuard = () => dev?.guards?.() ?? [guard];
    try {
      if (req.method === 'OPTIONS') return send_(204, undefined);
      if (opts.token && req.headers.authorization !== `Bearer ${opts.token}`) return send_(401, { error: 'unauthorized' });
      const url = new URL(req.url ?? '/', 'http://collector');

      // JSON only: a form or text/plain POST from a web page would skip the CORS preflight
      const json = async () => {
        if (!String(req.headers['content-type'] ?? '').startsWith('application/json')) throw Object.assign(new Error('content-type must be application/json'), { status: 415 });
        return JSON.parse(await readBody(req, opts.maxBody ?? 1_000_000));
      };

      if (dev && req.method === 'GET' && (url.pathname === '/' || url.pathname === '/panel.js')) {
        const js = url.pathname === '/panel.js';
        res.writeHead(200, {
          'content-type': js ? 'text/javascript; charset=utf-8' : 'text/html; charset=utf-8',
          'cache-control': 'no-store',
          ...(js ? {} : { 'content-security-policy': "default-src 'self'; style-src 'unsafe-inline'; img-src data:" }),
        });
        return res.end(js ? PANEL_JS : DASHBOARD_HTML);
      }

      if (dev && req.method === 'GET' && url.pathname === '/v1/page') {
        // everything that happened since the page was requested, grouped by task
        const since = Number(url.searchParams.get('since') ?? 0) || 0;
        const all = await store.list();
        const ids = [...new Set(all.filter((e) => e.ts >= since).map((e) => e.traceId))].slice(-50);
        const chains = ids.map((id) => buildChain(all.filter((e) => e.traceId === id)));
        const pending = everyGuard().flatMap((x) => [...x.pending.values()].map(({ settle, ...p }) => p));
        const halted = everyGuard().find((x) => x.halted)?.halted ?? null;
        return send_(200, { chains, pending, halted, mode: guard.policy.mode, now: Date.now() });
      }

      if (dev && req.method === 'POST' && url.pathname.startsWith('/v1/pending/')) {
        const body = await json();
        if (typeof body?.approved !== 'boolean') return send_(400, { error: 'approved must be true or false' });
        const id = decodeURIComponent(url.pathname.slice('/v1/pending/'.length));
        const ok = everyGuard().some((x) => x.answer(id, body.approved, 'dev panel'));
        return ok ? send_(200, { ok }) : send_(404, { error: 'no longer pending' });
      }

      if (dev && req.method === 'GET' && url.pathname === '/v1/policy') {
        const { mode, rules } = guard.policy;
        const audit = auditRules(await store.list(), { mode, rules, allowedDomains: guard.policy.allowedDomains });
        return send_(200, {
          mode,
          saved: dev.onRuleMode !== undefined,
          rules: rules.map((r, i) => ({ id: r.id, description: r.description, action: r.action, mode: r.mode ?? mode, audit: audit[i] })),
        });
      }

      if (dev && req.method === 'POST' && url.pathname === '/v1/policy/rule') {
        const body = await json();
        if (typeof body?.id !== 'string' || !MODE_SET.has(body.mode)) return send_(400, { error: 'expected { id, mode: off | shadow | enforce }' });
        const owners = everyGuard().filter((x) => x.policy.rules.some((r) => r.id === body.id));
        if (!owners.length) return send_(404, { error: 'no such rule' });
        try {
          dev.onRuleMode?.(body.id, body.mode); // persist first: a failure must not leave the panel and the file disagreeing
        } catch (err) {
          return send_(500, { error: `not saved: ${(err as Error).message}` });
        }
        for (const x of owners) x.setPolicy({ rules: x.policy.rules.map((r) => (r.id === body.id ? { ...r, mode: body.mode } : r)) });
        return send_(200, { ok: true, saved: dev.onRuleMode !== undefined });
      }

      if (dev && req.method === 'POST' && (url.pathname === '/v1/halt' || url.pathname === '/v1/resume')) {
        const body = await json();
        const reason = typeof body?.reason === 'string' && body.reason ? body.reason.slice(0, 200) : 'stopped from the dev panel';
        for (const x of everyGuard()) (url.pathname === '/v1/halt' ? x.halt(reason) : x.resume());
        return send_(200, { halted: guard.halted ?? null });
      }

      if (req.method === 'POST' && url.pathname === '/v1/events') {
        const parsed = await json();
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

  await new Promise<void>((resolve, reject) => {
    // without this, a busy port is an uncaught 'error' event that kills the host process
    server.once('error', reject);
    server.listen(opts.port ?? 4319, opts.host ?? '127.0.0.1', () => {
      server.off('error', reject);
      resolve();
    });
  });
  const addr = server.address();
  const port = typeof addr === 'object' && addr ? addr.port : opts.port;
  return { server, url: `http://${opts.host ?? '127.0.0.1'}:${port}`, store: current().store };
}
