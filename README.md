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

One guard per app, created from `shieldtrail/node`. It reads `shieldtrail.policy.json` (if present),
checks every `fetch` made inside a task, and in development starts the dev panel.

```ts
// lib/guard.ts
import { createGuard } from 'shieldtrail/node';

export const guard = createGuard({
  // real secrets: allowed towards their own domain only, never stored
  secrets: [{ name: 'STRIPE_KEY', value: process.env.STRIPE_KEY, domains: ['api.stripe.com'] }],
});
```

```ts
// where your agent runs
import { GuardBlockedError } from 'shieldtrail';
import { guard } from './lib/guard';

const trace = guard.startTrace({ agent: 'support-bot', task: 'Answer ticket #4521', allowedTools: ['tickets.*'] });

await trace.context({ source: attachmentUrl, text: pdfText });          // what the agent reads (untrusted)
const rows = await trace.tool('db.query', args, () => db.query(args));  // each tool call
try {
  await trace.run(() => agent.next());   // every fetch inside — yours, OpenAI's, Stripe's — goes through the rules
} catch (err) {
  if (err instanceof GuardBlockedError) console.log(err.decision);       // blocking mode only
}
await trace.usage(completion.usage);     // OpenAI / Anthropic / AI SDK usage, for token and spend budgets

const chain = await trace.chain();       // nodes, edges, severity, narrative
```

```json
// shieldtrail.policy.json — `npx shieldtrail check` validates it
{ "mode": "shadow", "allowedDomains": ["api.acme.com"], "rules": ["defaults"] }
```

`createGuard` from `shieldtrail` (no `/node`) is the same guard without file, `fetch` interception
or panel: it runs anywhere, including the browser and edge runtimes.

### Dev panel

In `next dev` (or any app with `NODE_ENV=development`) the guard serves a panel on
`http://127.0.0.1:4320`. Add it to your layout:

```tsx
{process.env.NODE_ENV === 'development' && <script src="http://127.0.0.1:4320/panel.js" async />}
```

A shield appears in the corner of a page **only** when an agent acted since that page was requested,
or when a step waits for approval — like the Next.js dev indicator. Click it to see:

- the page's tasks: each step, what was blocked or would be, and why;
- **Approvals** — steps held by an `ask` rule, with *Allow once* / *Deny*;
- **Rules** — every rule with an *Off / Watch / Block* switch (saved to `ruleModes` in the policy
  file) and whether it works, never matches, or is hidden behind another rule;
- *Stop all agents* (kill switch), the HTML report, and the full dashboard at
  `http://127.0.0.1:4320/` with the attack graph of every task.

It never runs in production, listens on `127.0.0.1` only, answers only pages from `localhost`,
and refuses requests whose `Host` is not a loopback name (DNS rebinding). With Next.js, add
`serverExternalPackages: ['shieldtrail']` to `next.config`. A complete app:
[examples/next-app](examples/next-app).

### MCP

```ts
import { guardMcpClient } from 'shieldtrail';

const mcp = guardMcpClient(client, trace, { server: 'helpdesk' }); // official MCP SDK Client
await mcp.listTools();   // a changed tool description later → drift.tool_definition_changed
await mcp.callTool({ name: 'db.query', arguments: { sql } });     // goes through the policy
```

### Next.js route handler

```ts
// app/api/refund/route.ts — the rule "refund-needs-human" (action "ask") holds the call until approved
import { GuardBlockedError } from 'shieldtrail';
import { guard } from '@/lib/guard';

export async function POST(req: Request) {
  const { order, amount } = await req.json();
  const trace = guard.startTrace({ agent: 'billing-bot', task: `Refund order ${order}` });
  try {
    return Response.json({ id: await trace.tool('payments.refund', { order, amount }, () => refund(order, amount)) });
  } catch (err) {
    if (err instanceof GuardBlockedError) return Response.json({ error: err.decision.reason }, { status: 403 });
    await trace.error(err);
    throw err;
  }
}
```

## How it works

```
Node.js / Next.js app
  └─ shieldtrail SDK            trace.context · trace.tool · trace.run (every fetch) · trace.usage · guardMcpClient
       │                         shieldtrail.policy.json  ◀──── dev panel switches, `check`, `replay`
       │
       ├─ Attack Chain Intelligence   taint from untrusted input → every later step
       │                              sensitive data in tool results → outbound bodies
       ├─ Security Autopilot          policy engine (off / shadow / enforce, per-rule override)
       │                              baseline drift: new tool, new domain, tool definition, rate, errors
       ├─ store                       MemoryStore | PostgresStore   (secrets redacted before storage)
       ├─ exporters                   webhook · SIEM (CEF / ECS) · OpenTelemetry spans · collector
       ├─ dev panel (development)     shield on pages with agent activity · approvals · rule switches · kill switch
       └─ collector (node:http) ───▶ Dashboard (Next.js + React Flow)
```

**Event kinds:** `task`, `context`, `tool_call`, `http`, `error`, `app`.
**Labels:** `untrusted`, `injection`, `sensitive`, `tainted`, `egress`, `unexpected_tool`, `drift`,
`canary`, `over_budget`, `secret_leak`.
**Decisions:** `allow`, `alert`, `would_block` (shadow), `block` (enforce); `ask` waits for a person
and is recorded as `allow` or `block` with who answered.

### Default rules

| Rule | Matches | Action |
|---|---|---|
| `secret-wrong-domain` | `http` carrying a bound secret to another domain | block |
| `exfil-after-injection` | `http` with `tainted` + `egress` | block |
| `secret-egress` | `http` with `sensitive` + `egress` | block |
| `tool-after-injection` | `tool_call` with `tainted` + `unexpected_tool` | alert (turn into block once `allowedTools` is tuned) |
| `unknown-domain` | `http` with `egress` | alert |
| `unexpected-tool` | `tool_call` with `unexpected_tool` | alert |
| `injection-seen` | `context` with `injection` | alert |
| `budget-exceeded` | step with `over_budget` | block |

Two protections sit above any rule set and block in every mode, even with custom rules: the kill
switch (`guard.halt()`) and planted canaries (`canary-leak`).

Rules are plain data, best kept in `shieldtrail.policy.json`. First match wins, so put `allow`
exceptions first; the string `"defaults"` stands for the built-in rules. `ruleModes` enforces one
rule while the rest stays in shadow (the panel's switches write there):

```json
{
  "mode": "shadow",
  "allowedDomains": ["api.acme.com"],
  "budget": { "maxCallsPerTool": 20, "maxCostUsd": 2 },
  "rules": [
    { "id": "trusted-partner", "match": { "kind": "http", "target": "https://api.partner.io/*" }, "action": "allow" },
    { "id": "refund-needs-human", "match": { "kind": "tool_call", "target": "payments.refund" }, "action": "ask" },
    "defaults"
  ],
  "ruleModes": { "exfil-after-injection": "enforce" }
}
```

Mistakes are reported with their place (`rules[1] (refund-needs-human).match: unknown key "kindd"`).
Options passed in code win over the file; `createGuard({ policyFile: false })` ignores it.

## More protections

Ideas taken from Pipelock, Invariant, nono, agentgateway, MCP Guardian and others, re-implemented
to feed the same chain, rules, replay, report and panel — see [docs/RESEARCH.md](docs/RESEARCH.md)
for what was taken, what was not, and why.

**Every request in a task** — with `shieldtrail/node`, any `fetch` made inside `trace.run()` or
`trace.tool()` goes through the rules: your calls and those of SDKs (OpenAI, Stripe…). Calls outside
a task pass untouched. Model APIs (OpenAI, Anthropic, Gemini, Mistral…) count as expected
destinations, so an agent's own model call after reading a poisoned page is not taken for
exfiltration (`aiProviders: false` turns that off).

**Secrets bound to domains** — `secrets: [{ name, value, domains }]`. Sent to its own domain, a
secret is fine (that domain counts as allowed); sent anywhere else, rule `secret-wrong-domain`
stops it. The exact value is removed from everything stored, even when no pattern knows its format.
An unset value (missing env var) is ignored.

**Ask a person** — `action: 'ask'`: in blocking mode the step waits for the dev panel or your
`approve` hook (Slack, admin UI…). No, a failing hook, no answer within `approvalTimeoutMs`
(2 min) or nobody to ask = blocked. Watch-only mode never waits.

```ts
createGuard({ approve: async ({ event, reason }) => slack.askYesNo(`${event.actor}: ${event.target} — ${reason}`) });
```

**Sequence rules** — block step B only if step A happened earlier in the same task; match tool
arguments with globs (`!` = does not match; for an array such as several recipients the rule
fires if any element matches — or, with `!`, if any element falls outside). E-mail addresses stay
readable in stored tool arguments (secrets do not), so `replay` reproduces these decisions. The
decision names the earlier step and the graph draws the link.

```ts
{
  id: 'no-external-forward',
  match: { kind: 'tool_call', target: 'email.send', args: { to: '!*@acme.com' },
           after: { kind: 'tool_call', target: 'email.inbox' } },
  action: 'block',
}
```

**Injections through tools and MCP** — what a tool returns (web page, e-mail, file) is scanned
for hidden instructions and taints the rest of the task; `guardMcpClient().listTools()` records a
poisoned tool description as an injection.

**Canary tokens** — plant a fake key; if it ever leaves through a request or a tool call, it is
blocked (even to an allowed domain, even in shadow mode).

```ts
const canary = createCanary();            // put it in .env, a prompt or a test customer row
const guard = createGuard({ canaries: [canary] });
```

**Budgets** — stop retry loops and hijacked agents: `budget: { maxToolCalls, maxCallsPerTool,
maxDurationMs, maxTokens, maxCostUsd }` on the guard, per task or in the policy file. Report model
usage with `trace.usage(response.usage)` (OpenAI, Anthropic and AI SDK shapes as they are; pass
`{ costUsd }` yourself — prices change too often to ship). Once over, the next action is stopped.

**Kill switch** — `guard.halt('incident #42')` blocks every tool call and request of every agent
until `guard.resume()`. In development it is the *Stop all agents* button of the panel.

**Per-task domains** — `startTrace({ allowedDomains: ['api.stripe.com'] })` widens the allow-list
for one task only.

**DLP** — secrets (AWS, GitHub, LLM keys, Slack, private keys, JWT), Luhn-valid cards,
checksum-valid IBANs, e-mails, and — once a task has been injected or has read sensitive data —
random-looking data smuggled in URLs to unknown domains (cursors, OAuth state, signed-URL
parameters and hashed file names are ignored). Canaries are also looked for in request headers.

**HTML report** — `npm run shieldtrail -- report events.jsonl --html report.html`, the
collector's `/v1/report.html`, or the dashboard's *Download HTML report* button: one file with
risk rating, the tasks that need attention, what blocking would stop, findings and a timeline.

## Shadow first, then enforce

1. **Observe** with `"mode": "shadow"`. Nothing is stopped; decisions are recorded as `would_block`.
2. **Review** `npm run shieldtrail -- report events.jsonl` (or the panel, or `/v1/report` on the collector).
3. **Enforce** only the rules you trust: *Block* in the panel, or `ruleModes` in the policy file.
4. **Check the rules** against recorded traffic: which work, which never fire, which are hidden
   behind an earlier rule.
5. **Replay before release:** re-run recorded chains through the next policy. Exit code 1 means the
   new policy would stop traffic that was allowed when recorded.

```bash
npm run shieldtrail -- check events.jsonl
# 10 rules checked against 42 recorded events
#   active   exfil-after-injection  decided 3×
#   shadowed partner-block  matches 1× but "unknown-domain" always decides first: move it up or remove it
#   unused   secret-wrong-domain  never matched: check its pattern, or keep it for traffic not recorded yet
npm run shieldtrail -- replay events.jsonl --policy policy.next.json
# 2 events replayed, 1 decisions changed
#   + STOP  http https://api.partner.io/invoices  (alert → block, rule no-unknown-egress)
```

Both read `./shieldtrail.policy.json` when `--policy` is not given.

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
npm run test:panel                      # dev panel end-to-end in local Chrome
npm run test:next                       # the Next.js example end-to-end in local Chrome
npm run build:web && npm run test:web   # static EN/FR site + Playwright smoke test (local Chrome)
npm run deploy:pages                    # publish the site to gh-pages
```

Layout: `packages/shieldtrail` (SDK, CLI, collector, dev panel), `apps/web` (site, demo, hosted
dashboard), `examples/agent-demo` (scenario shared by the CLI demo and the browser demo),
`examples/next-app` (Next.js app with the dev panel), `docs/PLAN.md` (plan of work and tests).

## Limits

- It sees what goes through the SDK: `trace.*` calls and every `fetch` inside a task. Libraries
  that do not use `fetch` (axios in Node, raw sockets) and other processes need a proxy or a sensor.
- The dev panel links a page to the tasks that started after the page was requested. Tasks of
  another tab that run at the same moment show up too.
- Injection detection is heuristic (normalised text, zero-width characters, base64). It raises the
  cost of an attack; it does not prove content is safe. Plug an LLM in through the `analyst` hook if
  you want a second opinion on a chain.
- `MemoryStore` keeps the last 100 000 events and is meant for development and tests. Use
  `PostgresStore` in production.

## Credits

Several protections are inspired by [Pipelock](https://github.com/pipelab-org/pipelock),
[Invariant Guardrails](https://github.com/invariantlabs-ai/invariant),
[nono](https://github.com/nolabs-ai/nono), [agentgateway](https://github.com/agentgateway/agentgateway),
[MCP Guardian](https://github.com/eqtylab/mcp-guardian) and [Cedar](https://github.com/cedar-policy/cedar)
(all Apache-2.0); no code was copied. Details in [docs/RESEARCH.md](docs/RESEARCH.md).

## License

MIT
