# ShieldTrail — plan of work and tests

ShieldTrail is a TypeScript SDK that sits inside a Node.js / Next.js app, records what AI agents
do (prompts, untrusted context, MCP tool calls, outbound HTTP, errors), **correlates those events
into attack chains**, and decides — in shadow or enforce mode — whether to stop the next step.

Not another egress firewall (Pipelock does that) and not a generic rule checker for agent traces
(Invariant does that). The angle is: *in-process correlation of agent traces with the app's own
HTTP, tool and error events, an attack-chain graph a human can read, and a shadow-first rollout
with replay before release.*

## Architecture

```
Node.js / Next.js app
  └─ shieldtrail SDK (browser-safe core)
       trace.context()  trace.tool()  trace.fetch()  trace.error()  guardMcpClient()
                │
                ▼
       Attack Chain Intelligence ── correlator: taint from untrusted input → sensitive access → egress
                │
                ▼
       Security Autopilot ───────── policy engine (shadow / enforce, per-rule override)
                │                    drift baseline (new tool, new domain, rate spike, tool-list change)
                ▼
       store (memory | PostgreSQL)   exporters (webhook, SIEM CEF/ECS, OpenTelemetry spans)
                │
                ▼
       collector (node:http)  ──▶  ShieldTrail Dashboard (Next.js + React Flow)
```

| Component | Choice | Where |
|---|---|---|
| SDK | TypeScript, zero runtime deps in core | `packages/shieldtrail` |
| Runtime | Node.js ≥ 20 / Next.js route handlers / browser (demo) | core is browser-safe |
| Event capture | explicit trace API + MCP client wrapper; picks up OTel trace ids | `guard.ts`, `mcp.ts` |
| Analysis | deterministic rules + optional `analyst` hook for an LLM | `policy.ts`, `chain.ts` |
| Storage | in-memory default, PostgreSQL via `pg` (optional peer) | `store/` |
| UI | Next.js static export + React Flow | `apps/web` |
| Integrations | MCP, HTTP, webhook, SIEM (CEF / ECS JSON), OpenTelemetry | `exporters.ts` |

Limits stated up front: the SDK only sees operations that go through it. Watching every process
and socket needs a proxy or a sensor — out of scope for v0.

## Data model

- **GuardEvent** `{ id, ts, traceId, parentId?, kind, actor, target, data, labels, findings, decision }`
  - `kind`: `task | context | tool_call | http | error | app`
  - `labels`: `untrusted`, `injection`, `sensitive`, `tainted`, `egress`
- **Decision** `{ action: allow | alert | block | would_block, ruleId?, reason, recommendation? }`
- **Chain** = all events of a trace + derived edges (causal `parentId` + data-flow from taint source
  to sink) + verdict (max severity) + narrative.

## Steps (each = commit + push)

1. **Scaffold + plan** — workspaces, TS config, vitest, this file.
2. **Detectors + policy engine** — prompt-injection heuristics, secret/PII patterns, rule matcher
   with `shadow` / `enforce` and per-rule `mode` override.
   *Tests*: injection phrases (incl. zero-width / encoded), secrets (AWS, GitHub, JWT, card with
   Luhn), rule matching by kind/target glob/taint/domain allow-list, shadow → `would_block`,
   per-rule enforce inside shadow mode.
3. **Attack Chain Intelligence** — correlator + `ShieldTrail` / `Trace` API (`context`, `tool`,
   `fetch`, `error`, `event`), `GuardBlockedError`, graph builder, narrative.
   *Tests*: injection → unexpected tool → egress builds one chain with data-flow edge and verdict
   `critical`; clean task stays `low`; blocked fetch never calls the network; tool result with
   secrets marks the trace `sensitive`.
4. **MCP wrapper + Security Autopilot drift** — `guardMcpClient(client, trace)` wraps
   `callTool` / `listTools`; baseline learns tools, domains, tool-list hash, per-target rate;
   findings carry evidence + a suggested rule.
   *Tests*: new tool / new domain / rate spike / tool description change (rug-pull) after
   `freeze()`; nothing reported while learning; suggested rule is valid input for the engine.
5. **Shadow mode report + replay + CLI** — `replay(events, policies)` re-runs recorded chains
   through new rules and diffs decisions; `shieldtrail replay events.jsonl --policy p.json`.
   *Tests*: tightening a rule turns `allow` into `block` and the diff says so; CLI exit code 1 when
   a new rule would block recorded traffic.
6. **Stores, exporters, collector** — `MemoryStore`, `PostgresStore`, webhook / CEF / ECS / OTel
   exporters, `startCollector()` (`POST /v1/events`, `GET /v1/chains`, `GET /v1/chains/:id`,
   `GET /v1/health`).
   *Tests*: CEF escaping, webhook payload with mocked fetch, OTel exporter against a fake tracer,
   collector round-trip over HTTP, Postgres round-trip (runs when `SHIELDTRAIL_PG_URL` is set,
   checked against a throwaway `postgres:16-alpine` container).
7. **Demo agent** — scripted agent (no LLM key needed) reading a poisoned document, calling an
   MCP `db.query` it was not asked to, then POSTing data out. Runs `--mode off|shadow|enforce`.
   *Tests*: off → exfil reaches the sink; shadow → reaches it, report shows `would_block`;
   enforce → blocked, sink empty, chain saved.
8. **Web: landing + live demo + dashboard** — static Next.js export for GitHub Pages: landing in
   the spirit of pipelab.org with its own palette, `/demo` runs the SDK in the browser with the
   React Flow attack graph and a with/without toggle, `/dashboard` reads a collector URL or demo
   data. *Tests*: `next build` (static export) passes; Playwright smoke on the built site: the
   demo blocks the exfil step and the graph renders nodes.
9. **GitHub Pages** — publish `apps/web/out` to the `gh-pages` branch.
10. **README** — install, 20-line quick start, architecture, honest comparison, limits.

## Quality gates (run locally before every push)

`npm run typecheck && npm test` in the repo root; `npm run build -w apps/web` for web steps.
GitHub Actions is not used for gating (account-level billing issue), so the local gates are the gates.

## Iteration 2 (23.11.2026)

- Renamed GuardPulse → ShieldTrail (package, CLI, repo, site under `/ShieldTrail`).
- Independent review → 9 fixes with tests in `packages/shieldtrail/test/hardening.test.ts` and the
  collector tests (ReDoS, collector origin allow-list + redaction + shape checks, URL/error
  redaction, non-string bodies, safe serialisation, replay fidelity, bounded memory, relative URLs).
- Site rebuilt in English and French (`/en/`, `/fr/`, root picks by browser language), light and
  dark theme (system default + toggle), a step-by-step *Get started* page, and a guided demo that
  plays the attack step by step and builds the graph as it goes.
- Smoke test covers: language redirect, both locales, theme toggle persistence, all three demo
  modes, the start page, phone width, and the dashboard against a live collector.


## Iteration 3 (24.11.2026) — ideas from Pipelock and Invariant

Analysis in [RESEARCH.md](RESEARCH.md). Added, each with tests and wired into graph, rules,
replay, report, dashboard and site (EN/FR): sequence rules + argument matching, injection in tool
output and MCP tool descriptions, canary tokens, task budgets, kill switch, HTML report (CLI,
collector, dashboard), URL entropy + IBAN detection, per-task allowed domains.
