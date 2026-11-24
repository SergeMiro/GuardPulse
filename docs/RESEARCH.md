# What we took from Pipelock and Invariant — and what we did not

Both projects are Apache-2.0. Nothing was copied: the ideas below were re-implemented from
their public documentation to fit ShieldTrail's shape — a library *inside* a Node.js / Next.js
app, where every protection feeds one attack chain, one set of rules, one replay and one report.

Sources read on 24.11.2026: the README and feature list of
[pipelab-org/pipelock](https://github.com/pipelab-org/pipelock) (v3.8, Go egress proxy + MCP
wrapper) and the README and standard library of
[invariantlabs-ai/invariant](https://github.com/invariantlabs-ai/invariant) (Guardrails rule
language and analyzer).

## How each one works

| | Pipelock | Invariant Guardrails | ShieldTrail |
|---|---|---|---|
| Where | Proxy between the agent and the network / MCP servers | Proxy (Gateway) or a Python analyzer run on a trace | Library inside the app |
| What it sees | Every request routed through it, even from programs that know nothing about it | Messages and tool calls of the agent | Agent steps **and** the app's own requests, errors and events, per task |
| Rules | Config presets (strict / balanced / audit), built-in scanners | A small Python-like rule language with flows `(a) -> (b)` | Plain objects, first match wins, shadow / enforce per rule |
| Output | Signed receipts, flight recorder, HTML report, dashboard (Pro) | Errors returned to the caller | Attack graph, narrative, replay, HTML report, SIEM / OTel |

## Taken, and why

| Feature in ShieldTrail | Idea from | Why it earns its place | API |
|---|---|---|---|
| **Sequence rules** + tool-argument matching | Invariant flows `(call) -> (call2)` and `tool:send_email({to: …})` | This *is* the attack-chain idea expressed as a rule: block step B only when step A happened earlier in the same task. The graph draws the cause. | `match: { after: {…}, args: { to: '!*@acme.com' } }` |
| **Injection in tool output** | Pipelock response scanning, Invariant `prompt_injection(output.content)` | The commonest real vector is not a document the app reads but what a tool returns (web page, e-mail). It now taints the task like a document does. | automatic in `trace.tool()` |
| **Poisoned MCP tool descriptions** | Pipelock tool poisoning, Invariant MCP scanning | Tool descriptions go straight into the model's context. | automatic in `guardMcpClient().listTools()` |
| **Canary tokens** | Pipelock `canary` | The one alarm that cannot be false: a fake key that should never leave. One line to set up; blocks even in shadow mode. | `createCanary()`, `canaries: [...]` |
| **Task budgets** | Pipelock denial-of-wallet, Invariant `count(min, max)` | Retry loops and hijacked agents burn API money before anyone looks. | `budget: { maxToolCalls, maxCallsPerTool, maxDurationMs }` |
| **Kill switch** | Pipelock kill switch | During an incident you want one call that stops every agent. | `guard.halt(reason)`, `guard.resume()` |
| **HTML incident report** | Pipelock `report --input events.jsonl` | A single file a security team can read without installing anything. Same function in CLI, collector and dashboard. | `report --html`, `/v1/report.html`, `renderReport()` |
| **Encoded data in URLs, IBAN** | Pipelock DLP + entropy checks | Base64-smuggled data in a query string or path; bank details matter for EU users. | automatic |
| **Per-task allowed domains** | Pipelock per-agent profiles | A billing task may call Stripe; the support bot may not. | `startTrace({ allowedDomains })` |

Each of these is labelled on the event (`injection`, `canary`, `over_budget`…), so it shows in the
graph, can be matched by any rule, is reproduced by `replay`, and is counted in the report.

## Not taken, and why

| Pipelock / Invariant feature | Why not (for now) |
|---|---|
| TLS interception, forward proxy, WebSocket frame scanning, DNS checks | Proxy territory. An in-process library sees requests before TLS, so it does not need them; programs that bypass the SDK need a proxy — use Pipelock next to ShieldTrail. |
| Process sandbox, host containment (Landlock, seccomp, namespaces) | Operating-system level, out of scope for a library. |
| Signed receipts, hash-chained flight recorder, Rekor anchoring | Valuable for audits, but adds key management. Candidate for a later version (hash chain first, signing after). |
| Fleet control plane, enrollment, remote kill over mTLS | Enterprise infrastructure; the kill switch here is per process. |
| A rule language of its own | Plain objects are typed, testable and need no parser; sequence rules cover the flow cases that motivated Invariant's language. |
| ML-based detectors (Invariant moderation, PII models) | Would add heavy dependencies; the `analyst` hook is where a model can be plugged in. |
| 74 DLP patterns, 34 injection patterns | We keep a short, high-signal list (with checksums where they exist) to stay fast and low-noise; extending it is a one-line change per pattern. |
