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

---

# Round 2 (24.11.2026): Rust projects, and making it simple to use

Sources read on 24.11.2026 (README and feature docs, not code), all Apache-2.0:
[nono](https://github.com/nolabs-ai/nono) (agent sandbox from the Sigstore team),
[agentgateway](https://github.com/agentgateway/agentgateway) (Linux Foundation proxy for LLM, MCP and A2A),
[MCP Guardian](https://github.com/eqtylab/mcp-guardian) (MCP proxy with live approvals),
[Cedar](https://github.com/cedar-policy/cedar) (AWS policy language and analyzer),
[Kingfisher](https://github.com/mongodb/kingfisher) (secret scanner with live validation).
[HOL Guard](https://github.com/hashgraph-online/hol-guard) (Python) was read for its approval flow.

## Taken, and how it was adapted

| Feature in ShieldTrail | Idea from | Adapted how | API |
|---|---|---|---|
| **Secrets bound to domains** | nono phantom tokens / credential injection | nono keeps the real key outside the agent's sandbox. A library lives in the same process as the key, so promising that would be false. What it can do honestly: know the exact value and where it may go, stop it anywhere else, and keep the value out of storage. Same exact-match mechanism as canaries, so no false positives. | `secrets: [{ name, value, domains }]` |
| **Ask a person** | MCP Guardian approvals, HOL Guard "request approval" | One more rule action instead of a separate system: shadow mode never waits, enforce waits for the dev panel or an `approve` hook, silence = blocked; the answer is part of the recorded decision, and replay treats answered steps as unchanged. | `action: 'ask'`, `approve` |
| **Token and spend budgets** | agentgateway budget and spend controls | No built-in price table (it would be stale within a month): the app reports usage in the provider's own shape and its own cost. | `trace.usage()`, `maxTokens`, `maxCostUsd` |
| **Rule check** | Cedar's analyzer (shadowed / unreachable policies) | Cedar proves properties of the policy text. We answer the practical question on recorded traffic with the replay engine: which rules decide, which match but are always pre-empted (and by which rule), which never match. | `shieldtrail check events.jsonl` |
| **One policy file** | agentgateway / nono profiles | Plain JSON next to package.json, validated with exact error places, `"defaults"` for the built-in rules, `ruleModes` for per-rule switches. The SDK, `check`, `replay` and the panel read and write the same file. | `shieldtrail.policy.json` |
| **Every request in a task** | proxies see all traffic | A library cannot see sockets, but it can see every `fetch` made inside a task (AsyncLocalStorage), which covers OpenAI, Stripe and most HTTP SDKs in Node 18+. | `trace.run()`, automatic in `trace.tool()` |

## Not taken

| Feature | Why not |
|---|---|
| Kernel sandbox, rollback snapshots (nono, sandlock) | Operating-system level, not a library's job. |
| Tamper-evident / signed audit log (nono) | A hash chain without external signing can be recomputed by whoever can edit the log; worth doing only together with signing and key management. Still on the list. |
| LLM routing, failover, inference scheduling (agentgateway) | A gateway's job; ShieldTrail sits inside the app next to whatever client you use. |
| Hundreds of secret rules and live validation (Kingfisher) | Your own keys are covered exactly by bound secrets; a long pattern list adds false alarms. Kingfisher can run as a CI scanner next to ShieldTrail. |
| A policy language (Cedar) | JSON rules stay typed, testable and need no parser; `check` covers the analysis people actually need. |

## Built around simplicity

- `createGuard()` from `shieldtrail/node` is the whole setup: policy file, `fetch` checks and dev panel.
- The dev panel is the single place to look while developing: a shield only on pages where an agent
  acted, approvals, rule switches, kill switch, and the full dashboard one click away.
- Every new protection is a label or a rule, so it shows in the graph, the report, `check` and `replay`
  without extra wiring.
