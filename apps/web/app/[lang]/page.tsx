import Link from 'next/link';
import { CodeTabs } from '../components/CodeTabs';
import { Cmd } from '../components/Cmd';
import { Footer, Nav } from '../components/Nav';
import { TrailField } from '../components/TrailField';
import { CLONE, dicts, type Lang } from '../i18n';

const NODE = `// lib/guard.ts — the rules live in shieldtrail.policy.json
import { createGuard } from 'shieldtrail/node';

export const guard = createGuard({
  secrets: [{ name: 'STRIPE_KEY', value: process.env.STRIPE_KEY, domains: ['api.stripe.com'] }],
});

// where your agent runs
const trace = guard.startTrace({ agent: 'support-bot', task: 'Answer ticket #4521', allowedTools: ['tickets.*'] });
await trace.context({ source: attachmentUrl, text: pdfText });   // what the agent reads
const rows = await trace.tool('db.query', args, () => db.query(args));
await trace.run(() => agent.next());   // every fetch inside goes through the rules
// a request to an unknown domain after an injection throws GuardBlockedError: it never leaves

console.log((await trace.chain()).narrative);`;

const MCP = `import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { guardMcpClient } from 'shieldtrail';

const client = new Client({ name: 'agent', version: '1.0.0' });
await client.connect(transport);

// every callTool goes through the rules, every tools/list feeds the baseline
const mcp = guardMcpClient(client, trace, { server: 'helpdesk' });
await mcp.listTools();
await mcp.callTool({ name: 'db.query', arguments: { sql } });`;

const NEXT = `// next.config.ts
export default { serverExternalPackages: ['shieldtrail'] };

// app/layout.tsx — the dev panel, only in \`next dev\`
{process.env.NODE_ENV === 'development' && <script src="http://127.0.0.1:4320/panel.js" async />}

// app/api/refund/route.ts — rule "refund-needs-human" (action: "ask") waits for your click in the panel
import { GuardBlockedError } from 'shieldtrail';
import { guard } from '@/lib/guard';

export async function POST(req: Request) {
  const { order, amount } = await req.json();
  const trace = guard.startTrace({ agent: 'billing-bot', task: \`Refund order \${order}\` });
  try {
    return Response.json({ id: await trace.tool('payments.refund', { order, amount }, () => refund(order, amount)) });
  } catch (err) {
    if (err instanceof GuardBlockedError) return Response.json({ error: err.decision.reason }, { status: 403 });
    throw err;
  }
}`;

const CI = `# before each release: check the rules against recorded traffic
npm run shieldtrail -- check events.jsonl
#   active    exfil-after-injection  decided 3×
#   shadowed  partner-block  matches 1× but "unknown-domain" always decides first
npm run shieldtrail -- replay events.jsonl
#   + STOP  http https://api.partner.io/invoices  (alert → block, rule no-unknown-egress)
#   exit code 1 → the new rules would break real traffic`;

export default async function Home({ params }: { params: Promise<{ lang: Lang }> }) {
  const { lang } = await params;
  const t = dicts[lang];
  const h = t.home;
  return (
    <>
      <Nav lang={lang} t={t} page="home" />
      <main id="main">
        <div className="hero">
          <TrailField />
          <div className="container">
            <div className="pills">
              <span className="pill pill-hot">{h.pill}</span>
              <span className="pill">{h.pill2}</span>
            </div>
            <h1>
              {h.h1a} <span className="grad">{h.h1grad}</span>
            </h1>
            <p className="lead">{h.lead}</p>
            <div className="cta">
              <Link className="btn btn-primary btn-lg" href={`/${lang}/demo/`}>
                {h.ctaDemo} <span aria-hidden="true">→</span>
              </Link>
              <Link className="btn btn-ghost btn-lg" href={`/${lang}/start/`}>
                {h.ctaStart}
              </Link>
            </div>
            <div className="term">
              <div className="term-bar">
                <i /> <i /> <i /> <span>{h.termTitle}</span>
              </div>
              <pre>
                {CLONE.split('\n').map((l) => (
                  <span key={l}>
                    <span className="c-prompt">$ </span>
                    {l}
                    {'\n'}
                  </span>
                ))}
                <span className="c-prompt">$ </span>npm run demo -- --mode enforce
              </pre>
            </div>
          </div>
        </div>

        <section>
          <div className="container">
            <div className="eyebrow">{h.problemEyebrow}</div>
            <h2>{h.problemTitle}</h2>
            <p className="sub">{h.problemSub}</p>
            <div className="chain-strip">
              {h.chain.map((c, i) => (
                <div key={c.title} className="chain-step">
                  <div className="num">{String(i + 1).padStart(2, '0')}</div>
                  <h3>{c.title}</h3>
                  <p>{c.text}</p>
                  <span className={`tag tag-${i}`}>{c.tag}</span>
                </div>
              ))}
            </div>
          </div>
        </section>

        <div className="divider" />

        <section id="how">
          <div className="container">
            <div className="eyebrow">{h.howEyebrow}</div>
            <h2>{h.howTitle}</h2>
            <div className="grid-3" style={{ marginTop: 34 }}>
              {h.how.map((c, i) => (
                <div key={c.title} className="card">
                  <span className="n">0{i + 1}</span>
                  <h3>{c.title}</h3>
                  <p>{c.text}</p>
                  <ul>
                    {c.points.map((p) => (
                      <li key={p}>{p}</li>
                    ))}
                  </ul>
                </div>
              ))}
            </div>
          </div>
        </section>

        <section style={{ paddingTop: 0 }}>
          <div className="container">
            <div className="eyebrow">{h.rolloutEyebrow}</div>
            <h2>{h.rolloutTitle}</h2>
            <p className="sub">{h.rolloutSub}</p>
            <div className="grid-3">
              {h.rollout.map((c, i) => (
                <div key={c.title} className="card">
                  <span className="n">0{i + 1}</span>
                  <h3>{c.title}</h3>
                  <p>{c.text}</p>
                  <code>{c.code}</code>
                </div>
              ))}
            </div>
          </div>
        </section>

        <div className="divider" />

        <section id="inside">
          <div className="container">
            <div className="eyebrow">{h.insideEyebrow}</div>
            <h2>{h.insideTitle}</h2>
            <p className="sub">{h.insideSub}</p>
            <div className="features">
              {h.inside.map((f) => (
                <div key={f.title} className="feature">
                  <h3>{f.title}</h3>
                  <p>{f.text}</p>
                  <code>{f.code}</code>
                </div>
              ))}
            </div>
          </div>
        </section>

        <div className="divider" />

        <section id="run">
          <div className="container">
            <div className="eyebrow">{h.runEyebrow}</div>
            <h2>{h.runTitle}</h2>
            <p className="sub">{h.runSub}</p>
            <div className="run-steps">
              {[CLONE, 'npm run demo -- --mode off\nnpm run demo -- --mode enforce', 'npm run shieldtrail -- collector'].map((code, i) => (
                <div key={code} className="run-step">
                  <b>
                    <span>{i + 1}.</span>
                    {h.runSteps[i]}
                  </b>
                  <Cmd code={code} copy={t.copy} copied={t.copied} />
                </div>
              ))}
            </div>
            <Link className="btn btn-ghost" href={`/${lang}/start/`}>
              {h.runGuide} →
            </Link>
          </div>
        </section>

        <section style={{ paddingTop: 0 }}>
          <div className="container">
            <div className="eyebrow">{h.codeEyebrow}</div>
            <h2>{h.codeTitle}</h2>
            <p className="sub">{h.codeSub}</p>
            <CodeTabs
              copy={t.copy}
              copied={t.copied}
              tabs={[
                { label: 'Node.js', raw: NODE, code: NODE },
                { label: 'MCP', raw: MCP, code: MCP },
                { label: 'Next.js', raw: NEXT, code: NEXT },
                { label: 'CI', raw: CI, code: CI },
              ]}
            />
          </div>
        </section>

        <div className="divider" />

        <section>
          <div className="container">
            <div className="eyebrow">{h.fitEyebrow}</div>
            <h2>{h.fitTitle}</h2>
            <p className="sub">{h.fitSub}</p>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    {h.fitHead.map((c, i) => (
                      <th key={i} scope="col">{c}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {h.fitRows.map((row) => (
                    <tr key={row[0]}>
                      {row.map((c, i) => (
                        <td key={i} className={i === 3 ? 'us' : undefined}>{c}</td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </section>

        <section style={{ paddingTop: 0 }}>
          <div className="container center">
            <div className="eyebrow">{h.integrationsEyebrow}</div>
            <h2>{h.integrationsTitle}</h2>
            <p className="sub">{h.integrationsSub}</p>
            <div className="logos">
              {['Node.js', 'Next.js', 'MCP SDK', 'OpenTelemetry', 'PostgreSQL', 'Webhooks', 'CEF', 'ECS (Elastic)', 'Microsoft Sentinel', 'Splunk'].map((l) => (
                <span key={l} className="logo-chip">{l}</span>
              ))}
            </div>
          </div>
        </section>

        <section className="final">
          <div className="container">
            <h2>
              {h.finalTitleA} <span className="grad">{h.finalGrad}</span> {h.finalTitleB}
            </h2>
            <p className="sub" style={{ margin: '0 auto 32px' }}>{h.finalSub}</p>
            <div className="cta" style={{ marginBottom: 0 }}>
              <Link className="btn btn-primary" href={`/${lang}/demo/`}>{h.finalDemo} →</Link>
              <Link className="btn btn-ghost" href={`/${lang}/dashboard/`}>{h.finalDash}</Link>
            </div>
          </div>
        </section>
      </main>
      <Footer lang={lang} t={t} />
    </>
  );
}
