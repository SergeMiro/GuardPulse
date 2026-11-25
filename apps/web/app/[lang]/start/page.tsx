import type { Metadata } from 'next';
import { Cmd } from '../../components/Cmd';
import { Footer, Nav } from '../../components/Nav';
import { dicts, type Lang } from '../../i18n';

const EXPECTED = `BLOCKED     5. POST customers to exfil.attacker.dev
            BLOCKED by exfil-after-injection. Request never left the app.
OK          6. Reply to customer

Data that reached the attacker: none`;

const RULES = `{
  "mode": "shadow",
  "allowedDomains": ["api.acme.com"],
  "budget": { "maxCallsPerTool": 20, "maxCostUsd": 2 },
  "rules": [
    {
      "id": "no-external-forward",
      "description": "Inbox content forwarded outside the company",
      "match": {
        "kind": "tool_call",
        "target": "email.send",
        "args": { "to": "!*@acme.com" },
        "after": { "kind": "tool_call", "target": "email.inbox" }
      },
      "action": "block",
      "mode": "enforce"
    },
    {
      "id": "refund-needs-human",
      "match": { "kind": "tool_call", "target": "payments.refund" },
      "action": "ask"
    },
    "defaults"
  ]
}`;

const SNIPPET = `// lib/guard.ts — reads shieldtrail.policy.json, starts the dev panel in development
import { createGuard } from 'shieldtrail/node';
export const guard = createGuard({
  secrets: [{ name: 'STRIPE_KEY', value: process.env.STRIPE_KEY, domains: ['api.stripe.com'] }],
});

// where your agent runs
const trace = guard.startTrace({ agent: 'support-bot', task: 'Answer a ticket', allowedTools: ['tickets.*'] });
await trace.context({ source: fileUrl, text: fileText });              // what the agent reads
const rows = await trace.tool('db.query', args, () => db.query(args)); // each tool call
await trace.run(() => agent.next());                                    // every fetch inside is checked
await trace.usage(completion.usage);                                    // tokens, for budgets

// app/layout.tsx — the panel, development only (Next.js: serverExternalPackages: ['shieldtrail'])
{process.env.NODE_ENV === 'development' && <script src="http://127.0.0.1:4320/panel.js" async />}`;

export async function generateMetadata({ params }: { params: Promise<{ lang: Lang }> }): Promise<Metadata> {
  const { lang } = await params;
  return { title: `${dicts[lang].start.title} — ShieldTrail` };
}

export default async function StartPage({ params }: { params: Promise<{ lang: Lang }> }) {
  const { lang } = await params;
  const t = dicts[lang];
  const s = t.start;
  const [run, dash, add, roll] = s.steps;
  return (
    <>
      <Nav lang={lang} t={t} page="start" />
      <main id="main" className="container">
        <div className="page-head">
          <h1>{s.title}</h1>
          <p className="lead">{s.lead}</p>
          <h2 style={{ fontSize: 16, margin: '26px 0 4px' }}>{s.needTitle}</h2>
          <div className="need">
            {s.need.map((n) => (
              <span key={n}>{n}</span>
            ))}
          </div>
          <Cmd label={s.needCheck} code="node -v" copy={t.copy} copied={t.copied} />
        </div>

        <div className="guide">
          <div className="guide-step">
            <div className="badge">1</div>
            <div>
              <h2>{run.title}</h2>
              <p>{run.text}</p>
              {run.blocks.map((b) => (
                <Cmd key={b.code} label={b.label} code={b.code} copy={t.copy} copied={t.copied} />
              ))}
              <span className="cmd-label">{run.expect}</span>
              <div className="cmd">
                <pre>{EXPECTED}</pre>
              </div>
            </div>
          </div>

          <div className="guide-step">
            <div className="badge">2</div>
            <div>
              <h2>{dash.title}</h2>
              <p>{dash.text}</p>
              {dash.blocks.map((b) => (
                <Cmd key={b.code} label={b.label} code={b.code} copy={t.copy} copied={t.copied} />
              ))}
            </div>
          </div>

          <div className="guide-step">
            <div className="badge">3</div>
            <div>
              <h2>{add.title}</h2>
              <p>{add.text}</p>
              {add.blocks.map((b) => (
                <Cmd key={b.code} label={b.label} code={b.code} copy={t.copy} copied={t.copied} />
              ))}
              <span className="cmd-label">{add.codeTitle}</span>
              <div className="cmd">
                <pre>{SNIPPET}</pre>
              </div>
            </div>
          </div>

          <div className="guide-step">
            <div className="badge">4</div>
            <div>
              <h2>{roll.title}</h2>
              <p>{roll.text}</p>
              {roll.blocks.map((b) => (
                <Cmd key={b.code} label={b.label} code={b.code} copy={t.copy} copied={t.copied} />
              ))}
            </div>
          </div>
        </div>

        <div className="guide" style={{ paddingTop: 0 }}>
          <div className="guide-step">
            <div className="badge">5</div>
            <div>
              <h2>{s.rules.title}</h2>
              <p>{s.rules.text}</p>
              <span className="cmd-label">shieldtrail.policy.json</span>
              <div className="cmd">
                <pre>{RULES}</pre>
              </div>
              <ul style={{ margin: '6px 0 0', paddingLeft: 20, color: 'var(--muted)', fontSize: 14 }}>
                {s.rules.notes.map((n) => (
                  <li key={n}>{n}</li>
                ))}
              </ul>
            </div>
          </div>
        </div>

        <section className="faq" style={{ paddingTop: 30 }}>
          <h2>{s.faqTitle}</h2>
          {s.faq.map((f) => (
            <details key={f.q}>
              <summary>{f.q}</summary>
              <p>{f.a}</p>
            </details>
          ))}
        </section>
      </main>
      <Footer lang={lang} t={t} />
    </>
  );
}
