import type { Metadata } from 'next';
import Link from 'next/link';
import { Cmd } from '../../components/Cmd';
import { Footer, Nav } from '../../components/Nav';
import { dicts, type Lang } from '../../i18n';

const EXPECTED = `BLOCKED     5. POST customers to exfil.attacker.dev
            BLOCKED by exfil-after-injection. Request never left the app.
OK          6. Reply to customer

Data that reached the attacker: none`;

const RULES = `import { createCanary, createGuard, defaultRules } from 'shieldtrail';

const canary = createCanary();        // plant it in a .env, a prompt or a test customer row

const guard = createGuard({
  mode: 'shadow',
  canaries: [canary],
  budget: { maxCallsPerTool: 20 },
  rules: [
    {
      id: 'no-external-forward',
      description: 'Inbox content forwarded outside the company',
      match: {
        kind: 'tool_call',
        target: 'email.send',
        args: { to: '!*@acme.com' },               // ! = does NOT match
        after: { kind: 'tool_call', target: 'email.inbox' },
      },
      action: 'block',
      mode: 'enforce',                              // this rule blocks, the rest only watches
    },
    ...defaultRules,
  ],
});

app.post('/admin/stop-agents', () => guard.halt('stopped from the admin panel'));`;

const SNIPPET = `import { createGuard, GuardBlockedError } from 'shieldtrail';

const guard = createGuard({ mode: 'shadow', allowedDomains: ['api.your-app.com'] });
const trace = guard.startTrace({ agent: 'support-bot', task: 'Answer a ticket', allowedTools: ['tickets.*'] });

await trace.context({ source: fileUrl, text: fileText });          // what the agent reads
const rows = await trace.tool('db.query', args, () => db.query(args)); // each tool call
const res = await trace.fetch(url, { method: 'POST', body });          // each outbound request`;

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
              <Link className="btn btn-primary" href={`/${lang}/dashboard/?api=http://127.0.0.1:4319`}>
                {dash.open} →
              </Link>
              <p className="note">
                {dash.note} <code>{dash.noteCode}</code> {dash.noteEnd}
              </p>
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
