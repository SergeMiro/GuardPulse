import Link from 'next/link';
import { CodeTabs } from '../components/CodeTabs';
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
            <div className="features" style={{ marginTop: 30 }}>
              {h.inside.map((f) => (
                <div key={f.title} className="feature">
                  <span className="feature-icon" aria-hidden="true">{f.icon}</span>
                  <h3>{f.title}</h3>
                  <p>{f.text}</p>
                </div>
              ))}
            </div>
          </div>
        </section>

        <div className="divider" />

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
                { label: 'Next.js', raw: NEXT, code: NEXT },
              ]}
            />
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
