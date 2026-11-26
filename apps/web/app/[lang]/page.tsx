import Link from 'next/link';
import { AttackConsole } from '../components/AttackConsole';
import { CodeTabs } from '../components/CodeTabs';
import { Footer, Nav } from '../components/Nav';
import { dicts, type Lang } from '../i18n';

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

const ICON = { fill: 'none', stroke: 'currentColor', strokeWidth: 1.8, strokeLinecap: 'round', strokeLinejoin: 'round' } as const;

/** One icon per "how it works" card: a trail of linked steps, a target, an eye. */
const HOW_ICONS = [
  <svg key="0" width="22" height="22" viewBox="0 0 24 24" {...ICON} aria-hidden="true"><circle cx="5" cy="18" r="2" /><circle cx="12" cy="7" r="2" /><circle cx="19" cy="15" r="2" /><path d="M6.2 16.3 10.8 8.7M13.6 8.3l4 5.3" /></svg>,
  <svg key="1" width="22" height="22" viewBox="0 0 24 24" {...ICON} aria-hidden="true"><circle cx="12" cy="12" r="8" /><circle cx="12" cy="12" r="3" /><path d="M12 2v3M12 19v3M2 12h3M19 12h3" /></svg>,
  <svg key="2" width="22" height="22" viewBox="0 0 24 24" {...ICON} aria-hidden="true"><path d="M2 12s3.5-6 10-6 10 6 10 6-3.5 6-10 6S2 12 2 12Z" /><circle cx="12" cy="12" r="2.5" /></svg>,
];

/** Panel, person, key, clock, stop, report. */
const FEATURE_ICONS = [
  <svg key="0" width="24" height="24" viewBox="0 0 24 24" {...ICON} aria-hidden="true"><rect x="3" y="4" width="18" height="13" rx="2" /><path d="M8 21h8M12 17v4" /><path d="M15.5 8.5 17 8v2c0 1.2-.7 2-1.5 2.4-.8-.4-1.5-1.2-1.5-2.4V8Z" /></svg>,
  <svg key="1" width="24" height="24" viewBox="0 0 24 24" {...ICON} aria-hidden="true"><circle cx="9" cy="8" r="3.5" /><path d="M2.5 20c0-3.6 2.9-6.5 6.5-6.5s6.5 2.9 6.5 6.5" /><path d="m16 11 2 2 4-4" /></svg>,
  <svg key="2" width="24" height="24" viewBox="0 0 24 24" {...ICON} aria-hidden="true"><circle cx="8" cy="15" r="4.5" /><path d="m11.2 11.8 8.8-8.8M16.5 6.5l2.5 2.5M14 9l2 2" /></svg>,
  <svg key="3" width="24" height="24" viewBox="0 0 24 24" {...ICON} aria-hidden="true"><circle cx="12" cy="13.5" r="7.5" /><path d="M12 9.5v4l2.5 2M9.5 2.5h5" /></svg>,
  <svg key="4" width="24" height="24" viewBox="0 0 24 24" {...ICON} aria-hidden="true"><path d="M8 2.5h8L21.5 8v8L16 21.5H8L2.5 16V8Z" /><rect x="9" y="9" width="6" height="6" rx="1" /></svg>,
  <svg key="5" width="24" height="24" viewBox="0 0 24 24" {...ICON} aria-hidden="true"><path d="M14 2.5H6.5A1.5 1.5 0 0 0 5 4v16a1.5 1.5 0 0 0 1.5 1.5h11A1.5 1.5 0 0 0 19 20V7.5Z" /><path d="M14 2.5v5h5M9 13h6M9 17h6" /></svg>,
];

const ARROW = (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
    <path d="M5 12h14M13 6l6 6-6 6" />
  </svg>
);

export default async function Home({ params }: { params: Promise<{ lang: Lang }> }) {
  const { lang } = await params;
  const t = dicts[lang];
  const h = t.home;
  return (
    <>
      <Nav lang={lang} t={t} page="home" />
      <main id="main" className="home">
        <section className="hero2 grid-bg">
          <div className="container hero2-inner">
            <div className="hero2-copy">
              <div className="badges">
                <span className="badge-hot">{h.pill}</span>
                <span className="badge-mono">{h.pill2}</span>
              </div>
              <h1>
                {h.h1a} <span className="accent">{h.h1grad}</span>
              </h1>
              <p className="lead">{h.lead}</p>
              <div className="cta">
                <Link className="btn btn-primary btn-lg" href={`/${lang}/demo/`}>
                  {h.ctaDemo} {ARROW}
                </Link>
                <Link className="btn btn-ghost btn-lg" href={`/${lang}/start/`}>
                  {h.ctaStart}
                </Link>
              </div>
              <pre className="term2">
                <span><i>$</i> git clone https://github.com/SergeMiro/ShieldTrail.git</span>
                <span><i>$</i> cd ShieldTrail &amp;&amp; npm install</span>
                <span><i>$</i> npm run demo -- --mode enforce</span>
              </pre>
            </div>
            <AttackConsole t={h.console} />
          </div>
        </section>

        <section className="strip" aria-label={h.stackLabel}>
          <div className="container strip-inner">
            <span className="strip-label">{h.stackLabel}</span>
            {h.stack.map((s) => (
              <span key={s}>{s}</span>
            ))}
            <span className="strip-hi">{h.stackZero}</span>
          </div>
        </section>

        <section className="block">
          <div className="container">
            <div className="block-head">
              <div className="eyebrow">{h.problemEyebrow}</div>
              <h2>{h.problemTitle}</h2>
              <p className="sub">{h.problemSub}</p>
            </div>
            <div className="pgrid">
              {h.chain.map((c, i) => (
                <div key={c.title} className={`pcard${i === h.chain.length - 1 ? ' pcard-stop' : ''}`}>
                  <div className="pcard-top">
                    <span>{String(i + 1).padStart(2, '0')}</span>
                    <span className="ptag">{c.tag}</span>
                  </div>
                  <h3>{c.title}</h3>
                  <p>{c.text}</p>
                </div>
              ))}
            </div>
          </div>
        </section>

        <section id="how" className="block band">
          <div className="container">
            <div className="block-head">
              <div className="eyebrow">{h.howEyebrow}</div>
              <h2>{h.howTitle}</h2>
            </div>
            <div className="hgrid">
              {h.how.map((c, i) => (
                <div key={c.title} className="hcard">
                  <span className="hicon">{HOW_ICONS[i]}</span>
                  <h3>{c.title}</h3>
                  <p>{c.text}</p>
                </div>
              ))}
            </div>
          </div>
        </section>

        <section id="inside" className="block">
          <div className="container">
            <div className="block-head">
              <div className="eyebrow">{h.insideEyebrow}</div>
              <h2>{h.insideTitle}</h2>
            </div>
            <div className="features">
              {h.inside.map((f, i) => (
                <div key={f.title} className={`feature${i === 4 ? ' feature-stop' : ''}`}>
                  {FEATURE_ICONS[i]}
                  <h3>{f.title}</h3>
                  <p>{f.text}</p>
                </div>
              ))}
            </div>
          </div>
        </section>

        <section className="block block-tight">
          <div className="container">
            <div className="block-head">
              <div className="eyebrow">{h.compareEyebrow}</div>
              <h2>{h.compareTitle}</h2>
              <p className="sub">{h.compareSub}</p>
            </div>
            <div className="compare-wrap">
              <table className="compare">
                <thead>
                  <tr>
                    <th scope="col" />
                    {h.compareHead.map((c, i) => (
                      <th key={c.name} scope="col" className={i === 2 ? 'us' : undefined}>
                        {c.name}
                        <small>{c.ex}</small>
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {h.compareRows.map(([label, ...cells]) => (
                    <tr key={label}>
                      <th scope="row">{label}</th>
                      {cells.map((c, i) => (
                        <td key={i} className={i === 2 ? 'us' : c === '—' ? 'none' : undefined}>{c}</td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </section>

        <section className="block band">
          <div className="container code2">
            <div className="code2-copy">
              <div className="eyebrow">{h.codeEyebrow}</div>
              <h2>{h.codeTitle}</h2>
              <p className="sub">{h.codeSub}</p>
              <Link className="more" href={`/${lang}/start/`}>
                {h.codeGuide} {ARROW}
              </Link>
            </div>
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

        <section className="final2">
          <div className="container">
            <svg width="56" height="56" viewBox="0 0 40 40" aria-hidden="true">
              <path d="M20 3 34 8.5V19c0 9-6 15.5-14 18-8-2.5-14-9-14-18V8.5Z" fill="var(--pulse-soft)" stroke="var(--pulse)" strokeWidth="2" strokeLinejoin="round" />
              <path d="M12.5 25 17 17.5l5.5 5L27 14" fill="none" stroke="var(--dim)" strokeWidth="1.4" strokeDasharray="2 2.2" strokeLinecap="round" />
              <circle cx="12.5" cy="25" r="2.2" fill="var(--pulse)" />
              <circle cx="17" cy="17.5" r="2.2" fill="var(--pulse)" />
              <circle cx="22.5" cy="22.5" r="2.2" fill="var(--pulse)" />
              <circle cx="27" cy="14" r="2.8" fill="var(--red)" />
            </svg>
            <h2>
              {h.finalTitleA} <span className="accent">{h.finalGrad}</span>
            </h2>
            <p className="sub">{h.finalSub}</p>
            <div className="cta">
              <Link className="btn btn-primary btn-lg" href={`/${lang}/demo/`}>{h.finalDemo}</Link>
              <Link className="btn btn-ghost btn-lg" href={`/${lang}/dashboard/`}>{h.finalDash}</Link>
            </div>
          </div>
        </section>
      </main>
      <Footer lang={lang} t={t} />
    </>
  );
}
