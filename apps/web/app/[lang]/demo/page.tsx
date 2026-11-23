import type { Metadata } from 'next';
import { Footer, Nav } from '../../components/Nav';
import { dicts, type Lang } from '../../i18n';
import { DemoClient } from './DemoClient';

export async function generateMetadata({ params }: { params: Promise<{ lang: Lang }> }): Promise<Metadata> {
  const { lang } = await params;
  return { title: `${dicts[lang].nav.demo} — ShieldTrail` };
}

export default async function DemoPage({ params }: { params: Promise<{ lang: Lang }> }) {
  const { lang } = await params;
  const t = dicts[lang];
  return (
    <>
      <Nav lang={lang} t={t} page="demo" />
      <main id="main" className="container">
        <div className="page-head">
          <div className="eyebrow">{t.demo.eyebrow}</div>
          <h1>
            {t.demo.title} <span className="grad">{t.demo.titleGrad}</span>
          </h1>
          <p className="lead">{t.demo.lead}</p>
        </div>
        <DemoClient lang={lang} />
      </main>
      <Footer lang={lang} t={t} />
    </>
  );
}
