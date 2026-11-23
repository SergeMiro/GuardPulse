import type { Metadata } from 'next';
import { Footer, Nav } from '../../components/Nav';
import { dicts, type Lang } from '../../i18n';
import { DashboardClient } from './DashboardClient';

export async function generateMetadata({ params }: { params: Promise<{ lang: Lang }> }): Promise<Metadata> {
  const { lang } = await params;
  return { title: `${dicts[lang].nav.dashboard} — ShieldTrail` };
}

export default async function DashboardPage({ params }: { params: Promise<{ lang: Lang }> }) {
  const { lang } = await params;
  const t = dicts[lang];
  return (
    <>
      <Nav lang={lang} t={t} page="dashboard" />
      <main id="main" className="container">
        <div className="page-head">
          <div className="eyebrow">{t.dash.eyebrow}</div>
          <h1>{t.dash.title}</h1>
          <p className="lead">{t.dash.lead}</p>
        </div>
        <DashboardClient lang={lang} />
      </main>
      <Footer lang={lang} t={t} />
    </>
  );
}
