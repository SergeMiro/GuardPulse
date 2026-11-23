import Link from 'next/link';
import { type Dict, type Lang, LANGS, REPO } from '../i18n';
import { LogoMark } from './Logo';
import { ThemeToggle } from './ThemeToggle';

export type Page = 'home' | 'start' | 'demo' | 'dashboard';
const path = (lang: Lang, page: Page) => `/${lang}/${page === 'home' ? '' : `${page}/`}`;

export function Nav({ lang, t, page }: { lang: Lang; t: Dict; page: Page }) {
  const cur = (p: Page) => (p === page ? 'page' : undefined);
  return (
    <header className="nav">
      <nav className="container nav-inner" aria-label={t.nav.menu}>
        <Link href={path(lang, 'home')} className="logo" aria-label="ShieldTrail">
          <LogoMark />
          <span>Shield<b>Trail</b></span>
        </Link>
        <div className="nav-links">
          <Link href={`${path(lang, 'home')}#how`}>{t.nav.how}</Link>
          <Link href={path(lang, 'start')} aria-current={cur('start')}>{t.nav.start}</Link>
          <Link href={path(lang, 'demo')} aria-current={cur('demo')}>{t.nav.demo}</Link>
          <Link href={path(lang, 'dashboard')} aria-current={cur('dashboard')}>{t.nav.dashboard}</Link>
          <a href={REPO}>{t.nav.github}</a>
        </div>
        <div className="nav-right">
          <div className="lang" role="group" aria-label={t.nav.lang}>
            {LANGS.map((l) => (
              <Link key={l} href={path(l, page)} aria-current={l === lang ? 'true' : undefined} hrefLang={l} lang={l}>
                {l.toUpperCase()}
              </Link>
            ))}
          </div>
          <ThemeToggle toLight={t.nav.toLight} toDark={t.nav.toDark} />
          <Link className="btn btn-primary btn-sm cta-nav" href={path(lang, 'demo')}>{t.nav.cta}</Link>
        </div>
      </nav>
    </header>
  );
}

export function Footer({ lang, t }: { lang: Lang; t: Dict }) {
  return (
    <footer>
      <div className="container foot">
        <div className="logo" style={{ fontSize: 15 }}>
          <LogoMark size={20} />
          <span>Shield<b>Trail</b></span>
          <span style={{ color: 'var(--dim)', fontWeight: 400, fontFamily: 'var(--sans)', fontSize: 13, marginLeft: 6 }}>{t.footer.tag}</span>
        </div>
        <nav aria-label="Footer">
          <Link href={path(lang, 'start')}>{t.nav.start}</Link>
          <Link href={path(lang, 'demo')}>{t.nav.demo}</Link>
          <Link href={path(lang, 'dashboard')}>{t.nav.dashboard}</Link>
          <a href={`${REPO}/blob/main/docs/PLAN.md`}>{t.footer.roadmap}</a>
          <a href={REPO}>GitHub</a>
        </nav>
      </div>
    </footer>
  );
}
