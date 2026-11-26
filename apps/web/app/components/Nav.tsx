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
          <a className="icon-btn" href={REPO} aria-label={t.nav.github}>
            <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
              <path d="M12 2a10 10 0 0 0-3.16 19.49c.5.09.68-.22.68-.48v-1.7c-2.78.6-3.37-1.34-3.37-1.34-.45-1.16-1.11-1.47-1.11-1.47-.91-.62.07-.6.07-.6 1 .07 1.53 1.03 1.53 1.03.9 1.53 2.35 1.09 2.92.83.09-.65.35-1.09.64-1.34-2.22-.25-4.56-1.11-4.56-4.94 0-1.09.39-1.98 1.03-2.68-.1-.25-.45-1.27.1-2.65 0 0 .84-.27 2.75 1.02a9.5 9.5 0 0 1 5 0c1.91-1.29 2.75-1.02 2.75-1.02.55 1.38.2 2.4.1 2.65.64.7 1.03 1.59 1.03 2.68 0 3.84-2.34 4.69-4.57 4.93.36.31.68.92.68 1.85v2.75c0 .27.18.58.69.48A10 10 0 0 0 12 2Z" />
            </svg>
          </a>
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
        <div className="foot-brand">
          <LogoMark size={22} />
          <span>ShieldTrail · {t.footer.tag}</span>
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
