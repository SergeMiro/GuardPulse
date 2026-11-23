import Link from 'next/link';
import { LogoMark } from './Logo';

export const REPO = 'https://github.com/SergeMiro/GuardPulse';

export function Nav({ current }: { current?: 'demo' | 'dashboard' }) {
  return (
    <header className="nav">
      <nav className="container nav-inner" aria-label="Main navigation">
        <Link href="/" className="logo" aria-label="GuardPulse home">
          <LogoMark />
          <span>Guard<b>Pulse</b></span>
        </Link>
        <div className="nav-links">
          <Link href="/#chain">How it works</Link>
          <Link href="/#autopilot">Shadow mode</Link>
          <Link href="/demo/" aria-current={current === 'demo' ? 'page' : undefined}>Live demo</Link>
          <Link href="/dashboard/" aria-current={current === 'dashboard' ? 'page' : undefined}>Dashboard</Link>
          <a href={`${REPO}#readme`}>Docs</a>
        </div>
        <div className="nav-right">
          <a className="btn btn-ghost btn-sm gh" href={REPO} aria-label="GuardPulse on GitHub">
            <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27s1.36.09 2 .27c1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0 0 16 8c0-4.42-3.58-8-8-8" /></svg>
            GitHub
          </a>
          <Link className="btn btn-primary btn-sm" href="/demo/">Try the live demo</Link>
        </div>
      </nav>
    </header>
  );
}

export function Footer() {
  return (
    <footer>
      <div className="container foot">
        <div className="logo" style={{ fontSize: 15 }}>
          <LogoMark size={20} />
          <span>Guard<b>Pulse</b></span>
          <span style={{ color: 'var(--dim)', fontWeight: 400, fontFamily: 'var(--sans)', fontSize: 13, marginLeft: 8 }}>MIT · open source</span>
        </div>
        <nav aria-label="Footer navigation">
          <Link href="/demo/">Live demo</Link>
          <Link href="/dashboard/">Dashboard</Link>
          <a href={`${REPO}#readme`}>Docs</a>
          <a href={`${REPO}/blob/main/docs/PLAN.md`}>Roadmap</a>
          <a href={REPO}>GitHub</a>
        </nav>
      </div>
    </footer>
  );
}
