'use client';
import Link from 'next/link';
import { useEffect } from 'react';

/** Sends visitors to /fr/ or /en/ depending on their browser language. */
export default function LanguageRedirect() {
  useEffect(() => {
    const fr = (navigator.languages ?? [navigator.language]).some((l) => l?.toLowerCase().startsWith('fr'));
    const base = window.location.pathname.endsWith('/') ? window.location.pathname : `${window.location.pathname}/`;
    window.location.replace(`${base}${fr ? 'fr' : 'en'}/`);
  }, []);
  return (
    <main style={{ display: 'grid', placeItems: 'center', minHeight: '100vh', fontFamily: 'system-ui', gap: 12 }}>
      <p>
        <Link href="/en/">English</Link> · <Link href="/fr/">Français</Link>
      </p>
    </main>
  );
}
