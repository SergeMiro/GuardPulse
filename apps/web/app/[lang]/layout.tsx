import type { Metadata, Viewport } from 'next';
import { Inter, JetBrains_Mono } from 'next/font/google';
import { notFound } from 'next/navigation';
import { THEME_SCRIPT } from '../components/ThemeToggle';
import { dicts, isLang, LANGS } from '../i18n';
import '../globals.css';

const sans = Inter({ subsets: ['latin'], variable: '--font-sans' });
const mono = JetBrains_Mono({ subsets: ['latin'], variable: '--font-mono', weight: ['400', '500', '700'] });

export const dynamicParams = false;
export const generateStaticParams = () => LANGS.map((lang) => ({ lang }));
export const viewport: Viewport = { themeColor: [{ media: '(prefers-color-scheme: dark)', color: '#07070d' }, { media: '(prefers-color-scheme: light)', color: '#f7f7fb' }] };

export async function generateMetadata({ params }: { params: Promise<{ lang: string }> }): Promise<Metadata> {
  const { lang } = await params;
  const t = dicts[isLang(lang) ? lang : 'en'];
  return { title: t.meta.title, description: t.meta.description };
}

export default async function LangLayout({ children, params }: { children: React.ReactNode; params: Promise<{ lang: string }> }) {
  const { lang } = await params;
  if (!isLang(lang)) notFound();
  return (
    <html lang={lang} className={`${sans.variable} ${mono.variable}`} suppressHydrationWarning>
      <body>
        {/* first thing in <body>: applies a saved theme before paint; in <head> it raced hydration */}
        <script dangerouslySetInnerHTML={{ __html: THEME_SCRIPT }} suppressHydrationWarning />
        <a className="skip" href="#main">{dicts[lang].skip}</a>
        {children}
      </body>
    </html>
  );
}
