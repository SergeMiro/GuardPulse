import type { Metadata, Viewport } from 'next';
import { Inter, JetBrains_Mono } from 'next/font/google';
import './globals.css';

const sans = Inter({ subsets: ['latin'], variable: '--font-sans' });
const mono = JetBrains_Mono({ subsets: ['latin'], variable: '--font-mono', weight: ['400', '500', '700'] });

export const metadata: Metadata = {
  title: 'GuardPulse — attack chain intelligence for AI agents',
  description:
    'Open-source TypeScript SDK that correlates prompt injection, MCP tool calls and outbound requests into one attack graph, and blocks the dangerous step — shadow mode first.',
  icons: { icon: `${process.env.PAGES_BASE_PATH ?? ''}/favicon.svg` },
};

export const viewport: Viewport = { themeColor: '#07070d' };

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={`${sans.variable} ${mono.variable}`}>
      <body>
        <a className="skip" href="#main">Skip to main content</a>
        {children}
      </body>
    </html>
  );
}
