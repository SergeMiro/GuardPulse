import type { ReactNode } from 'react';

export const metadata = { title: 'ShieldTrail + Next.js' };

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body style={{ fontFamily: 'system-ui, sans-serif', maxWidth: 720, margin: '40px auto', padding: '0 16px' }}>
        <nav style={{ display: 'flex', gap: 16, marginBottom: 24 }}>
          <a href="/">Home</a>
          <a href="/support">Support ticket</a>
          <a href="/refund">Refund</a>
        </nav>
        {children}
        {/* ShieldTrail dev panel: development only */}
        {process.env.NODE_ENV === 'development' && <script src="http://127.0.0.1:4320/panel.js" async />}
      </body>
    </html>
  );
}
