import type { Metadata } from 'next';
import { THEME_SCRIPT } from '../components/ThemeToggle';
import '../globals.css';

export const metadata: Metadata = { title: 'ShieldTrail' };

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body>
        <script dangerouslySetInnerHTML={{ __html: THEME_SCRIPT }} suppressHydrationWarning />
        {children}
      </body>
    </html>
  );
}
