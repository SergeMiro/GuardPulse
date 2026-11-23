import type { Metadata } from 'next';
import { Footer, Nav } from '../components/Nav';
import { DashboardClient } from './DashboardClient';

export const metadata: Metadata = { title: 'Dashboard — GuardPulse' };

export default function DashboardPage() {
  return (
    <>
      <Nav current="dashboard" />
      <main id="main" className="container">
        <div className="page-head">
          <div className="eyebrow">GuardPulse Dashboard</div>
          <h1>Threats, chains, decisions</h1>
          <p className="lead">
            Point it at your collector (<code>npx guardpulse collector</code>) or browse demo traffic generated in your browser.
          </p>
        </div>
        <DashboardClient />
      </main>
      <Footer />
    </>
  );
}
