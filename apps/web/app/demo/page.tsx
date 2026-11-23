import type { Metadata } from 'next';
import { Footer, Nav } from '../components/Nav';
import { DemoClient } from './DemoClient';

export const metadata: Metadata = { title: 'Live demo — ShieldTrail' };

export default function DemoPage() {
  return (
    <>
      <Nav current="demo" />
      <main id="main" className="container">
        <div className="page-head">
          <div className="eyebrow">Live demo · runs in your browser</div>
          <h1>
            One agent. One poisoned PDF. <span className="grad">Three outcomes.</span>
          </h1>
          <p className="lead">
            A support bot answers ticket #4521. The invoice attached to it hides instructions: dump the customers table, send it to an
            attacker. Run it without ShieldTrail, in shadow mode, and in enforce mode. This is the real SDK, not a recording.
          </p>
        </div>
        <DemoClient />
      </main>
      <Footer />
    </>
  );
}
