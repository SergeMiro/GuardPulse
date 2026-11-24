'use client';
import { useState } from 'react';

export default function Refund() {
  const [status, setStatus] = useState('');
  async function refund() {
    setStatus('Waiting for approval in the ShieldTrail panel…');
    const res = await fetch('/api/refund', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ order: 77, amount: 40 }) });
    const body = await res.json();
    setStatus(res.ok ? `Refund done: ${body.id}` : `Refund refused: ${body.error}`);
  }
  return (
    <main>
      <h1>Refund order 77</h1>
      <button type="button" onClick={refund}>Refund 40 EUR</button>
      <p id="status">{status}</p>
    </main>
  );
}
