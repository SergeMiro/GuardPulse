import { answerTicket } from '../../lib/agent';

export const dynamic = 'force-dynamic';

export default async function Support() {
  const result = await answerTicket();
  return (
    <main>
      <h1>Ticket #4521</h1>
      <ol>
        {result.steps.map((s) => (
          <li key={s}>{s}</li>
        ))}
      </ol>
      {result.blocked ? <p id="verdict">Blocked by ShieldTrail: {result.blocked}</p> : <p id="verdict">Done.</p>}
      <p>Click the shield in the corner to see the whole chain.</p>
    </main>
  );
}
