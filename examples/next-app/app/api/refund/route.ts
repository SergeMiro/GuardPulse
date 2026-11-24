import { GuardBlockedError } from 'shieldtrail';
import { guard } from '../../../lib/guard';

export async function POST(req: Request) {
  const { order, amount } = await req.json();
  const trace = guard.startTrace({ agent: 'billing-bot', task: `Refund order ${order}` });
  try {
    // rule refund-needs-human (action "ask") holds this call until someone approves it
    const id = await trace.tool('payments.refund', { order, amount }, () => `re_${order}_${amount}`);
    return Response.json({ id });
  } catch (err) {
    if (err instanceof GuardBlockedError) return Response.json({ error: err.decision.reason }, { status: 403 });
    throw err;
  }
}
