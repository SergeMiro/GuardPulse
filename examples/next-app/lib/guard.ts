import { createGuard } from 'shieldtrail/node';

// Rules live in shieldtrail.policy.json. In `next dev` this also starts the dev panel on
// http://127.0.0.1:4320; in production it does not.
export const guard = createGuard({
  // real secrets: allowed only towards their own domain, never stored
  secrets: [{ name: 'CRM_TOKEN', value: process.env.CRM_TOKEN ?? 'crm-demo-token-41b7c2', domains: ['localhost'] }],
  budget: { maxToolCalls: 20 },
});
