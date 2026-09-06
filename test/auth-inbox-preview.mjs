// Synthetic UI preview only. It cannot reach a provider or approve a real request.
import { startApprovalInbox } from '../auth/inbox.js';
const requests = [{ requestId: 'synthetic-request', serviceId: 'acme-work', name: 'Acme workspace', accountId: 'Work account', requesterId: 'research-agent', origin: 'https://accounts.example.com', purpose: 'reauthentication', factors: ['password', 'totp'], status: 'pending' }];
const policies = [];
const inbox = await startApprovalInbox({ call: async (operation, args) => {
  if (operation === 'requests') return { items: requests, nextCursor: null, hasMore: false };
  if (operation === 'policies') return { items: policies, nextCursor: null, hasMore: false };
  if (operation === 'enrollments') return { items: [], nextCursor: null, hasMore: false };
  if (operation === 'peers') return [{ id: 'synthetic-agent', role: 'agent', enabled: true }];
  if (operation === 'request.decide') { requests.splice(0); return { status: args.decision === 'deny' ? 'denied' : 'succeeded' }; }
  if (operation === 'provider.put') return { status: 'configured' };
  return { status: 'saved' };
} });
console.log(JSON.stringify({ url: inbox.url, synthetic: true }));
const stop = async () => { await inbox.close(); process.exit(0); };
process.once('SIGINT', stop); process.once('SIGTERM', stop);
