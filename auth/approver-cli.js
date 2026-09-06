import { setTimeout as delay } from 'node:timers/promises';
import { OWNER_OPERATIONS } from './inbox.js';

export async function runApproverCommand(remote, command, values, { output = value => console.log(JSON.stringify(value)), bell = () => process.stderr.write('\x07'), signal, sleep = delay } = {}) {
  if (remote.role !== 'approver') throw new Error('Approval commands require an approver identity');
  const call = (operation, args = {}) => {
    if (!OWNER_OPERATIONS.has(operation)) throw new Error('Approval operation unavailable');
    return remote.call(operation, args, { signal });
  };
  if (command === 'requests') return output(await call('requests', { cursor: values.cursor }));
  if (command === 'decide') {
    if (!values.request || !['once', 'always', 'deny'].includes(values.decision)) throw new Error('Provide a request and decision');
    return output(await call('request.decide', { requestId: values.request, decision: values.decision, ...(values.factors ? { factors: values.factors.split(',') } : {}) }));
  }
  if (command !== 'approvals' || !values.watch) throw new Error('Unknown approval command');
  const interval = values.interval === undefined ? 15 : Number(values.interval);
  if (!Number.isFinite(interval) || interval < 5 || interval > 3600) throw new Error('Watch interval must be between 5 and 3600 seconds');
  const seen = new Set();
  while (!signal?.aborted) {
    let cursor = null;
    do {
      const page = await call('requests', { cursor });
      if (!Array.isArray(page?.items)) break;
      let reachedRecovery = false;
      for (const row of page.items) {
        if (row.status !== 'pending') { reachedRecovery = true; break; }
        const requestId = row.requestId || row.id;
        if (row.status !== 'pending' || seen.has(requestId)) continue;
        seen.add(requestId);
        if (seen.size > 10000) seen.delete(seen.values().next().value);
        output({ event: 'pending', requestId, name: row.name || row.serviceId, origin: row.origin, requesterId: row.requesterId, expiresAt: row.expiresAt });
        bell();
      }
      cursor = !reachedRecovery && page.hasMore ? page.nextCursor : null;
    } while (cursor && !signal?.aborted);
    try { await sleep(interval * 1000, undefined, { signal }); } catch (error) { if (error.name !== 'AbortError') throw error; }
  }
}
