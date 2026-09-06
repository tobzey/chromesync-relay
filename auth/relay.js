import { readOnly } from './operations.js';
import { setTimeout as delay } from 'node:timers/promises';
import { relayPush, relayList, relayGet, relayDelete } from '../companion/relay-client.js';
import { sealMessage, openMessage, newId, messageName, MESSAGE_TTL } from './protocol.js';
import { compactAuthState, authJournalBytes, AUTH_JOURNAL_ADMISSION_BUDGET, AUTH_CACHED_RESPONSE_LIMIT } from './store.js';

const DEFAULT_IO = { push: relayPush, list: relayList, get: relayGet, delete: relayDelete };
const MAX_JOURNAL = 2000;

// Commands carry encrypted, signed envelopes in independent authentication
// rooms. The relay can delay/delete them but cannot approve or invent commands.
export function createRelayCaller({ identity, peer, io = DEFAULT_IO, now = Date.now, sleep = delay }) {
  if (!peer?.enabled) throw new Error('Authentication peer is disabled');
  return {
    async call(operation, args = {}, { timeoutMs = 90000, signal, discardOnTimeout = readOnly.has(operation) } = {}) {
      if (!Number.isInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > MESSAGE_TTL - 5000) throw new Error('Invalid call timeout');
      const id = newId();
      const started = now();
      const request = sealMessage({ type: 'command', operation, args }, identity, peer.identity, { id, now: started });
      const name = messageName('request', id), responseName = messageName('response', id);
      let capacity = false;
      const uncertain = async () => {
        if (discardOnTimeout) await io.delete({ ...peer.channel, name }).catch(() => {});
        return { status: 'uncertain', reason: capacity ? 'relay-capacity' : 'executor-unavailable-or-response-delayed', commandId: id };
      };
      let pause = 500;
      let networkRetries = 0;
      for (;;) {
        try { await io.push({ ...peer.channel, name, blob: request }); break; }
        catch (error) {
          capacity = error.status === 507;
          if (signal?.aborted || now() - started >= timeoutMs) return uncertain();
          if (error.status && ![429, 503, 507].includes(error.status)) throw error;
          // No response does not prove rejection. Retry the same encrypted
          // command ID once, then look for its possibly committed response.
          if (!error.status && networkRetries++ >= 1) break;
          try { await sleep(pause, undefined, { signal }); } catch { return uncertain(); }
          pause = Math.min(5000, pause * 2);
        }
      }
      try {
        while (now() - started < timeoutMs) {
          if (signal?.aborted) return uncertain();
          try {
            const blob = await io.get({ ...peer.channel, name: responseName, timeoutMs: 5000 });
            const { value } = openMessage(blob, identity, peer.identity, { now: now() });
            if (value.type !== 'response' || value.replyTo !== id) throw new Error('Response binding failed');
            await io.delete({ ...peer.channel, name: responseName }).catch(() => {});
            if (!value.ok) {
              const code = typeof value.code === 'string' && /^[A-Z_]{1,40}$/.test(value.code) ? value.code : 'OPERATION_REJECTED';
              throw Object.assign(new Error(`Authentication operation rejected (${code})`), { code, operationRejected: true });
            }
            return value.result;
          } catch (error) {
            if (error.status === 507) capacity = true;
            if (error.status && ![404, 429, 503, 507].includes(error.status)) throw error;
            if (!error.status && error.operationRejected === true) throw error;
            if (error.status !== 404) pause = Math.min(5000, pause * 2);
          }
          await sleep(pause, undefined, { signal });
          pause = Math.min(5000, pause + 500);
        }
        // Timeout is not cancellation or evidence that a command never ran.
        return uncertain();
      } catch (error) {
        if (error.name === 'AbortError') return uncertain();
        throw error;
      } finally {
        // A still-valid queued request must remain deliverable after client loss.
        // The executor deletes it only after committing a durable response.
      }
    },
  };
}

export function createRelayExecutor({ identity, getPeers, store, dispatch, isReadOnly = () => false, io = DEFAULT_IO, now = Date.now }) {
  let polling = false, rejectedEnvelopes = 0;
  const active = new Set();
  const jobs = new Set();
  const ephemeralResponses = new Map();
  async function processPeer(peer) {
    const snapshot = typeof store.read === 'function' ? await store.read() : {};
    const ownResponses = new Map(Object.entries(snapshot.transport || {}).filter(([key]) => key.startsWith(`${peer.identity.id}:`)).map(([key, row]) => [messageName('response', key.slice(-32)), row]));
    const entries = await io.list(peer.channel);
    for (const entry of entries.slice(0, 100)) {
      if (typeof entry.name !== 'string') continue;
      if (ephemeralResponses.has(entry.name)) {
        if (ephemeralResponses.get(entry.name) <= now()) {
          await io.delete({ ...peer.channel, name: entry.name }).catch(() => {});
          ephemeralResponses.delete(entry.name);
        }
        continue;
      }
      if (ownResponses.has(entry.name)) {
        if (ownResponses.get(entry.name).expiresAt <= now()) await io.delete({ ...peer.channel, name: entry.name }).catch(() => {});
        continue;
      }
      if (Number.isFinite(entry.mtime) && entry.mtime <= now() && entry.mtime < now() - 2 * MESSAGE_TTL) {
        await io.delete({ ...peer.channel, name: entry.name }).catch(() => {});
        continue;
      }
      let opened, blob;
      try { blob = await io.get({ ...peer.channel, name: entry.name }); } catch { continue; }
      try { opened = openMessage(blob, identity, peer.identity, { now: now() }); }
      catch { rejectedEnvelopes++; continue; }
      const { header, value } = opened;
      if (value?.type !== 'command' || entry.name !== messageName('request', header.id)) continue;
      const commandKey = `${peer.identity.id}:${header.id}`;
      if (active.has(commandKey) || active.size >= 64) continue;
      active.add(commandKey);
      const job = executeCommand(peer, entry, opened, commandKey).catch(() => {}).finally(() => { active.delete(commandKey); jobs.delete(job); });
      jobs.add(job);
    }
  }
  async function executeCommand(peer, entry, { header, value }, commandKey) {
      let previous;
      let ephemeralRead = false;
      let rejected = false;
      const readOnly = isReadOnly(value.operation);
      const owner = ['approver', 'executor'].includes(peer.identity.role);
      const cleanup = owner && (['policy.revoke', 'peer.revoke'].includes(value.operation) ||
        (value.operation === 'request.decide' && value.args?.decision === 'deny') ||
        (value.operation === 'takeover.finish' && value.args?.cancel === true));
      await store.mutate(state => {
        compactAuthState(state, now());
        const journal = state.transport ||= {};
        previous = journal[commandKey];
        if (!previous) {
          const count = Object.keys(journal).length;
          const capacity = count >= MAX_JOURNAL - 128 || authJournalBytes(state) >= AUTH_JOURNAL_ADMISSION_BUDGET * (owner ? 1 : 0.5);
          // Reads can be repeated safely after a fresh authorization check.
          // They remain available even while mutation admission is saturated.
          if (capacity && readOnly) { ephemeralRead = true; return; }
          if (count >= MAX_JOURNAL + (cleanup ? 128 : 0)) throw new Error('Authentication queue full');
          rejected = capacity && !cleanup;
          journal[commandKey] = { status: rejected ? 'rejected' : 'executing', expiresAt: header.expiresAt };
        }
        rejected ||= previous?.status === 'rejected';
      });
      try {
        let response = previous?.response;
        if (!response) {
          let outcome;
          if (rejected) outcome = { ok: true, result: { status: 'failed', reason: 'storage-capacity', commandId: header.id } };
          else if (previous && !previous.readOnly) outcome = { ok: true, result: { status: 'uncertain', reason: 'executor-restarted', commandId: header.id } };
          else {
            // Recheck current peer authorization after fetching and reserving.
            try {
              const current = (await getPeers()).find(p => p.enabled && p.identity.id === peer.identity.id);
              if (!current) throw new Error('Peer revoked');
              outcome = { ok: true, result: await dispatch(value.operation, value.args, current.identity) };
            } catch (error) { outcome = { ok: false, code: typeof error?.code === 'string' && /^[A-Z_]{1,40}$/.test(error.code) ? error.code : 'OPERATION_REJECTED' }; }
          }
          const encode = (result) => sealMessage({ type: 'response', replyTo: header.id, ...result }, identity, peer.identity, { now: now() }).toString('base64url');
          const oversized = () => ({ ok: true, result: { status: readOnly ? 'failed' : 'uncertain', reason: 'response-capacity', commandId: header.id } });
          try { response = encode(outcome); } catch { response = encode(oversized()); }
          if (!readOnly && response.length > (cleanup ? 2048 : AUTH_CACHED_RESPONSE_LIMIT)) response = encode(oversized());
          if (!ephemeralRead && !rejected) await store.mutate(state => {
            state.transport[commandKey] = { status: 'done', expiresAt: header.expiresAt, ...(readOnly ? { readOnly: true } : { response }) };
          });
        }
        await io.push({ ...peer.channel, name: messageName('response', header.id), blob: Buffer.from(response, 'base64url') });
        if (ephemeralRead) {
          ephemeralResponses.set(messageName('response', header.id), now() + MESSAGE_TTL);
          if (ephemeralResponses.size > 512) ephemeralResponses.delete(ephemeralResponses.keys().next().value);
        }
        await io.delete({ ...peer.channel, name: entry.name });
      } finally { /* Reservation remains durable if response upload fails. */ }
  }
  return {
    async drain() { await Promise.allSettled([...jobs]); },
    async poll() {
      if (polling) return { status: 'busy' };
      polling = true; rejectedEnvelopes = 0;
      try {
        const peers = (await getPeers()).filter(peer => peer.enabled);
        const results = await Promise.allSettled(peers.map(processPeer));
        return { status: results.some(result => result.status === 'rejected') ? 'delivery-unavailable' : 'ready', rejectedEnvelopes };
      } finally { polling = false; }
    },
  };
}
