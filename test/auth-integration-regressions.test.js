import test from 'node:test';
import assert from 'node:assert/strict';
import { createIdentity, publicIdentity, channelCredentials, messageName, newId, openMessage, sealMessage } from '../auth/protocol.js';
import { createRelayCaller, createRelayExecutor } from '../auth/relay.js';

// Synthetic transport only: real signed/encrypted envelopes and the production
// relay state machine, with no external server or real 1Password credentials.
function transportFixture(role = 'agent') {
  const executorIdentity = createIdentity('executor');
  const agent = createIdentity(role);
  const channel = channelCredentials();
  const peer = { identity: publicIdentity(agent), enabled: true, channel };
  const executorPeer = { identity: publicIdentity(executorIdentity), enabled: true, channel };
  const blobs = new Map();
  const reads = [];
  const state = { version: 1, enrollments: [], requests: [], policies: [], audit: [] };
  let time = 1_000_000;
  const now = () => time;
  const advance = (milliseconds) => { time += milliseconds; };
  const io = {
    list: async () => [...blobs.keys()].map((name) => ({ name, mtime: now() })),
    get: async ({ name }) => {
      reads.push(name);
      if (!blobs.has(name)) throw Object.assign(new Error('Missing synthetic blob'), { status: 404 });
      return blobs.get(name);
    },
    push: async ({ name, blob }) => { blobs.set(name, blob); },
    delete: async ({ name }) => { blobs.delete(name); },
  };
  const store = {
    read: async () => structuredClone(state),
    mutate: async (operation) => structuredClone(operation(state)),
  };
  const enqueue = (operation, args = {}, id = newId()) => {
    const name = messageName('request', id);
    const blob = sealMessage({ type: 'command', operation, args }, agent, publicIdentity(executorIdentity), { id, now: now() });
    blobs.set(name, blob);
    return { id, name, blob };
  };
  const reply = (id) => openMessage(blobs.get(messageName('response', id)), agent, publicIdentity(executorIdentity), { now: now() }).value;
  return { executorIdentity, agent, channel, peer, executorPeer, blobs, reads, state, now, advance, io, store, enqueue, reply };
}

test('accepted PUT with lost acknowledgement retries one identical command and retrieves its original result', async () => {
  const f = transportFixture();
  const uploads = [];
  const executions = new Set();
  const io = { ...f.io, push: async ({ name, blob }) => {
    uploads.push({ name, blob: blob.toString('base64') });
    const command = openMessage(blob, f.executorIdentity, publicIdentity(f.agent), { now: f.now() });
    executions.add(command.header.id);
    f.blobs.set(messageName('response', command.header.id), sealMessage({
      type: 'response', replyTo: command.header.id, ok: true, result: { status: 'succeeded' },
    }, f.executorIdentity, publicIdentity(f.agent), { now: f.now() }));
    throw new Error('Synthetic response lost after server commit');
  } };
  const caller = createRelayCaller({ identity: f.agent, peer: f.executorPeer, io, now: f.now, sleep: async (milliseconds) => f.advance(milliseconds) });
  assert.deepEqual(await caller.call('browser.click', { sessionId: 'synthetic', handle: 'button' }, { timeoutMs: 3000 }), { status: 'succeeded' });
  assert.equal(uploads.length, 2);
  assert.deepEqual(uploads[0], uploads[1]);
  assert.equal(executions.size, 1);
});

test('lost command acknowledgement and unavailable response produce an uncertain outcome bound to the submitted ID', async () => {
  const f = transportFixture();
  const submitted = [];
  const io = {
    ...f.io,
    push: async ({ blob }) => {
      submitted.push(openMessage(blob, f.executorIdentity, publicIdentity(f.agent), { now: f.now() }).header.id);
      throw new Error('Synthetic ambiguous upload');
    },
    get: async () => { throw new Error('Synthetic network unavailable'); },
  };
  const caller = createRelayCaller({ identity: f.agent, peer: f.executorPeer, io, now: f.now, sleep: async (milliseconds) => f.advance(milliseconds) });
  const result = await caller.call('browser.click', {}, { timeoutMs: 3000 });
  assert.equal(result.status, 'uncertain');
  assert.equal(result.commandId, submitted[0]);
  assert.equal(new Set(submitted).size, 1);
});

test('aborting during ambiguous upload backoff preserves the command ID instead of reporting a definite failure', async () => {
  const f = transportFixture();
  let submitted;
  const aborter = new AbortController();
  const io = { ...f.io, push: async ({ blob }) => {
    submitted = openMessage(blob, f.executorIdentity, publicIdentity(f.agent), { now: f.now() }).header.id;
    throw new Error('Synthetic connection lost after upload');
  } };
  const caller = createRelayCaller({ identity: f.agent, peer: f.executorPeer, io, now: f.now, sleep: async () => {
    aborter.abort();
    throw Object.assign(new Error('Synthetic cancelled wait'), { name: 'AbortError' });
  } });
  const result = await caller.call('browser.click', {}, { timeoutMs: 3000, signal: aborter.signal });
  assert.equal(result.status, 'uncertain');
  assert.equal(result.commandId, submitted);
});

test('executor skips its own durable response blobs on subsequent polls and deletes them after expiry', async () => {
  const f = transportFixture();
  const executor = createRelayExecutor({ identity: f.executorIdentity, getPeers: () => [f.peer], store: f.store, io: f.io, now: f.now,
    dispatch: async () => ({ status: 'succeeded' }) });
  const command = f.enqueue('browser.click');
  await executor.poll(); await executor.drain();
  const responseName = messageName('response', command.id);
  assert.equal(f.reply(command.id).result.status, 'succeeded');
  f.reads.length = 0;
  for (let index = 0; index < 10; index++) { f.advance(5000); await executor.poll(); }
  assert.equal(f.reads.includes(responseName), false);
  assert.equal(f.blobs.has(responseName), true);
  f.advance(120_001);
  await executor.poll();
  assert.equal(f.blobs.has(responseName), false);
  assert.equal(f.reads.includes(responseName), false);
});

test('read-only responses keep small durable replay markers and recheck live peer authorization on retry', async () => {
  const f = transportFixture();
  let calls = 0;
  const executor = createRelayExecutor({ identity: f.executorIdentity, getPeers: () => [f.peer], store: f.store, io: f.io, now: f.now,
    isReadOnly: (operation) => operation === 'takeover.observe',
    dispatch: async () => ({ status: 'ready', observation: ++calls, image: 'synthetic-pixel'.repeat(6000) }) });
  const command = f.enqueue('takeover.observe');
  await executor.poll(); await executor.drain();
  assert.equal(f.reply(command.id).result.observation, 1);
  assert.ok(JSON.stringify(f.state.transport).length < 1000);
  f.blobs.set(command.name, command.blob);
  await executor.poll(); await executor.drain();
  assert.equal(f.reply(command.id).result.observation, 2);
  f.peer.enabled = false;
  f.blobs.set(command.name, command.blob);
  await executor.poll(); await executor.drain();
  assert.equal(calls, 2);
});

test('journal pressure rejects new mutations explicitly and the same rejected ID never executes after capacity returns', async () => {
  const f = transportFixture();
  f.state.transport = Object.fromEntries(Array.from({ length: 80 }, () => [`${f.agent.id}:${newId()}`, {
    status: 'done', expiresAt: f.now() + 120000, response: 'synthetic'.repeat(1000),
  }]));
  let calls = 0;
  const executor = createRelayExecutor({ identity: f.executorIdentity, getPeers: () => [f.peer], store: f.store, io: f.io, now: f.now,
    dispatch: async () => { calls++; return { status: 'succeeded' }; } });
  const command = f.enqueue('browser.click');
  await executor.poll(); await executor.drain();
  assert.equal(f.reply(command.id).result.reason, 'storage-capacity');
  assert.equal(f.reply(command.id).result.status, 'failed');
  assert.equal(calls, 0);
  const key = `${f.agent.id}:${command.id}`;
  assert.equal(f.state.transport[key].status, 'rejected');
  f.state.transport = { [key]: f.state.transport[key] };
  f.blobs.set(command.name, command.blob);
  await executor.poll(); await executor.drain();
  assert.equal(f.reply(command.id).result.reason, 'storage-capacity');
  assert.equal(calls, 0);
});

test('owner reads and denial retain reserved access when the normal journal is saturated', async () => {
  const f = transportFixture('approver');
  f.state.transport = Object.fromEntries(Array.from({ length: 2000 }, () => [`${f.agent.id}:${newId()}`, { status: 'rejected', expiresAt: f.now() + 120000 }]));
  const calls = [];
  const executor = createRelayExecutor({ identity: f.executorIdentity, getPeers: () => [f.peer], store: f.store, io: f.io, now: f.now,
    isReadOnly: (operation) => operation === 'requests', dispatch: async (operation) => {
      calls.push(operation);
      return operation === 'requests' ? { items: [], nextCursor: null, hasMore: false } : { status: 'denied' };
    } });
  const read = f.enqueue('requests');
  await executor.poll(); await executor.drain();
  assert.deepEqual(f.reply(read.id).result.items, []);
  assert.equal(Object.keys(f.state.transport).length, 2000, 'saturated reads need no durable mutation marker');
  f.reads.length = 0;
  await executor.poll();
  assert.equal(f.reads.includes(messageName('response', read.id)), false);
  const deny = f.enqueue('request.decide', { requestId: 'pending-request', decision: 'deny' });
  await executor.poll(); await executor.drain();
  assert.equal(f.reply(deny.id).result.status, 'denied');
  assert.deepEqual(calls, ['requests', 'request.decide']);
  assert.equal(Object.keys(f.state.transport).length, 2001);
});

test('oversized mutation results commit a bounded uncertain response without repeating the mutation on retry', async () => {
  const f = transportFixture();
  let calls = 0;
  const options = { identity: f.executorIdentity, getPeers: () => [f.peer], store: f.store, io: f.io, now: f.now,
    dispatch: async () => { calls++; return { status: 'changed', diagnostic: 'synthetic'.repeat(10000) }; } };
  let executor = createRelayExecutor(options);
  const command = f.enqueue('synthetic.mutation');
  await executor.poll(); await executor.drain();
  assert.equal(f.reply(command.id).result.status, 'uncertain');
  assert.equal(f.reply(command.id).result.reason, 'response-capacity');
  assert.ok(f.state.transport[`${f.agent.id}:${command.id}`].response.length < 8 * 1024);
  executor = createRelayExecutor(options);
  f.blobs.set(command.name, command.blob);
  await executor.poll(); await executor.drain();
  assert.equal(calls, 1);
  assert.equal(f.reply(command.id).result.reason, 'response-capacity');
});
