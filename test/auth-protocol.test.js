import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { createIdentity, publicIdentity, sealMessage, openMessage, newId, channelCredentials, messageName } from '../auth/protocol.js';
import { createEncryptedStore } from '../auth/store.js';
import { createRelayCaller, createRelayExecutor } from '../auth/relay.js';
import { startRelay } from '../server/server.js';
import { relayPush, relayGet } from '../companion/relay-client.js';

test('authentication envelopes bind sender, recipient, purpose and deadline without plaintext', () => {
  const sender = createIdentity('approver'), receiver = createIdentity('executor'), stranger = createIdentity('agent');
  const time = Date.now();
  const blob = sealMessage({ operation: 'request.decide', value: 'synthetic-secret-only' }, sender, publicIdentity(receiver), { now: time });
  assert.ok(!blob.includes('synthetic-secret-only'));
  assert.equal(openMessage(blob, receiver, publicIdentity(sender), { now: time }).value.operation, 'request.decide');
  assert.throws(() => openMessage(blob, stranger, publicIdentity(sender), { now: time }));
  assert.throws(() => openMessage(blob, receiver, publicIdentity(stranger), { now: time }));
  assert.throws(() => openMessage(blob, receiver, publicIdentity(sender), { now: time + 120001 }));
  const changed = JSON.parse(blob); changed.signature = changed.signature.slice(0, -6) + 'AAAAAA';
  assert.throws(() => openMessage(Buffer.from(JSON.stringify(changed)), receiver, publicIdentity(sender), { now: time }));
});

test('actual opaque relay delivers an authenticated command once across retry and executor restart', async t => {
  const home = await fs.mkdtemp(path.join(os.tmpdir(), 'cs-auth-relay-'));
  let executor, relay, timer;
  const polls = new Set();
  t.after(async () => {
    clearInterval(timer);
    await Promise.allSettled([...polls]);
    await executor?.drain();
    await relay?.close();
    await fs.rm(home, { recursive: true, force: true });
  });
  const keys = channelCredentials();
  relay = await startRelay({ host: '127.0.0.1', port: 0, dataDir: path.join(home, 'relay'), allowedRooms: [keys.roomId], rateIpCapacity: 1000, rateIpRefillPerSec: 1000, rateRoomCapacity: 1000, rateRoomRefillPerSec: 1000, log: () => {} });
  const executorIdentity = createIdentity('executor'), agent = createIdentity('agent');
  const channel = { ...keys, relayUrl: relay.url };
  const executorPeer = { identity: publicIdentity(executorIdentity), enabled: true, channel };
  const agentPeer = { identity: publicIdentity(agent), enabled: true, channel };
  const store = createEncryptedStore({ path: path.join(home, 'state.enc'), key: crypto.randomBytes(32) });
  let executions = 0;
  const options = { identity: executorIdentity, getPeers: () => [agentPeer], store, dispatch: async (operation, args, identity) => {
    assert.equal(operation, 'test.operation'); assert.equal(identity.role, 'agent'); executions++;
    return { status: 'ok', counter: executions, argument: args.publicValue };
  } };
  executor = createRelayExecutor(options);
  const id = newId();
  const blob = sealMessage({ type: 'command', operation: 'test.operation', args: { publicValue: 'example' } }, agent, publicIdentity(executorIdentity), { id });
  const submit = () => relayPush({ ...channel, name: messageName('request', id), blob });
  await submit(); await executor.poll(); await executor.drain();
  assert.equal(executions, 1);
  executor = createRelayExecutor(options);
  await submit(); await executor.poll(); await executor.drain();
  assert.equal(executions, 1, 'replayed command must return committed response');
  const result = openMessage(await relayGet({ ...channel, name: messageName('response', id) }), agent, publicIdentity(executorIdentity)).value;
  assert.equal(result.replyTo, id); assert.equal(result.result.counter, 1);

  const caller = createRelayCaller({ identity: agent, peer: executorPeer });
  timer = setInterval(() => {
    const polling = executor.poll().catch(() => {}).finally(() => polls.delete(polling));
    polls.add(polling);
  }, 25);
  const response = await caller.call('test.operation', { publicValue: 'second' }, { timeoutMs: 10000 });
  assert.equal(response.argument, 'second'); assert.equal(executions, 2);
  const disk = await fs.readFile(path.join(home, 'state.enc'), 'utf8');
  assert.ok(!disk.includes('test.operation')); assert.ok(!disk.includes('second'));
});

test('relay command dispatch remains concurrent so cancellation can reach an active command', async () => {
  const executorIdentity = createIdentity('executor'), agent = createIdentity('agent');
  const peer = { identity: publicIdentity(agent), enabled: true, channel: channelCredentials() };
  const blobs = new Map(); const journal = { version: 1, enrollments: [], requests: [], policies: [], audit: [] };
  const io = { list: async () => [...blobs.keys()].map(name => ({ name })), get: async ({ name }) => blobs.get(name), push: async ({ name, blob }) => { blobs.set(name, blob); }, delete: async ({ name }) => { blobs.delete(name); } };
  let release, started; const begin = new Promise(resolve => { started = resolve; });
  const executor = createRelayExecutor({ identity: executorIdentity, getPeers: () => [peer], io,
    store: { mutate: async fn => fn(journal) }, dispatch: async operation => {
      if (operation === 'hold') { started(); await new Promise(resolve => { release = resolve; }); return { status: 'done' }; }
      release(); return { status: 'cancelled' };
    } });
  for (const operation of ['hold', 'cancel']) { const id = newId(); blobs.set(messageName('request', id), sealMessage({ type: 'command', operation, args: {} }, agent, publicIdentity(executorIdentity), { id })); }
  await executor.poll(); await begin; await executor.drain();
  assert.equal(Object.values(journal.transport).filter(item => item.status === 'done').length, 2);
});
