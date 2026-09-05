import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createProfile, createInvite } from '../cli/setup.js';
import { syncProfile } from '../cli/sync.js';
import { terminalMessage } from '../companion/terminal.js';
import { collectTerminalCookies, syncTerminal } from '../src/terminal.js';
import { readJson, profilePaths } from '../cli/config.js';

test('extension source → shared CLI invitation → receiver, including deletion and source isolation', async t => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'chromesync-terminal-test-'));
  t.after(() => fs.rmSync(home, { recursive: true, force: true }));
  const p = await createProfile(home, { name: 'work', role: 'source', source: 'extension', relay: 'https://relay.example.com', domains: 'example.com' });
  const blobs = new Map(), instanceId = 'ab'.repeat(16);
  const deps = { home, push: async ({ name, blob }) => blobs.set(name, blob) };
  const profiles = await terminalMessage({ type: 'terminalProfiles' }, deps);
  assert.deepEqual(profiles, { ok: true, profiles: [{ name: 'work', domains: ['example.com'] }] });
  assert.ok(!JSON.stringify(profiles).includes(p.secret));
  const message = { type: 'terminalPush', name: p.name, instanceId, cookies: [{ name: 'session', value: 'synthetic-terminal-cookie', domain: 'example.com', path: '/', hostOnly: true, secure: true, httpOnly: true, sameSite: 'lax', session: true },
    { name: 'excluded', value: 'synthetic-excluded', domain: 'example.org' }] };
  await assert.rejects(terminalMessage(message, deps), /Connect/);
  await terminalMessage({ ...message, type: 'terminalBind' }, deps);
  await assert.rejects(terminalMessage({ ...message, instanceId: 'cd'.repeat(16), type: 'terminalBind' }, deps), /already connected/);
  const sent = await terminalMessage(message, deps);
  assert.equal(sent.written, 1);
  assert.ok(![...blobs.values()][0].includes(Buffer.from('synthetic-terminal-cookie')));
  const invite = path.join(home, 'invite.json');
  createInvite(p, invite);
  const receiverHome = path.join(home, 'receiver');
  const receiver = await createProfile(receiverHome, { name: 'agent', 'invite-file': invite });
  const calls = [];
  const client = { close() {}, async send(method, params) {
    calls.push({ method, params });
    if (method === 'Target.createTarget') return { targetId: 'page' };
    if (method === 'Target.attachToTarget') return { sessionId: 'session' };
    return {};
  } };
  const receiverDeps = { connect: async () => ({ client, wsUrl: 'ws://127.0.0.1/synthetic' }), list: async () => [...blobs.keys()].map(name => ({ name })), get: async ({ name }) => blobs.get(name) };
  assert.equal((await syncProfile(receiverHome, receiver, receiverDeps)).written, 1);
  const cookie = calls.find(c => c.method === 'Storage.setCookies').params.cookies[0];
  assert.equal(cookie.url, 'https://example.com/');
  assert.equal(cookie.sameSite, 'Lax');
  assert.ok(!('expires' in cookie));
  await terminalMessage({ ...message, cookies: [] }, deps);
  assert.equal((await syncProfile(receiverHome, receiver, receiverDeps)).deleted, 1);
  assert.equal(readJson(profilePaths(home, 'work').state).counter, 2);
  assert.equal((await syncProfile(home, p)).status, 'extension-source');
});

test('extension collects partitioned and regular jars without duplicates; errors abort collection', async () => {
  const plain = { name: 's', value: 'synthetic', domain: 'example.com', path: '/', storeId: '0' };
  const partitioned = { ...plain, partitionKey: { topLevelSite: 'https://example.org', hasCrossSiteAncestor: true } };
  const cookies = await collectTerminalCookies({ getAll: async options => options.partitionKey ? [plain, partitioned] : [plain] });
  assert.equal(cookies.length, 2);
  await assert.rejects(collectTerminalCookies({ getAll: async options => { if (options.partitionKey) throw new Error('collection failed'); return [plain]; } }), /collection/);
  let request;
  const summary = await syncTerminal({ name: 'work', instanceId: 'ab'.repeat(16) }, { collect: async () => cookies, send: async msg => { request = msg; return { ok: true, written: 2 }; } });
  assert.equal(request.type, 'terminalPush');
  assert.equal(summary.sinks.work.written, 2);
  assert.ok(!JSON.stringify(summary).includes('synthetic'));
});
