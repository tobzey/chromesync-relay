import { paired, pairReceiver } from './pairing-fixture.js';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { startRelay } from '../server/server.js';
import { resolveChromePath } from '../companion/host-core.js';
import { openProfile, connectProfile } from '../cli/browser.js';
import { syncProfile } from '../cli/sync.js';
import { createProfile, createInvite } from '../cli/setup.js';
import { terminalMessage } from '../companion/terminal.js';

test('terminal profiles: real Chrome → encrypted relay → Chrome, isolated profiles and logout', { skip: !resolveChromePath(), timeout: 60000 }, async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'chromesync-cli-e2e-'));
  const sourceHome = path.join(root, 'source'), receiverHome = path.join(root, 'receiver');
  const relay = await startRelay({ host: '127.0.0.1', port: 0, dataDir: path.join(root, 'relay'), sweepIntervalMs: 0, log() {} });
  const { source: p, receiver: receiverProfile, result } = await paired(null, { sourceHome, receiverHome, relay: relay.url });
  relay.config.allowedRooms.push(result.roomId);
  const clients = [];
  try {
    for (const home of [sourceHome, receiverHome]) {
      await openProfile(home, p.name, { headless: true });
      clients.push((await connectProfile(home, p.name)).client);
    }
    let [source, receiver] = clients;
    const cookie = { name: '__Host-session', value: 'synthetic-cli-e2e-value', url: 'https://example.com/', path: '/', secure: true, httpOnly: true, sameSite: 'Lax' };
    await source.send('Storage.setCookies', { cookies: [cookie, { ...cookie, name: 'partitioned', partitionKey: { topLevelSite: 'https://example.org', hasCrossSiteAncestor: true } }] });
    await receiver.send('Storage.setCookies', { cookies: [{ name: 'receiver-only', value: 'synthetic-local', url: 'https://test.invalid/' }] });
    assert.equal((await syncProfile(sourceHome, p)).status, 'sent');

    assert.equal((await syncProfile(receiverHome, receiverProfile)).written, 2);
    const received = (await receiver.send('Storage.getCookies')).cookies;
    assert.equal(received.find(c => c.name === cookie.name).value, cookie.value);
    assert.equal(received.find(c => c.name === cookie.name).session, true);
    assert.ok(received.find(c => c.name === 'partitioned').partitionKey);
    // Restart both real browsers. Simulate session-only cookies discarded on
    // shutdown, then restore the receiver while the relay is unavailable.
    const restart = async (home, old) => {
      await old.send('Browser.close').catch(() => {});
      old.close();
      await delay(800);
      await openProfile(home, p.name, { headless: true });
      const client = (await connectProfile(home, p.name)).client;
      clients.push(client);
      await client.send('Storage.clearCookies');
      return client;
    };
    source = await restart(sourceHome, source);
    assert.equal((await syncProfile(sourceHome, p)).status, 'unchanged');
    assert.equal((await source.send('Storage.getCookies')).cookies.length, 2);
    receiver = await restart(receiverHome, receiver);
    assert.equal((await syncProfile(receiverHome, receiverProfile, { list: async () => { throw new Error('offline'); } })).status, 'restored-offline');
    assert.equal((await receiver.send('Storage.getCookies')).cookies.find(c => c.name === cookie.name).value, cookie.value);
    await receiver.send('Storage.setCookies', { cookies: [{ name: 'receiver-only', value: 'synthetic-local', url: 'https://test.invalid/' }] });
    // A different named profile has its own room identity and never imports this source.
    const personalSource = await createProfile(sourceHome, { name: 'personal', role: 'source', relay: relay.url });
    const personal = await pairReceiver(sourceHome, personalSource, receiverHome, 'personal');
    relay.config.allowedRooms.push(personal.result.roomId);
    assert.equal((await syncProfile(receiverHome, personal.receiver)).status, 'waiting-for-source');
    await source.send('Storage.clearCookies');
    await syncProfile(sourceHome, p);
    assert.equal((await syncProfile(receiverHome, receiverProfile)).deleted, 2);
    const after = (await receiver.send('Storage.getCookies')).cookies;
    assert.deepEqual(after.map(c => c.name), ['receiver-only']);
    // An everyday-Chrome extension source uses the same receiver flow. Its
    // synthetic chrome.cookies payload goes through the real relay and CDP.
    const extensionSource = await createProfile(sourceHome, { name: 'everyday', role: 'source', source: 'extension', relay: relay.url });
    const inviteFile = path.join(root, 'everyday.invite.json');
    const { receiver: extensionReceiver, result: extensionPair } = await pairReceiver(sourceHome, extensionSource, receiverHome, 'everyday');
    relay.config.allowedRooms.push(extensionPair.roomId);
    await openProfile(receiverHome, 'everyday', { headless: true });
    const extensionClient = (await connectProfile(receiverHome, 'everyday')).client;
    clients.push(extensionClient);
    const request = { name: 'everyday', instanceId: 'ab'.repeat(16) };
    await terminalMessage({ ...request, type: 'terminalBind' }, { home: sourceHome });
    await terminalMessage({ ...request, type: 'terminalPush', cookies: [{ name: '__Host-session', value: 'synthetic-extension-session',
      domain: 'example.com', path: '/', secure: true, httpOnly: true, hostOnly: true, sameSite: 'lax', session: true,
      partitionKey: { topLevelSite: 'https://example.org', hasCrossSiteAncestor: true } }] }, { home: sourceHome });
    assert.equal((await syncProfile(receiverHome, extensionReceiver)).written, 1);
    const extensionCookie = (await extensionClient.send('Storage.getCookies')).cookies[0];
    assert.equal(extensionCookie.value, 'synthetic-extension-session');
    assert.equal(extensionCookie.partitionKey.topLevelSite, 'https://example.org');
    await terminalMessage({ ...request, type: 'terminalPush', cookies: [] }, { home: sourceHome });
    assert.equal((await syncProfile(receiverHome, extensionReceiver)).deleted, 1);
  } finally {
    for (const client of clients) {
      await client.send('Browser.close').catch(() => {});
      client.close();
    }
    await relay.close();
    // Chrome may still flush its profile after Browser.close returns.
    for (let i = 0; i < 20; i++) {
      await delay(200);
      try { fs.rmSync(root, { recursive: true, force: true }); break; } catch { /* Still flushing. */ }
    }
  }
});
