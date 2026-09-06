// Relay client against the real local server: encrypt/decrypt round-trip,
// SSRF/redirect guards, replay + tamper via importBlob. Synthetic cookies only.

import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { startRelay } from "../server/server.js";
import { deriveRelayAuth, clearRelayAuthCache } from "../companion/relay-auth.js";
import { relayPush, relayList, relayGet, parseRelayUrl, RelayClientError } from "../companion/relay-client.js";
import { encryptCookies, HEADER_LEN } from "../companion/drop-crypto.js";
import { exportBlobWithState, importBlob, emptyState, loadState } from "../companion/drop.js";
import { generateHostId } from "../companion/drop-store.js";
import { mapCookies } from "../src/cookies.js";
import { syntheticCookies } from "./fixtures.js";

const SECRET = "test-pairing-secret-not-real";

function mappedCookies() {
  return mapCookies(syntheticCookies).cookies;
}

function cookieValues() {
  return syntheticCookies.map((c) => c.value);
}

function assertNoLeak(text) {
  const s = String(text);
  for (const v of cookieValues()) {
    assert.equal(s.includes(v), false, "cookie value leaked");
  }
  assert.equal(s.includes(SECRET), false, "pairing secret leaked");
}

async function withRelay(fn) {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "chromesync-relay-"));
  const relay = await startRelay({
    allowedRooms: [deriveRelayAuth(SECRET).roomId],
    host: "127.0.0.1",
    port: 0,
    dataDir,
    sweepIntervalMs: 0,
    rateIpCapacity: 10_000,
    rateRoomCapacity: 10_000,
    log: () => {},
  });
  try {
    await fn(relay, dataDir);
  } finally {
    await relay.close();
    fs.rmSync(dataDir, { recursive: true, force: true });
  }
}

test("push → list → pull encrypt/decrypt is byte-equal for synthetic cookies", async () => {
  await withRelay(async (relay) => {
    const cookies = mappedCookies();
    clearRelayAuthCache();
    const { token, roomId } = deriveRelayAuth(SECRET);
    const exported = exportBlobWithState({
      secret: SECRET,
      cookies,
      state: emptyState(),
      sourceHostId: generateHostId(),
    });
    for (const v of cookieValues()) {
      assert.equal(exported.blob.includes(v), false, "plaintext cookie value in blob");
    }
    await relayPush({
      relayUrl: relay.url,
      token,
      roomId,
      name: exported.filename,
      blob: exported.blob,
    });
    const listed = await relayList({ relayUrl: relay.url, token, roomId });
    assert.equal(listed.length, 1);
    assert.equal(listed[0].name, exported.filename);

    const pulled = await relayGet({ relayUrl: relay.url, token, roomId, name: exported.filename });
    assert.equal(pulled.equals(exported.blob), true);

    const { calls, inject } = (() => {
      const calls = [];
      return {
        calls,
        inject: async (c) => {
          calls.push(c);
          return { written: c.length, skipped: 0, errors: [] };
        },
      };
    })();
    const res = await importBlob({
      blob: pulled,
      sourceHostId: exported.sourceHostId,
      secret: SECRET,
      state: emptyState(),
      inject,
    });
    assert.equal(res.ok, true);
    assert.equal(res.injected, true);
    assert.deepEqual(calls[0], cookies);
    assert.equal(JSON.stringify(calls[0]), JSON.stringify(cookies));
  });
});

test("SSRF guards: non-loopback http rejected; credentials rejected", () => {
  assert.throws(() => parseRelayUrl("http://example.com"), (e) => e instanceof RelayClientError);
  assert.throws(() => parseRelayUrl("http://8.8.8.8"), (e) => e instanceof RelayClientError);
  assert.throws(() => parseRelayUrl("http://user:pass@127.0.0.1/"), (e) => e instanceof RelayClientError);
  parseRelayUrl("http://127.0.0.1");
  parseRelayUrl("http://localhost");
  parseRelayUrl("https://relay.example.com");
});

test("server returning 302 is rejected (no redirect follow)", async () => {
  const srv = http.createServer((req, res) => {
    res.writeHead(302, { Location: "http://127.0.0.1/elsewhere" });
    res.end();
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  const { port } = srv.address();
  try {
    clearRelayAuthCache();
    const { token, roomId } = deriveRelayAuth(SECRET);
    await assert.rejects(
      () => relayList({ relayUrl: `http://127.0.0.1:${port}`, token, roomId }),
      (e) => e instanceof RelayClientError && e.status >= 300 && e.status < 400,
    );
  } finally {
    await new Promise((r) => srv.close(r));
  }
});

test("replayed blob is rejected by the monotonic counter; nothing re-injected", async () => {
  await withRelay(async (relay) => {
    const cookies = mappedCookies();
    clearRelayAuthCache();
    const { token, roomId } = deriveRelayAuth(SECRET);
    const exported = exportBlobWithState({
      secret: SECRET,
      cookies,
      state: emptyState(),
      sourceHostId: generateHostId(),
    });
    await relayPush({ relayUrl: relay.url, token, roomId, name: exported.filename, blob: exported.blob });
    const pulled = await relayGet({ relayUrl: relay.url, token, roomId, name: exported.filename });
    const state = emptyState();
    const calls = [];
    const inject = async (c) => {
      calls.push(c);
      return { written: c.length, skipped: 0, errors: [] };
    };
    const first = await importBlob({ blob: pulled, sourceHostId: exported.sourceHostId, secret: SECRET, state, inject });
    assert.equal(first.ok, true);
    const replay = await importBlob({ blob: pulled, sourceHostId: exported.sourceHostId, secret: SECRET, state, inject });
    assert.equal(replay.ok, false);
    assert.equal(replay.injected, false);
    assert.match(replay.error, /replayed/);
    assert.equal(calls.length, 1);
    assertNoLeak(replay.error);
  });
});

test("tampered ciphertext byte fails AEAD; nothing injected", async () => {
  await withRelay(async (relay, dataDir) => {
    const cookies = mappedCookies();
    clearRelayAuthCache();
    const { token, roomId } = deriveRelayAuth(SECRET);
    const cookies2 = mappedCookies();
    const { blob } = encryptCookies(cookies2, SECRET, { counter: 1, createdAt: Date.now() });
    const hostId = generateHostId();
    const name = `chromesync-${hostId}-1.csync`;
    await relayPush({ relayUrl: relay.url, token, roomId, name, blob });
    const fp = path.join(dataDir, roomId, name);
    const raw = Buffer.from(fs.readFileSync(fp));
    raw[HEADER_LEN] = raw[HEADER_LEN] ^ 0xff;
    fs.writeFileSync(fp, raw);
    const pulled = await relayGet({ relayUrl: relay.url, token, roomId, name });
    const calls = [];
    const res = await importBlob({
      blob: pulled,
      sourceHostId: hostId,
      secret: SECRET,
      state: emptyState(),
      inject: async (c) => {
        calls.push(c);
        return { written: c.length, skipped: 0, errors: [] };
      },
    });
    assert.equal(res.ok, false);
    assert.equal(res.injected, false);
    assert.equal(calls.length, 0);
    assertNoLeak(res.error);
  });
});

test("exportBlobWithState does not persist the counter; caller saves after PUT", async () => {
  const tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), "chromesync-home-"));
  const statePath = path.join(tmpHome, "drop-state.json");
  try {
    const cookies = mappedCookies();
    const exported = exportBlobWithState({
      secret: SECRET,
      cookies,
      statePath,
      sourceHostId: generateHostId(),
    });
    assert.ok(Buffer.isBuffer(exported.blob));
    assert.equal(exported.counter, 1);
    assert.equal(fs.existsSync(statePath), false);
    const st = loadState(statePath);
    assert.equal(st.exportCounter, 0);
  } finally {
    fs.rmSync(tmpHome, { recursive: true, force: true });
  }
});
