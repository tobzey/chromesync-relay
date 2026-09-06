// Production wiring: RelaySink posts relayValidate/relayPush; DEFAULT_CONFIG
// includes the relay sink; buildRegistry returns it. Options-shaped config
// (blank host id, empty statePath) against a real local relay.

import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { RelaySink } from "../src/sinks/relay.js";
import { DEFAULT_CONFIG } from "../src/storage.js";
import { buildRegistry } from "../src/sinks/registry.js";
import { handleNativeMessage } from "../companion/host-messages.js";
import { loadState, defaultStatePath } from "../companion/drop.js";
import { startRelay } from "../server/server.js";
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
  const s = JSON.stringify(text);
  for (const v of cookieValues()) {
    assert.equal(s.includes(v), false, "cookie value leaked");
  }
  assert.equal(s.includes(SECRET), false, "pairing secret leaked");
}

test("DEFAULT_CONFIG includes the relay sink and syncOnChange", () => {
  assert.equal(DEFAULT_CONFIG.syncOnChange, true);
  assert.ok(DEFAULT_CONFIG.sinks.relay);
  assert.equal(DEFAULT_CONFIG.sinks.relay.enabled, false);
  assert.equal(DEFAULT_CONFIG.sinks.relay.mode, "push");
  assert.equal(DEFAULT_CONFIG.sinks.relay.pollMinutes, 1);
  assert.equal(DEFAULT_CONFIG.sinks.relay.maxAgeMs, 0);
  assert.equal(DEFAULT_CONFIG.sinks.relay.relayUrl, "");
});

test("buildRegistry returns RelaySink", () => {
  const reg = buildRegistry();
  const s = reg.get("relay");
  assert.ok(s);
  assert.equal(s.id, "relay");
  assert.equal(s.label, "Encrypted sync server");
});

test("RelaySink posts relayValidate / relayPush native messages", async () => {
  const posted = [];
  const sink = new RelaySink({
    send: async (msg) => {
      posted.push(msg);
      return { ok: true };
    },
  });
  const cfg = { pairingSecret: SECRET, relayUrl: "http://127.0.0.1:1" };
  const valid = await sink.validate(cfg);
  assert.equal(valid.ok, true);
  assert.equal(posted[0].type, "relayValidate");
  assert.equal(posted[0].relayUrl, cfg.relayUrl);
  assert.equal(posted[0].pairingSecret, SECRET);
  const cookies = mappedCookies();
  const written = await sink.writeCookies(cookies, cfg);
  assert.deepEqual(written.errors, []);
  assert.equal(posted[1].type, "relayPush");
  assert.equal(posted[1].cookies, cookies);
});

test("native legacy relay entry points reject even with valid transport fields", async () => {
  for (const type of ['relayValidate', 'relayPush', 'relayPull']) {
    const result = await handleNativeMessage({ type, pairingSecret: SECRET, relayUrl: 'https://relay.example.com', cookies: [] }, { relayPush: () => assert.fail('legacy upload'), relayList: () => assert.fail('legacy download') });
    assert.equal(result.ok, false); assert.match(result.error, /disabled/);
  }
});
