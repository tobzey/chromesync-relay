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

test("Options-shaped push persists counter only after a successful PUT", async () => {
  const tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), "chromesync-home-"));
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "chromesync-relay-"));
  const env = { HOME: tmpHome };
  const cookies = mappedCookies();
  const relay = await startRelay({
    host: "127.0.0.1",
    port: 0,
    dataDir,
    sweepIntervalMs: 0,
    rateIpCapacity: 10_000,
    rateRoomCapacity: 10_000,
    log: () => {},
  });
  try {
    const cfg = {
      relayUrl: relay.url,
      pairingSecret: SECRET,
      sourceHostId: "",
      statePath: "",
    };
    const sink = new RelaySink({
      send: (msg) => handleNativeMessage(msg, { env }),
    });
    const valid = await sink.validate(cfg);
    assert.equal(valid.ok, true, valid.error);

    const res = await sink.writeCookies(cookies, cfg);
    assert.deepEqual(res.errors, []);
    assert.equal(res.written, cookies.length);

    const stateFile = defaultStatePath(env);
    assert.equal(fs.existsSync(stateFile), true);
    const st = loadState(stateFile);
    assert.match(st.sourceHostId, /^[a-f0-9]+$/);
    assert.equal(st.exportCounter, 1);
    const stateText = fs.readFileSync(stateFile, "utf8");
    for (const v of cookieValues()) {
      assert.equal(stateText.includes(v), false, "cookie value in state file");
    }

    const listed = await handleNativeMessage(
      { type: "relayValidate", ...cfg },
      { env },
    );
    assert.equal(listed.ok, true);

    const calls = [];
    const first = await handleNativeMessage(
      { type: "relayPull", ...cfg },
      {
        env,
        inject: async (c) => {
          calls.push(c);
          return { written: c.length, skipped: 0, errors: [] };
        },
      },
    );
    assert.equal(first.imported, 1);
    assert.equal(calls.length, 1);
    assert.deepEqual(calls[0], cookies);
    assertNoLeak(first);

    const second = await handleNativeMessage(
      { type: "relayPull", ...cfg },
      {
        env,
        inject: async (c) => {
          calls.push(c);
          return { written: c.length, skipped: 0, errors: [] };
        },
      },
    );
    assert.equal(second.imported, 0);
    assert.equal(calls.length, 1);
    assertNoLeak(second);
  } finally {
    await relay.close();
    fs.rmSync(tmpHome, { recursive: true, force: true });
    fs.rmSync(dataDir, { recursive: true, force: true });
  }
});

test("failed push does not persist the export counter", async () => {
  const tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), "chromesync-home-"));
  const env = { HOME: tmpHome };
  try {
    const res = await handleNativeMessage(
      {
        type: "relayPush",
        relayUrl: "http://127.0.0.1:1",
        pairingSecret: SECRET,
        statePath: "",
        cookies: mappedCookies(),
      },
      { env },
    );
    assert.equal(res.ok, false);
    assert.ok(res.errors && res.errors.length);
    assertNoLeak(res);
    const stateFile = defaultStatePath(env);
    if (fs.existsSync(stateFile)) {
      assert.equal(loadState(stateFile).exportCounter, 0);
    }
  } finally {
    fs.rmSync(tmpHome, { recursive: true, force: true });
  }
});
