// Production wiring: FileDropSink → exportDrop / importDrop with Options-shaped
// config (blank sourceHostId, statePath: "", no counter). Uses a temp HOME so
// tests never touch the real home directory. Synthetic cookies / dummy domains.

import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { mapCookies } from "../src/cookies.js";
import { syntheticCookies } from "./fixtures.js";
import { FileDropSink } from "../src/sinks/fileDrop.js";
import { handleNativeMessage } from "../companion/host-messages.js";
import { defaultStatePath, listBlobFiles, loadState } from "../companion/drop.js";

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

function optionsConfig(dropDir) {
  return {
    dropDir,
    pairingSecret: SECRET,
    sourceHostId: "",
    statePath: "",
  };
}

function makeSink(env, extra = {}) {
  return new FileDropSink({
    send: (msg) => handleNativeMessage(msg, { env, inject: extra.inject, fs: extra.fs }),
  });
}

test("Options-shaped export: blank host id + empty statePath generates and persists host id", async () => {
  const tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), "chromesync-home-"));
  const dropDir = fs.mkdtempSync(path.join(os.tmpdir(), "chromesync-drop-"));
  const env = { HOME: tmpHome };
  const cfg = optionsConfig(dropDir);
  const cookies = mappedCookies();
  try {
    const sink = makeSink(env);
    const valid = await sink.validate(cfg);
    assert.equal(valid.ok, true, valid.error);

    const res = await sink.writeCookies(cookies, cfg);
    assert.deepEqual(res.errors, []);
    assert.equal(res.written, cookies.length);

    const blobs = listBlobFiles(dropDir);
    assert.equal(blobs.length, 1);
    assert.equal(blobs[0].counter, 1);
    assert.match(blobs[0].sourceHostId, /^[a-f0-9]+$/);

    const raw = fs.readFileSync(blobs[0].path);
    for (const v of cookieValues()) {
      assert.equal(raw.includes(v), false, "plaintext cookie value on disk");
    }

    const stateFile = defaultStatePath(env);
    assert.equal(stateFile.startsWith(tmpHome), true);
    assert.equal(fs.existsSync(stateFile), true);
    const st = loadState(stateFile);
    assert.equal(st.sourceHostId, blobs[0].sourceHostId);
    assert.equal(st.exportCounter, 1);
    const stateText = fs.readFileSync(stateFile, "utf8");
    for (const v of cookieValues()) {
      assert.equal(stateText.includes(v), false, "cookie value in state file");
    }
    assert.equal(JSON.parse(stateText).replay && typeof JSON.parse(stateText).replay, "object");

    // Second export reuses the same host id and increments the counter.
    const res2 = await sink.writeCookies(cookies, cfg);
    assert.deepEqual(res2.errors, []);
    const blobs2 = listBlobFiles(dropDir);
    assert.equal(blobs2.length, 2);
    assert.equal(new Set(blobs2.map((b) => b.sourceHostId)).size, 1);
    assert.deepEqual(blobs2.map((b) => b.counter).sort((a, b) => a - b), [1, 2]);
    assert.equal(loadState(stateFile).exportCounter, 2);
    assert.equal(loadState(stateFile).sourceHostId, st.sourceHostId);
  } finally {
    fs.rmSync(tmpHome, { recursive: true, force: true });
    fs.rmSync(dropDir, { recursive: true, force: true });
  }
});

test("validate fails closed when drop dir is missing (Options-shaped config)", async () => {
  const tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), "chromesync-home-"));
  const env = { HOME: tmpHome };
  try {
    const sink = makeSink(env);
    const valid = await sink.validate(optionsConfig(path.join(tmpHome, "no-such-drop")));
    assert.equal(valid.ok, false);
    assert.match(valid.error, /drop folder/);
  } finally {
    fs.rmSync(tmpHome, { recursive: true, force: true });
  }
});

test("importDrop without statePath persists replay; second run refuses the blob", async () => {
  const tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), "chromesync-home-"));
  const dropDir = fs.mkdtempSync(path.join(os.tmpdir(), "chromesync-drop-"));
  const env = { HOME: tmpHome };
  const cfg = optionsConfig(dropDir);
  const cookies = mappedCookies();
  const calls = [];
  try {
    const sink = makeSink(env);
    assert.equal((await sink.validate(cfg)).ok, true);
    assert.deepEqual((await sink.writeCookies(cookies, cfg)).errors, []);

    const inject = async (c) => {
      calls.push(c);
      return { written: c.length, skipped: 0, errors: [] };
    };
    const first = await handleNativeMessage(
      { type: "importDrop", dropDir, pairingSecret: SECRET, statePath: "" },
      { env, inject },
    );
    assert.equal(first.ok, true);
    assert.equal(first.injected, true);
    assert.equal(calls.length, 1);
    assert.deepEqual(calls[0], cookies);
    assertNoLeak(first);

    const st = loadState(defaultStatePath(env));
    const hostId = listBlobFiles(dropDir)[0].sourceHostId;
    assert.equal(st.replay[hostId], 1);

    const second = await handleNativeMessage(
      { type: "importDrop", dropDir, pairingSecret: SECRET, statePath: "" },
      { env, inject },
    );
    assert.equal(second.injected, false);
    assert.equal(calls.length, 1);
    assert.ok(second.errors.some((e) => /replayed/.test(e)));
    assertNoLeak(second);
  } finally {
    fs.rmSync(tmpHome, { recursive: true, force: true });
    fs.rmSync(dropDir, { recursive: true, force: true });
  }
});

test("inject failure does not consume the persisted counter; retry then succeeds", async () => {
  const tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), "chromesync-home-"));
  const dropDir = fs.mkdtempSync(path.join(os.tmpdir(), "chromesync-drop-"));
  const env = { HOME: tmpHome };
  const cfg = optionsConfig(dropDir);
  const cookies = mappedCookies();
  try {
    const sink = makeSink(env);
    assert.equal((await sink.validate(cfg)).ok, true);
    assert.deepEqual((await sink.writeCookies(cookies, cfg)).errors, []);
    const hostId = listBlobFiles(dropDir)[0].sourceHostId;

    const fail = await handleNativeMessage(
      { type: "importDrop", dropDir, pairingSecret: SECRET, statePath: "" },
      { env, inject: async () => ({ written: 0, skipped: 1, errors: ["cdp failed"] }) },
    );
    assert.equal(fail.ok, false);
    assert.equal(fail.injected, false);
    assert.equal(loadState(defaultStatePath(env)).replay[hostId], undefined);
    assertNoLeak(fail);

    const calls = [];
    const retry = await handleNativeMessage(
      { type: "importDrop", dropDir, pairingSecret: SECRET, statePath: "" },
      {
        env,
        inject: async (c) => {
          calls.push(c);
          return { written: c.length, skipped: 0, errors: [] };
        },
      },
    );
    assert.equal(retry.ok, true);
    assert.equal(retry.injected, true);
    assert.equal(calls.length, 1);
    assert.equal(loadState(defaultStatePath(env)).replay[hostId], 1);
    assertNoLeak(retry);
  } finally {
    fs.rmSync(tmpHome, { recursive: true, force: true });
    fs.rmSync(dropDir, { recursive: true, force: true });
  }
});
