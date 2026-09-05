// profile-use CLI wrap tests. Fake binary on a temp PATH only — never a real
// profile-use install, never a real API key, never a real Chrome profile UUID.
// Existing mock HTTPS tests live in browserUse.test.js and must keep passing.

import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn as realSpawn, spawnSync as realSpawnSync } from "node:child_process";
import { BrowserUseSink } from "../src/sinks/browserUse.js";
import { validateProfileUse, runProfileUseSync, MIN_PROFILE_USE_VERSION } from "../companion/profile-use.js";
import { mapCookies } from "../src/cookies.js";
import { syntheticCookies } from "./fixtures.js";
import { createMockBuServer } from "../mock/bu-api.js";

const DUMMY_KEY = "dummy-bu-key";

assert.equal(MIN_PROFILE_USE_VERSION, "1.0.5");

function installFake(dir, { version = "1.0.5", exitCode = 0, recordPath } = {}) {
  const bin = path.join(dir, "profile-use");
  const script = `#!${process.execPath}
const fs = require("fs");
const version = ${JSON.stringify(version)};
const exitCode = ${Number(exitCode)};
const recordPath = ${JSON.stringify(recordPath || "")};
if (process.argv.includes("--version")) {
  process.stdout.write(version + "\\n");
  process.exit(0);
}
if (recordPath) {
  fs.writeFileSync(recordPath, JSON.stringify({
    argv: process.argv.slice(2),
    keyPresent: Boolean(process.env.BROWSER_USE_API_KEY),
    key: process.env.BROWSER_USE_API_KEY || ""
  }));
}
process.exit(exitCode);
`;
  fs.writeFileSync(bin, script, { mode: 0o755 });
  fs.chmodSync(bin, 0o755);
  return bin;
}

function makeSink(env, extra = {}) {
  const deps = { env, spawn: extra.spawn, spawnSync: extra.spawnSync, fs: extra.fs };
  return new BrowserUseSink(undefined, {
    env,
    profileUse: {
      validate: (cfg, d) => validateProfileUse(cfg, { ...d, ...deps }),
      write: (cfg, d) => runProfileUseSync(cfg, { ...d, ...deps }),
    },
  });
}

function assertNoLeak(text) {
  const s = JSON.stringify(text);
  for (const c of syntheticCookies) {
    assert.equal(s.includes(c.value), false, "cookie value leaked");
  }
  // Product errors must not echo the key. The dummy value may appear in the
  // fake CLI's record file (that's how the happy path asserts env), not here.
}

test("happy path: key set, fake binary v1.0.5, valid dir → expected argv and env", async () => {
  const binDir = fs.mkdtempSync(path.join(os.tmpdir(), "chromesync-pu-bin-"));
  const profileDir = fs.mkdtempSync(path.join(os.tmpdir(), "chromesync-pu-profile-"));
  const recordPath = path.join(binDir, "record.json");
  try {
    installFake(binDir, { version: "1.0.5", exitCode: 0, recordPath });
    const env = { PATH: binDir, BROWSER_USE_API_KEY: DUMMY_KEY };
    const sink = makeSink(env);
    const cfg = { profileUseDir: profileDir };

    const valid = await sink.validate(cfg);
    assert.equal(valid.ok, true);

    const { cookies } = mapCookies(syntheticCookies);
    const res = await sink.writeCookies(cookies, cfg);
    assert.deepEqual(res.errors, []);
    assert.equal(fs.existsSync(recordPath), true);
    const rec = JSON.parse(fs.readFileSync(recordPath, "utf8"));
    assert.deepEqual(rec.argv, ["sync", "--user-data-dir", profileDir]);
    assert.equal(rec.keyPresent, true);
    assert.equal(rec.key, DUMMY_KEY);
    assert.equal(JSON.stringify(res).includes(DUMMY_KEY), false);
    assertNoLeak(res);
  } finally {
    fs.rmSync(binDir, { recursive: true, force: true });
    fs.rmSync(profileDir, { recursive: true, force: true });
  }
});

test("missing binary (empty PATH) → disabled, actionable error, no crash", async () => {
  const profileDir = fs.mkdtempSync(path.join(os.tmpdir(), "chromesync-pu-profile-"));
  try {
    let spawned = 0;
    const spawn = (...args) => {
      spawned++;
      return realSpawn(...args);
    };
    const spawnSync = (...args) => {
      spawned++;
      return realSpawnSync(...args);
    };
    const env = { PATH: "", BROWSER_USE_API_KEY: DUMMY_KEY };
    const sink = makeSink(env, { spawn, spawnSync });
    const cfg = { profileUseDir: profileDir };

    const valid = await sink.validate(cfg);
    assert.equal(valid.ok, false);
    assert.match(valid.error, /profile-use not found on PATH/);
    assert.equal(spawned, 0);

    const res = await sink.writeCookies([], cfg);
    assert.equal(res.errors.length > 0, true);
    assert.match(res.errors[0], /profile-use not found on PATH/);
    assert.equal(spawned, 0);
    assertNoLeak(valid);
    assertNoLeak(res);
  } finally {
    fs.rmSync(profileDir, { recursive: true, force: true });
  }
});

test("version too old (1.0.4) → disabled with version message", async () => {
  const binDir = fs.mkdtempSync(path.join(os.tmpdir(), "chromesync-pu-bin-"));
  const profileDir = fs.mkdtempSync(path.join(os.tmpdir(), "chromesync-pu-profile-"));
  const recordPath = path.join(binDir, "record.json");
  try {
    installFake(binDir, { version: "1.0.4", recordPath });
    const env = { PATH: binDir, BROWSER_USE_API_KEY: DUMMY_KEY };
    const sink = makeSink(env);
    const cfg = { profileUseDir: profileDir };

    const valid = await sink.validate(cfg);
    assert.equal(valid.ok, false);
    assert.equal(valid.error, "profile-use >= 1.0.5 required, found 1.0.4");
    assert.equal(fs.existsSync(recordPath), false);

    const res = await sink.writeCookies([], cfg);
    assert.match(res.errors[0], /profile-use >= 1.0.5 required, found 1.0.4/);
    assert.equal(fs.existsSync(recordPath), false);
  } finally {
    fs.rmSync(binDir, { recursive: true, force: true });
    fs.rmSync(profileDir, { recursive: true, force: true });
  }
});

test("missing BROWSER_USE_API_KEY → disabled, no shell-out", async () => {
  const binDir = fs.mkdtempSync(path.join(os.tmpdir(), "chromesync-pu-bin-"));
  const profileDir = fs.mkdtempSync(path.join(os.tmpdir(), "chromesync-pu-profile-"));
  const recordPath = path.join(binDir, "record.json");
  try {
    installFake(binDir, { version: "1.0.5", recordPath });
    let spawned = 0;
    const spawn = (...args) => {
      spawned++;
      return realSpawn(...args);
    };
    const spawnSync = (...args) => {
      spawned++;
      return realSpawnSync(...args);
    };
    const env = { PATH: binDir, BROWSER_USE_API_KEY: "" };
    const sink = makeSink(env, { spawn, spawnSync });
    const cfg = { profileUseDir: profileDir };

    const valid = await sink.validate(cfg);
    assert.equal(valid.ok, false);
    assert.match(valid.error, /BROWSER_USE_API_KEY is not set/);
    assert.equal(spawned, 0);
    assert.equal(fs.existsSync(recordPath), false);

    const res = await sink.writeCookies([], cfg);
    assert.match(res.errors[0], /BROWSER_USE_API_KEY is not set/);
    assert.equal(spawned, 0);
  } finally {
    fs.rmSync(binDir, { recursive: true, force: true });
    fs.rmSync(profileDir, { recursive: true, force: true });
  }
});

test("CLI nonzero exit → generic error, counts-only, no leak", async () => {
  const binDir = fs.mkdtempSync(path.join(os.tmpdir(), "chromesync-pu-bin-"));
  const profileDir = fs.mkdtempSync(path.join(os.tmpdir(), "chromesync-pu-profile-"));
  const recordPath = path.join(binDir, "record.json");
  try {
    installFake(binDir, { version: "1.0.5", exitCode: 2, recordPath });
    const env = { PATH: binDir, BROWSER_USE_API_KEY: DUMMY_KEY };
    const sink = makeSink(env);
    const cfg = { profileUseDir: profileDir };

    const valid = await sink.validate(cfg);
    assert.equal(valid.ok, true);

    const { cookies } = mapCookies(syntheticCookies);
    const res = await sink.writeCookies(cookies, cfg);
    assert.equal(res.written, 0);
    assert.equal(typeof res.skipped, "number");
    assert.deepEqual(res.errors, ["profile-use failed"]);
    const serialized = JSON.stringify(res);
    assert.equal(serialized.includes(DUMMY_KEY), false);
    assertNoLeak(res);
    // Fake did run (record exists) but product errors stay generic.
    assert.equal(fs.existsSync(recordPath), true);
  } finally {
    fs.rmSync(binDir, { recursive: true, force: true });
    fs.rmSync(profileDir, { recursive: true, force: true });
  }
});

test("HTTPS mock stub still works when profileUseDir is not set", async () => {
  const mock = createMockBuServer();
  const baseUrl = await mock.listen();
  try {
    const sink = new BrowserUseSink();
    const valid = await sink.validate({ apiKey: "dummy-key", baseUrl });
    assert.equal(valid.ok, true);
    const { cookies } = mapCookies(syntheticCookies);
    const res = await sink.writeCookies(cookies, { apiKey: "dummy-key", baseUrl, profileId: "test-profile" });
    assert.equal(res.written, cookies.length);
    assert.equal(res.errors.length, 0);
  } finally {
    await mock.close();
  }
});
