// Transport A unit tests: fake drop store (temp dir), synthetic cookies, dummy
// domains only. Never writes plaintext cookie files. Errors must not contain
// cookie values or the pairing secret.

import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { mapCookies } from "../src/cookies.js";
import { syntheticCookies } from "./fixtures.js";
import {
  MAGIC,
  VERSION,
  HEADER_LEN,
  TAG_LEN,
  DropError,
  encryptCookies,
  decryptCookies,
} from "../companion/drop-crypto.js";
import {
  generateHostId,
  blobFilename,
  listBlobFiles,
  emptyState,
} from "../companion/drop-store.js";
import { exportCookies, importBlob, importFromDrop } from "../companion/drop.js";

const SECRET = "test-pairing-secret-not-real";
const OTHER_SECRET = "different-pairing-secret-not-real";

function mappedCookies() {
  return mapCookies(syntheticCookies).cookies;
}

function tempDrop() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "chromesync-drop-"));
}

function cleanup(dir) {
  fs.rmSync(dir, { recursive: true, force: true });
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
  assert.equal(s.includes(OTHER_SECRET), false, "pairing secret leaked");
}

function trackingInject() {
  const calls = [];
  const inject = async (cookies) => {
    calls.push(cookies);
    return { written: cookies.length, skipped: 0, errors: [] };
  };
  return { calls, inject };
}

test("encrypt/decrypt round-trip is byte-equal for the CDP cookie array", () => {
  const cookies = mappedCookies();
  const { blob, counter, createdAt } = encryptCookies(cookies, SECRET, { counter: 1, createdAt: 1_700_000_000_000 });
  assert.ok(Buffer.isBuffer(blob));
  assert.equal(blob.subarray(0, 5).toString("ascii"), "CSYNC");
  assert.equal(blob[5], VERSION);
  assert.equal(blob.length >= HEADER_LEN + TAG_LEN, true);

  for (const v of cookieValues()) {
    assert.equal(blob.includes(v), false, "plaintext cookie value in blob");
  }

  const out = decryptCookies(blob, SECRET);
  assert.equal(out.counter, counter);
  assert.equal(out.createdAt, createdAt);
  assert.deepEqual(out.cookies, cookies);
  assert.equal(JSON.stringify(out.cookies), JSON.stringify(cookies));
});

test("fake drop store: write blob, list dir, read/decrypt, byte-equal cookies", () => {
  const dropDir = tempDrop();
  const cookies = mappedCookies();
  const sourceHostId = generateHostId();
  try {
    const res = exportCookies({
      dropDir,
      secret: SECRET,
      sourceHostId,
      cookies,
      counter: 1,
      createdAt: 1_700_000_000_000,
    });
    assert.equal(res.filename, blobFilename(sourceHostId, 1));
    assert.equal(fs.existsSync(res.path), true);
    assert.equal(fs.existsSync(res.path + ".tmp"), false);

    const listed = listBlobFiles(dropDir);
    assert.equal(listed.length, 1);
    assert.equal(listed[0].sourceHostId, sourceHostId);
    assert.equal(listed[0].counter, 1);

    const raw = fs.readFileSync(listed[0].path);
    assert.ok(raw.equals ? raw.subarray(0, MAGIC.length).equals(MAGIC) : true);
    for (const v of cookieValues()) {
      assert.equal(raw.includes(v), false, "plaintext cookie value on disk");
    }
    // File must not be a plaintext JSON cookie array.
    assert.throws(() => {
      const parsed = JSON.parse(raw.toString("utf8"));
      if (Array.isArray(parsed)) throw new Error("plaintext json cookies");
    });

    const out = decryptCookies(raw, SECRET);
    assert.deepEqual(out.cookies, cookies);
    assert.equal(JSON.stringify(out.cookies), JSON.stringify(cookies));
  } finally {
    cleanup(dropDir);
  }
});

test("wrong pairing secret: decrypt throws, import hard-fails, nothing injected", async () => {
  const dropDir = tempDrop();
  const cookies = mappedCookies();
  const sourceHostId = generateHostId();
  const { calls, inject } = trackingInject();
  try {
    const { path: filePath } = exportCookies({
      dropDir,
      secret: SECRET,
      sourceHostId,
      cookies,
      counter: 1,
    });

    assert.throws(() => decryptCookies(fs.readFileSync(filePath), OTHER_SECRET), (err) => {
      assert.ok(err instanceof DropError);
      assert.equal(err.code, "AUTH");
      assertNoLeak(err.message);
      return true;
    });

    const state = emptyState();
    const res = await importBlob({ filePath, sourceHostId, secret: OTHER_SECRET, state, inject });
    assert.equal(res.ok, false);
    assert.equal(res.injected, false);
    assert.equal(calls.length, 0);
    assertNoLeak(res.error);
  } finally {
    cleanup(dropDir);
  }
});

test("corrupted ciphertext byte: auth-tag mismatch, hard fail, nothing injected", async () => {
  const dropDir = tempDrop();
  const cookies = mappedCookies();
  const sourceHostId = generateHostId();
  const { calls, inject } = trackingInject();
  try {
    const { path: filePath } = exportCookies({
      dropDir,
      secret: SECRET,
      sourceHostId,
      cookies,
      counter: 2,
    });
    const raw = Buffer.from(fs.readFileSync(filePath));
    const flipAt = HEADER_LEN; // first ciphertext byte
    raw[flipAt] = raw[flipAt] ^ 0xff;
    fs.writeFileSync(filePath, raw);

    assert.throws(() => decryptCookies(raw, SECRET), (err) => {
      assert.ok(err instanceof DropError);
      assert.equal(err.code, "AUTH");
      assertNoLeak(err.message);
      return true;
    });

    const res = await importBlob({ filePath, sourceHostId, secret: SECRET, state: emptyState(), inject });
    assert.equal(res.ok, false);
    assert.equal(res.injected, false);
    assert.equal(calls.length, 0);
    assertNoLeak(res.error);
  } finally {
    cleanup(dropDir);
  }
});

test("truncated blob (dropped trailing bytes): format/auth mismatch, hard fail", async () => {
  const dropDir = tempDrop();
  const cookies = mappedCookies();
  const sourceHostId = generateHostId();
  const { calls, inject } = trackingInject();
  try {
    const { path: filePath } = exportCookies({
      dropDir,
      secret: SECRET,
      sourceHostId,
      cookies,
      counter: 3,
    });
    const raw = fs.readFileSync(filePath);
    fs.writeFileSync(filePath, raw.subarray(0, raw.length - 8));

    assert.throws(() => decryptCookies(fs.readFileSync(filePath), SECRET), (err) => {
      assert.ok(err instanceof DropError);
      assertNoLeak(err.message);
      return true;
    });

    const res = await importBlob({ filePath, sourceHostId, secret: SECRET, state: emptyState(), inject });
    assert.equal(res.ok, false);
    assert.equal(res.injected, false);
    assert.equal(calls.length, 0);
  } finally {
    cleanup(dropDir);
  }
});

test("tampered header AAD (counter) fails authentication", () => {
  const cookies = mappedCookies();
  const { blob } = encryptCookies(cookies, SECRET, { counter: 7, createdAt: 1_700_000_000_000 });
  const tampered = Buffer.from(blob);
  // counter is u64 BE at offset 34 (5 magic + 1 ver + 16 salt + 12 iv)
  tampered[41] = tampered[41] ^ 0x01;
  assert.throws(() => decryptCookies(tampered, SECRET), (err) => {
    assert.ok(err instanceof DropError);
    assert.equal(err.code, "AUTH");
    assertNoLeak(err.message);
    return true;
  });
});

test("bad magic / unknown version hard-fail without injecting", async () => {
  const dropDir = tempDrop();
  const { calls, inject } = trackingInject();
  try {
    const badMagic = path.join(dropDir, "chromesync-" + generateHostId() + "-1.csync");
    const cookies = mappedCookies();
    const { blob } = encryptCookies(cookies, SECRET, { counter: 1, createdAt: Date.now() });
    const copy = Buffer.from(blob);
    copy[0] = "X".charCodeAt(0);
    fs.writeFileSync(badMagic, copy);

    assert.throws(() => decryptCookies(copy, SECRET), (err) => {
      assert.ok(err instanceof DropError);
      assert.equal(err.code, "FORMAT");
      return true;
    });

    const res = await importBlob({
      filePath: badMagic,
      sourceHostId: generateHostId(),
      secret: SECRET,
      state: emptyState(),
      inject,
    });
    assert.equal(res.ok, false);
    assert.equal(res.injected, false);
    assert.equal(calls.length, 0);

    const badVer = Buffer.from(blob);
    badVer[5] = 0x02;
    assert.throws(() => decryptCookies(badVer, SECRET), (err) => {
      assert.equal(err.code, "FORMAT");
      return true;
    });
  } finally {
    cleanup(dropDir);
  }
});

test("replayed blob is rejected by per-source monotonic counter; nothing re-injected", async () => {
  const dropDir = tempDrop();
  const cookies = mappedCookies();
  const sourceHostId = generateHostId();
  const { calls, inject } = trackingInject();
  const state = emptyState();
  try {
    const { path: filePath } = exportCookies({
      dropDir,
      secret: SECRET,
      sourceHostId,
      cookies,
      counter: 4,
    });

    const first = await importBlob({ filePath, sourceHostId, secret: SECRET, state, inject });
    assert.equal(first.ok, true);
    assert.equal(first.injected, true);
    assert.equal(calls.length, 1);
    assert.deepEqual(calls[0], cookies);

    const replay = await importBlob({ filePath, sourceHostId, secret: SECRET, state, inject });
    assert.equal(replay.ok, false);
    assert.equal(replay.injected, false);
    assert.match(replay.error, /replayed/);
    assert.equal(calls.length, 1);
    assertNoLeak(replay.error);

    // A new blob with the same counter is also refused.
    const again = exportCookies({
      dropDir,
      secret: SECRET,
      sourceHostId,
      cookies,
      counter: 4,
    });
    const sameCounter = await importBlob({
      filePath: again.path,
      sourceHostId,
      secret: SECRET,
      state,
      inject,
    });
    assert.equal(sameCounter.ok, false);
    assert.equal(sameCounter.injected, false);
    assert.equal(calls.length, 1);

    // Lower counter after a higher one is refused.
    const lower = exportCookies({
      dropDir,
      secret: SECRET,
      sourceHostId,
      cookies,
      counter: 3,
    });
    const lowerRes = await importBlob({
      filePath: lower.path,
      sourceHostId,
      secret: SECRET,
      state,
      inject,
    });
    assert.equal(lowerRes.ok, false);
    assert.equal(calls.length, 1);

    // Next counter is accepted.
    const next = exportCookies({
      dropDir,
      secret: SECRET,
      sourceHostId,
      cookies,
      counter: 5,
    });
    const nextRes = await importBlob({
      filePath: next.path,
      sourceHostId,
      secret: SECRET,
      state,
      inject,
    });
    assert.equal(nextRes.ok, true);
    assert.equal(calls.length, 2);
  } finally {
    cleanup(dropDir);
  }
});

test("stale createdAt is rejected by the freshness window", async () => {
  const dropDir = tempDrop();
  const cookies = mappedCookies();
  const sourceHostId = generateHostId();
  const { calls, inject } = trackingInject();
  try {
    const now = 1_800_000_000_000;
    const { path: filePath } = exportCookies({
      dropDir,
      secret: SECRET,
      sourceHostId,
      cookies,
      counter: 1,
      createdAt: now - 10_000,
    });
    const res = await importBlob({
      filePath,
      sourceHostId,
      secret: SECRET,
      state: emptyState(),
      inject,
      maxAgeMs: 1_000,
      now,
    });
    assert.equal(res.ok, false);
    assert.equal(res.injected, false);
    assert.match(res.error, /stale/);
    assert.equal(calls.length, 0);
    assertNoLeak(res.error);
  } finally {
    cleanup(dropDir);
  }
});

test("inject failure does not consume the replay counter; retry succeeds", async () => {
  const dropDir = tempDrop();
  const cookies = mappedCookies();
  const sourceHostId = generateHostId();
  const state = emptyState();
  try {
    const { path: filePath } = exportCookies({
      dropDir,
      secret: SECRET,
      sourceHostId,
      cookies,
      counter: 1,
    });
    const first = await importBlob({
      filePath,
      sourceHostId,
      secret: SECRET,
      state,
      inject: async () => ({ written: 0, skipped: 1, errors: ["cdp failed"] }),
    });
    assert.equal(first.ok, false);
    assert.equal(first.injected, false);
    assert.equal(state.replay[sourceHostId], undefined);

    const thrown = await importBlob({
      filePath,
      sourceHostId,
      secret: SECRET,
      state,
      inject: async () => {
        throw new Error("cdp connect error");
      },
    });
    assert.equal(thrown.ok, false);
    assert.equal(thrown.injected, false);
    assert.equal(thrown.error, "inject failed");
    assert.equal(state.replay[sourceHostId], undefined);
    assertNoLeak(thrown.error);

    const { calls, inject } = trackingInject();
    const retry = await importBlob({ filePath, sourceHostId, secret: SECRET, state, inject });
    assert.equal(retry.ok, true);
    assert.equal(retry.injected, true);
    assert.equal(calls.length, 1);
    assert.equal(state.replay[sourceHostId], 1);
  } finally {
    cleanup(dropDir);
  }
});

test("importFromDrop injects a valid blob and skips a replay of it", async () => {
  const dropDir = tempDrop();
  const cookies = mappedCookies();
  const sourceHostId = generateHostId();
  const { calls, inject } = trackingInject();
  try {
    exportCookies({ dropDir, secret: SECRET, sourceHostId, cookies, counter: 1 });
    const first = await importFromDrop({ dropDir, secret: SECRET, state: emptyState(), inject });
    assert.equal(first.imported, 1);
    assert.equal(first.injected, true);
    assert.equal(calls.length, 1);

    const second = await importFromDrop({ dropDir, secret: SECRET, state: first.state, inject });
    assert.equal(second.imported, 0);
    assert.equal(second.injected, false);
    assert.equal(calls.length, 1);
  } finally {
    cleanup(dropDir);
  }
});

test("dummy domains only in mapped fixtures used by the drop payload", () => {
  const cookies = mappedCookies();
  const allowed = ["example.com", "example.org", "test.invalid"];
  for (const c of cookies) {
    const domain = String(c.domain || c.url || "");
    assert.ok(
      allowed.some((d) => domain.includes(d)),
      `unexpected domain ${domain}`,
    );
  }
});
