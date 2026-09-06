// Real local relay: PUT→list→GET byte-for-byte, auth/path negatives, quota,
// retention, TTL, DELETE. Synthetic data only; 127.0.0.1 ephemeral port.

import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { startRelay } from "../server/server.js";
import { TokenBucket } from "../server/ratelimit.js";
import { STALE_TMP_MS } from "../server/store.js";
import { deriveRelayAuth, clearRelayAuthCache } from "../companion/relay-auth.js";
import { blobFilename, generateHostId } from "../companion/drop-store.js";

const SECRET = "test-pairing-secret-not-real";

function auth() {
  clearRelayAuthCache();
  return deriveRelayAuth(SECRET);
}

async function raw({ url, method, token, body, headers, roomId, name }) {
  const u = new URL(url);
  if (roomId && name) u.pathname = `/rooms/${roomId}/blobs/${name}`;
  else if (roomId) u.pathname = `/rooms/${roomId}/blobs`;
  const payload = body == null ? null : Buffer.isBuffer(body) ? body : Buffer.from(body);
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        hostname: u.hostname,
        port: u.port,
        path: u.pathname,
        method,
        headers: {
          ...(token ? { authorization: `Bearer ${token}` } : {}),
          ...(payload ? { "content-length": String(payload.length), "content-type": "application/octet-stream" } : {}),
          ...headers,
        },
      },
      (res) => {
        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => resolve({ status: res.statusCode, body: Buffer.concat(chunks) }));
      },
    );
    req.on("error", reject);
    if (payload) req.write(payload);
    req.end();
  });
}

async function withRelay(extra, fn) {
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
    ...extra,
  });
  try {
    await fn(relay, dataDir);
  } finally {
    await relay.close();
    fs.rmSync(dataDir, { recursive: true, force: true });
  }
}

test("PUT → list → GET preserves bytes byte-for-byte; on-disk matches upload", async () => {
  await withRelay({}, async (relay) => {
    const { token, roomId } = auth();
    const hostId = generateHostId();
    const name = blobFilename(hostId, 1);
    const uploaded = Buffer.from("CSYNC-opaque-fixture-not-cookies");
    const put = await raw({ url: relay.url, method: "PUT", token, roomId, name, body: uploaded });
    assert.equal(put.status, 204);

    const list = await raw({ url: relay.url, method: "GET", token, roomId });
    assert.equal(list.status, 200);
    const items = JSON.parse(list.body.toString("utf8"));
    assert.equal(items.length, 1);
    assert.equal(items[0].name, name);
    assert.equal(items[0].size, uploaded.length);
    assert.equal(typeof items[0].mtime, "number");

    const got = await raw({ url: relay.url, method: "GET", token, roomId, name });
    assert.equal(got.status, 200);
    assert.equal(got.body.equals(uploaded), true);

    const onDisk = fs.readFileSync(path.join(relay.store.dataDir, roomId, name));
    assert.equal(onDisk.equals(uploaded), true);
  });
});

test("wrong token ⇒ 403", async () => {
  await withRelay({}, async (relay) => {
    const { roomId } = auth();
    const res = await raw({
      url: relay.url,
      method: "GET",
      token: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      roomId,
    });
    assert.equal(res.status, 403);
  });
});

test("valid token but wrong roomId ⇒ 403", async () => {
  await withRelay({}, async (relay) => {
    const { token } = auth();
    const otherRoom = "bbbbbbbbbbbbbbbbbbbbbb";
    const res = await raw({ url: relay.url, method: "GET", token, roomId: otherRoom });
    assert.equal(res.status, 403);
  });
});

test("missing or blank auth ⇒ 401", async () => {
  await withRelay({}, async (relay) => {
    const { roomId } = auth();
    const missing = await raw({ url: relay.url, method: "GET", roomId });
    assert.equal(missing.status, 401);
    const blank = await raw({
      url: relay.url,
      method: "GET",
      roomId,
      headers: { authorization: "Bearer " },
    });
    assert.equal(blank.status, 401);
  });
});

test("oversized body ⇒ 413", async () => {
  await withRelay({ maxBodyBytes: 64 }, async (relay) => {
    const { token, roomId } = auth();
    const name = blobFilename(generateHostId(), 1);
    const body = Buffer.alloc(65, 7);
    const res = await raw({ url: relay.url, method: "PUT", token, roomId, name, body });
    assert.equal(res.status, 413);
  });
});

test("bad :name (traversal / wrong pattern) ⇒ 400", async () => {
  await withRelay({}, async (relay) => {
    const { token, roomId } = auth();
    const u = new URL(relay.url);
    async function putPath(p, body = "x") {
      const payload = Buffer.from(body);
      return new Promise((resolve, reject) => {
        const req = http.request(
          {
            hostname: u.hostname,
            port: u.port,
            path: p,
            method: "PUT",
            headers: {
              authorization: `Bearer ${token}`,
              "content-length": String(payload.length),
              "content-type": "application/octet-stream",
            },
          },
          (r) => {
            r.resume();
            r.on("end", () => resolve({ status: r.statusCode }));
          },
        );
        req.on("error", reject);
        req.write(payload);
        req.end();
      });
    }
    assert.equal((await putPath(`/rooms/${roomId}/blobs/../secret.csync`)).status, 400);
    assert.equal((await putPath(`/rooms/${roomId}/blobs/not-a-blob.txt`)).status, 400);
    assert.equal((await putPath(`/rooms/${roomId}/blobs/${encodeURIComponent("chromesync-../1.csync")}`)).status, 400);
  });
});

test("bad :roomId (not 22 base64url) ⇒ 400", async () => {
  await withRelay({}, async (relay) => {
    const { token } = auth();
    const short = await raw({ url: relay.url, method: "GET", token, roomId: "short" });
    assert.equal(short.status, 400);
    const weird = await raw({ url: relay.url, method: "GET", token, roomId: "not valid room id!!!!" });
    assert.equal(weird.status, 400);
  });
});

test("rate limit ⇒ 429", async () => {
  await withRelay({ rateIpCapacity: 1, rateIpRefillPerSec: 0, rateRoomCapacity: 10_000 }, async (relay) => {
    const { token, roomId } = auth();
    const first = await raw({ url: relay.url, method: "GET", token, roomId });
    assert.equal(first.status, 200);
    const second = await raw({ url: relay.url, method: "GET", token, roomId });
    assert.equal(second.status, 429);
  });
});

test("unauthenticated / bad-auth request does not create a per-room rate-limit bucket", async () => {
  const roomLimiter = new TokenBucket({ capacity: 10_000, refillPerSec: 1 });
  await withRelay({ roomLimiter }, async (relay) => {
    const { token, roomId } = auth();
    const missing = await raw({ url: relay.url, method: "GET", roomId });
    assert.equal(missing.status, 401);
    assert.equal(roomLimiter.buckets.size, 0);

    const forged = await raw({
      url: relay.url,
      method: "GET",
      token: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      roomId,
    });
    assert.equal(forged.status, 403);
    assert.equal(roomLimiter.buckets.size, 0);

    const ok = await raw({ url: relay.url, method: "GET", token, roomId });
    assert.equal(ok.status, 200);
    assert.equal(roomLimiter.buckets.size, 1);
  });
});

test("TRUST_PROXY uses the rightmost X-Forwarded-For hop, not the client-controlled leftmost", async () => {
  await withRelay(
    { trustProxy: true, rateIpCapacity: 1, rateIpRefillPerSec: 0, rateRoomCapacity: 10_000 },
    async (relay) => {
      const { token, roomId } = auth();
      const first = await raw({
        url: relay.url,
        method: "GET",
        token,
        roomId,
        headers: { "x-forwarded-for": "1.1.1.1, 10.0.0.9" },
      });
      assert.equal(first.status, 200);
      const spoofedLeft = await raw({
        url: relay.url,
        method: "GET",
        token,
        roomId,
        headers: { "x-forwarded-for": "9.9.9.9, 10.0.0.9" },
      });
      assert.equal(spoofedLeft.status, 429);
    },
  );
});

test("per-host retention prunes the oldest when over K", async () => {
  await withRelay({ retentionPerHost: 2 }, async (relay) => {
    const { token, roomId } = auth();
    const hostId = generateHostId();
    for (const n of [1, 2, 3]) {
      const name = blobFilename(hostId, n);
      const put = await raw({ url: relay.url, method: "PUT", token, roomId, name, body: Buffer.from(`blob-${n}`) });
      assert.equal(put.status, 204);
    }
    const list = await raw({ url: relay.url, method: "GET", token, roomId });
    const items = JSON.parse(list.body.toString("utf8"));
    const names = items.map((i) => i.name).sort();
    assert.deepEqual(names, [blobFilename(hostId, 2), blobFilename(hostId, 3)].sort());
    const gone = await raw({ url: relay.url, method: "GET", token, roomId, name: blobFilename(hostId, 1) });
    assert.equal(gone.status, 404);
  });
});

test("TTL sweep removes an aged blob", async () => {
  await withRelay({ blobTtlMs: 1_000 }, async (relay) => {
    const { token, roomId } = auth();
    const name = blobFilename(generateHostId(), 1);
    const put = await raw({ url: relay.url, method: "PUT", token, roomId, name, body: Buffer.from("aged") });
    assert.equal(put.status, 204);
    const fp = path.join(relay.store.dataDir, roomId, name);
    const old = Date.now() / 1000 - 10;
    fs.utimesSync(fp, old, old);
    const removed = relay.sweep();
    assert.ok(removed >= 1);
    const list = await raw({ url: relay.url, method: "GET", token, roomId });
    assert.deepEqual(JSON.parse(list.body.toString("utf8")), []);
  });
});

test("sweep removes a stale .csync.tmp leftover and leaves a fresh in-flight tmp", async () => {
  await withRelay({ blobTtlMs: 0 }, async (relay) => {
    const { token, roomId } = auth();
    const name = blobFilename(generateHostId(), 1);
    const uploaded = Buffer.from("keep-me");
    const put = await raw({ url: relay.url, method: "PUT", token, roomId, name, body: uploaded });
    assert.equal(put.status, 204);

    const dir = path.join(relay.store.dataDir, roomId);
    const stale = path.join(dir, `${name}.tmp`);
    fs.writeFileSync(stale, "orphan-tmp");
    const staleAgeSec = (STALE_TMP_MS / 1000) * 2;
    const old = Date.now() / 1000 - staleAgeSec;
    fs.utimesSync(stale, old, old);

    const fresh = path.join(dir, "chromesync-abc123-99.csync.tmp");
    fs.writeFileSync(fresh, "in-flight");

    const removed = relay.sweep();
    assert.ok(removed >= 1);
    assert.equal(fs.existsSync(stale), false);
    assert.equal(fs.existsSync(fresh), true);
    assert.equal(fs.readFileSync(path.join(dir, name)).equals(uploaded), true);
  });
});

test("DELETE ⇒ 204 and the blob is gone", async () => {
  await withRelay({}, async (relay) => {
    const { token, roomId } = auth();
    const name = blobFilename(generateHostId(), 1);
    assert.equal((await raw({ url: relay.url, method: "PUT", token, roomId, name, body: Buffer.from("x") })).status, 204);
    const del = await raw({ url: relay.url, method: "DELETE", token, roomId, name });
    assert.equal(del.status, 204);
    const got = await raw({ url: relay.url, method: "GET", token, roomId, name });
    assert.equal(got.status, 404);
  });
});

test("unknown method ⇒ 405; unknown path ⇒ 404", async () => {
  await withRelay({}, async (relay) => {
    const { token, roomId } = auth();
    const patch = await raw({ url: relay.url, method: "PATCH", token, roomId });
    assert.equal(patch.status, 405);
    const u = new URL(relay.url);
    const missing = await new Promise((resolve, reject) => {
      const req = http.request(
        { hostname: u.hostname, port: u.port, path: "/nope", method: "GET" },
        (r) => {
          r.resume();
          r.on("end", () => resolve({ status: r.statusCode }));
        },
      );
      req.on("error", reject);
      req.end();
    });
    assert.equal(missing.status, 404);
  });
});

test('filesystem room listing selects oldest files before applying the cap', async t => {
  const { createStore } = await import('../server/store.js');
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'chromesync-list-order-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const { roomId } = auth();
  fs.mkdirSync(path.join(root, roomId), { recursive: true });
  const names = ['chromesync-aa-1.csync', 'chromesync-bb-1.csync', 'chromesync-cc-1.csync'];
  names.forEach((name, i) => { const file = path.join(root, roomId, name); fs.writeFileSync(file, 'synthetic'); fs.utimesSync(file, 30 - i, 30 - i); });
  const store = createStore({ dataDir: root, maxBlobsPerRoom: 2 });
  assert.deepEqual(store.list(roomId).map(r => r.name), [names[2], names[1]]);
});
