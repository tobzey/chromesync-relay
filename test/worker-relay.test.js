// Worker relay conformance: PUT→list→GET, auth/path negatives, quota,
// retention, TTL, DELETE. In-memory R2 stub; no network.

import { test } from "node:test";
import assert from "node:assert/strict";
import { createHandler } from "../worker/index.js";
import { blobKey } from "../worker/store.js";
import { TokenBucket } from "../server/ratelimit.js";
import { deriveRelayAuth, clearRelayAuthCache } from "../companion/relay-auth.js";
import { blobFilename, generateHostId } from "../companion/drop-store.js";
import { MemoryR2Bucket } from "./r2-stub.js";

const SECRET = "test-pairing-secret-not-real";

function auth() {
  clearRelayAuthCache();
  return deriveRelayAuth(SECRET);
}

function bytesEqual(a, b) {
  const aa = a instanceof Uint8Array ? a : new Uint8Array(a);
  const bb = b instanceof Uint8Array ? b : new Uint8Array(b);
  if (aa.byteLength !== bb.byteLength) return false;
  for (let i = 0; i < aa.byteLength; i++) if (aa[i] !== bb[i]) return false;
  return true;
}

function asText(body) {
  return new TextDecoder().decode(body);
}

async function call(handler, { method, path, token, body, headers } = {}) {
  const h = new Headers(headers);
  if (token) h.set("authorization", `Bearer ${token}`);
  const init = { method: method || "GET", headers: h };
  if (body != null && init.method !== "GET" && init.method !== "HEAD") {
    init.body = body;
  }
  const response = await handler(new Request(`https://relay.test${path}`, init));
  const buf = new Uint8Array(await response.arrayBuffer());
  return { status: response.status, body: buf, headers: response.headers };
}

function withHandler(extra, fn) {
  const bucket = extra.bucket || new MemoryR2Bucket();
  const handler = createHandler({
    config: { allowedRooms: [deriveRelayAuth(SECRET).roomId],
      rateIpCapacity: 10_000,
      rateRoomCapacity: 10_000,
      ...(extra.config || {}),
    },
    ipLimiter: extra.ipLimiter,
    roomLimiter: extra.roomLimiter,
    log: extra.log || (() => {}),
    bucket,
  });
  return fn(handler, bucket);
}

test("PUT → list → GET preserves bytes; stub matches upload; no pairing-secret leak", async () => {
  await withHandler({}, async (handler, bucket) => {
    const { token, roomId } = auth();
    const hostId = generateHostId();
    const name = blobFilename(hostId, 1);
    const uploaded = new TextEncoder().encode("CSYNC-opaque-fixture-not-cookies");
    const putRes = await call(handler, {
      method: "PUT",
      path: `/rooms/${roomId}/blobs/${name}`,
      token,
      body: uploaded,
    });
    assert.equal(putRes.status, 204);
    assert.equal(putRes.headers.get("x-content-type-options"), "nosniff");

    const listRes = await call(handler, { method: "GET", path: `/rooms/${roomId}/blobs`, token });
    assert.equal(listRes.status, 200);
    assert.equal(listRes.headers.get("content-type"), "application/json");
    const items = JSON.parse(asText(listRes.body));
    assert.equal(items.length, 1);
    assert.equal(items[0].name, name);
    assert.equal(items[0].size, uploaded.byteLength);
    assert.equal(typeof items[0].mtime, "number");

    const got = await call(handler, { method: "GET", path: `/rooms/${roomId}/blobs/${name}`, token });
    assert.equal(got.status, 200);
    assert.equal(got.headers.get("content-type"), "application/octet-stream");
    assert.equal(bytesEqual(got.body, uploaded), true);

    const stored = bucket.objects.get(blobKey(roomId, name));
    assert.ok(stored);
    assert.equal(bytesEqual(stored.bytes, uploaded), true);
    const storedText = asText(stored.bytes);
    assert.equal(storedText.includes(SECRET), false, "pairing secret leaked into stored bytes");
  });
});

test("wrong token ⇒ 403", async () => {
  await withHandler({}, async (handler) => {
    const { roomId } = auth();
    const res = await call(handler, {
      method: "GET",
      path: `/rooms/${roomId}/blobs`,
      token: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    });
    assert.equal(res.status, 403);
    assert.equal(asText(res.body), "forbidden");
    assert.equal(res.headers.get("x-content-type-options"), "nosniff");
  });
});

test("valid token but wrong roomId ⇒ 403", async () => {
  await withHandler({}, async (handler) => {
    const { token } = auth();
    const res = await call(handler, {
      method: "GET",
      path: `/rooms/bbbbbbbbbbbbbbbbbbbbbb/blobs`,
      token,
    });
    assert.equal(res.status, 403);
  });
});

test("missing or blank auth ⇒ 401", async () => {
  await withHandler({}, async (handler) => {
    const { roomId } = auth();
    const missing = await call(handler, { method: "GET", path: `/rooms/${roomId}/blobs` });
    assert.equal(missing.status, 401);
    const blank = await call(handler, {
      method: "GET",
      path: `/rooms/${roomId}/blobs`,
      headers: { authorization: "Bearer " },
    });
    assert.equal(blank.status, 401);
    assert.equal(asText(blank.body), "unauthorized");
  });
});

test("oversized body ⇒ 413 via Content-Length and via actual bytes", async () => {
  await withHandler({ config: { maxBodyBytes: 64 } }, async (handler) => {
    const { token, roomId } = auth();
    const name = blobFilename(generateHostId(), 1);

    const cl = await call(handler, {
      method: "PUT",
      path: `/rooms/${roomId}/blobs/${name}`,
      token,
      headers: { "content-length": "65" },
    });
    assert.equal(cl.status, 413);
    assert.equal(asText(cl.body), "payload too large");

    const actual = await call(handler, {
      method: "PUT",
      path: `/rooms/${roomId}/blobs/${name}`,
      token,
      body: new Uint8Array(65).fill(7),
    });
    assert.equal(actual.status, 413);

    // Understated Content-Length still 413 after the body is read.
    let cancelled = false;
    const fake = {
      method: "PUT",
      url: `https://relay.test/rooms/${roomId}/blobs/${name}`,
      headers: {
        get(k) {
          const key = String(k).toLowerCase();
          if (key === "authorization") return `Bearer ${token}`;
          if (key === "content-length") return "10";
          return null;
        },
      },
      body: new ReadableStream({
        start(controller) {
          controller.enqueue(new Uint8Array(32).fill(7));
          controller.enqueue(new Uint8Array(33).fill(7));
        },
        cancel() { cancelled = true; },
      }),
    };
    const understated = await handler(fake);
    assert.equal(understated.status, 413);
    assert.equal(cancelled, true, 'oversized streams are cancelled without reading the rest');
  });
});

test("bad :name (wrong pattern / percent-encoded traversal) ⇒ 400; raw ../ is 400 or 404", async () => {
  await withHandler({}, async (handler) => {
    const { token, roomId } = auth();
    const txt = await call(handler, {
      method: "PUT",
      path: `/rooms/${roomId}/blobs/not-a-blob.txt`,
      token,
      body: new Uint8Array([1]),
    });
    assert.equal(txt.status, 400);

    const encoded = await call(handler, {
      method: "PUT",
      path: `/rooms/${roomId}/blobs/${encodeURIComponent("chromesync-../1.csync")}`,
      token,
      body: new Uint8Array([1]),
    });
    assert.equal(encoded.status, 400);

    const raw = await call(handler, {
      method: "PUT",
      path: `/rooms/${roomId}/blobs/../secret.csync`,
      token,
      body: new Uint8Array([1]),
    });
    assert.ok(raw.status === 400 || raw.status === 404, `raw ../ expected 400 or 404, got ${raw.status}`);
  });
});

test("bad :roomId (not 22 base64url) ⇒ 400", async () => {
  await withHandler({}, async (handler) => {
    const { token } = auth();
    const short = await call(handler, { method: "GET", path: "/rooms/short/blobs", token });
    assert.equal(short.status, 400);
    const weird = await call(handler, {
      method: "GET",
      path: "/rooms/not%20valid%20room%20id!!!!/blobs",
      token,
    });
    assert.equal(weird.status, 400);
  });
});

test("rate limit ⇒ 429 + Retry-After", async () => {
  await withHandler(
    { config: { rateIpCapacity: 1, rateIpRefillPerSec: 0, rateRoomCapacity: 10_000 } },
    async (handler) => {
      const { token, roomId } = auth();
      const first = await call(handler, { method: "GET", path: `/rooms/${roomId}/blobs`, token });
      assert.equal(first.status, 200);
      const second = await call(handler, { method: "GET", path: `/rooms/${roomId}/blobs`, token });
      assert.equal(second.status, 429);
      assert.equal(second.headers.get("retry-after"), "1");
      assert.equal(asText(second.body), "too many requests");
    },
  );
});

test("unauthenticated / bad-auth request does not create a per-room rate-limit bucket", async () => {
  const roomLimiter = new TokenBucket({ capacity: 10_000, refillPerSec: 1 });
  await withHandler({ roomLimiter }, async (handler) => {
    const { token, roomId } = auth();
    const missing = await call(handler, { method: "GET", path: `/rooms/${roomId}/blobs` });
    assert.equal(missing.status, 401);
    assert.equal(roomLimiter.buckets.size, 0);

    const forged = await call(handler, {
      method: "GET",
      path: `/rooms/${roomId}/blobs`,
      token: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    });
    assert.equal(forged.status, 403);
    assert.equal(roomLimiter.buckets.size, 0);

    const ok = await call(handler, { method: "GET", path: `/rooms/${roomId}/blobs`, token });
    assert.equal(ok.status, 200);
    assert.equal(roomLimiter.buckets.size, 1);
  });
});

test("per-host retention prunes the oldest when over K", async () => {
  await withHandler({ config: { retentionPerHost: 2 } }, async (handler) => {
    const { token, roomId } = auth();
    const hostId = generateHostId();
    for (const n of [1, 2, 3]) {
      const name = blobFilename(hostId, n);
      const putRes = await call(handler, {
        method: "PUT",
        path: `/rooms/${roomId}/blobs/${name}`,
        token,
        body: new TextEncoder().encode(`blob-${n}`),
      });
      assert.equal(putRes.status, 204);
    }
    const listRes = await call(handler, { method: "GET", path: `/rooms/${roomId}/blobs`, token });
    const items = JSON.parse(asText(listRes.body));
    const names = items.map((i) => i.name).sort();
    assert.deepEqual(names, [blobFilename(hostId, 2), blobFilename(hostId, 3)].sort());
    const gone = await call(handler, {
      method: "GET",
      path: `/rooms/${roomId}/blobs/${blobFilename(hostId, 1)}`,
      token,
    });
    assert.equal(gone.status, 404);
  });
});

test("quota ⇒ 507 and the overflowing object is gone from the stub", async () => {
  await withHandler({ config: { maxBlobsPerRoom: 1, retentionPerHost: 10 } }, async (handler, bucket) => {
    const { token, roomId } = auth();
    const a = blobFilename(generateHostId(), 1);
    const b = blobFilename(generateHostId(), 1);
    assert.equal(
      (
        await call(handler, {
          method: "PUT",
          path: `/rooms/${roomId}/blobs/${a}`,
          token,
          body: new TextEncoder().encode("keep"),
        })
      ).status,
      204,
    );
    const overflow = await call(handler, {
      method: "PUT",
      path: `/rooms/${roomId}/blobs/${b}`,
      token,
      body: new TextEncoder().encode("too-many"),
    });
    assert.equal(overflow.status, 507);
    assert.equal(asText(overflow.body), "insufficient storage");
    assert.equal(bucket.objects.has(blobKey(roomId, b)), false);
    assert.equal(bucket.objects.has(blobKey(roomId, a)), true);
  });
});

test("TTL: expired expiresAt → GET 404, list omits, object lazily deleted", async () => {
  await withHandler({ config: { blobTtlMs: 60_000 } }, async (handler, bucket) => {
    const { token, roomId } = auth();
    const name = blobFilename(generateHostId(), 1);
    const putRes = await call(handler, {
      method: "PUT",
      path: `/rooms/${roomId}/blobs/${name}`,
      token,
      body: new TextEncoder().encode("aged"),
    });
    assert.equal(putRes.status, 204);
    const obj = bucket.objects.get(blobKey(roomId, name));
    assert.ok(obj);
    obj.customMetadata.expiresAt = String(Date.now() - 1);

    const got = await call(handler, { method: "GET", path: `/rooms/${roomId}/blobs/${name}`, token });
    assert.equal(got.status, 404);
    assert.equal(bucket.objects.has(blobKey(roomId, name)), false);

    const listed = await call(handler, { method: "GET", path: `/rooms/${roomId}/blobs`, token });
    assert.deepEqual(JSON.parse(asText(listed.body)), []);
  });
});

test("list omits expired blobs even before GET", async () => {
  await withHandler({ config: { blobTtlMs: 60_000 } }, async (handler, bucket) => {
    const { token, roomId } = auth();
    const name = blobFilename(generateHostId(), 1);
    assert.equal(
      (
        await call(handler, {
          method: "PUT",
          path: `/rooms/${roomId}/blobs/${name}`,
          token,
          body: new TextEncoder().encode("aged"),
        })
      ).status,
      204,
    );
    bucket.objects.get(blobKey(roomId, name)).customMetadata.expiresAt = String(Date.now() - 1);
    const listed = await call(handler, { method: "GET", path: `/rooms/${roomId}/blobs`, token });
    assert.deepEqual(JSON.parse(asText(listed.body)), []);
    assert.equal(bucket.objects.has(blobKey(roomId, name)), false);
  });
});

test("DELETE ⇒ 204 then GET 404; DELETE of missing ⇒ 404", async () => {
  await withHandler({}, async (handler) => {
    const { token, roomId } = auth();
    const name = blobFilename(generateHostId(), 1);
    assert.equal(
      (
        await call(handler, {
          method: "PUT",
          path: `/rooms/${roomId}/blobs/${name}`,
          token,
          body: new TextEncoder().encode("x"),
        })
      ).status,
      204,
    );
    const delRes = await call(handler, { method: "DELETE", path: `/rooms/${roomId}/blobs/${name}`, token });
    assert.equal(delRes.status, 204);
    const got = await call(handler, { method: "GET", path: `/rooms/${roomId}/blobs/${name}`, token });
    assert.equal(got.status, 404);
    const missing = await call(handler, { method: "DELETE", path: `/rooms/${roomId}/blobs/${name}`, token });
    assert.equal(missing.status, 404);
  });
});

test("PATCH ⇒ 405 with Allow; /nope ⇒ 404", async () => {
  await withHandler({}, async (handler) => {
    const { token, roomId } = auth();
    const name = blobFilename(generateHostId(), 1);
    const collection = await call(handler, { method: "PATCH", path: `/rooms/${roomId}/blobs`, token });
    assert.equal(collection.status, 405);
    assert.equal(collection.headers.get("allow"), "GET");

    const item = await call(handler, { method: "PATCH", path: `/rooms/${roomId}/blobs/${name}`, token });
    assert.equal(item.status, 405);
    assert.equal(item.headers.get("allow"), "GET, PUT, DELETE");

    const nope = await call(handler, { method: "GET", path: "/nope" });
    assert.equal(nope.status, 404);
    assert.equal(asText(nope.body), "not found");
    assert.equal(nope.headers.get("x-content-type-options"), "nosniff");
  });
});

test("/health ⇒ 200 ok with no auth and with limiter exhausted", async () => {
  const ipLimiter = new TokenBucket({ capacity: 1, refillPerSec: 0 });
  await withHandler({ ipLimiter, config: { rateRoomCapacity: 10_000 } }, async (handler) => {
    const { token, roomId } = auth();
    const health = await call(handler, { method: "GET", path: "/health" });
    assert.equal(health.status, 200);
    assert.equal(asText(health.body), "ok");
    assert.equal(health.headers.get("content-type"), "text/plain");
    assert.equal(health.headers.get("x-content-type-options"), "nosniff");

    const first = await call(handler, { method: "GET", path: `/rooms/${roomId}/blobs`, token });
    assert.equal(first.status, 200);
    const limited = await call(handler, { method: "GET", path: `/rooms/${roomId}/blobs`, token });
    assert.equal(limited.status, 429);

    const still = await call(handler, { method: "GET", path: "/health" });
    assert.equal(still.status, 200);
    assert.equal(asText(still.body), "ok");
  });
});

test("unadmitted room is denied", async () => {
  await withHandler({}, async (handler) => {
    const { token, roomId } = auth();
    const listRes = await call(handler, { method: "GET", path: `/rooms/${roomId}/blobs`, token });
    assert.equal(listRes.status, 200);
    assert.deepEqual(JSON.parse(asText(listRes.body)), []);
  });
});

test('room listing selects oldest uploads before applying the cap', async () => {
  const { list } = await import('../worker/store.js');
  const bucket = new MemoryR2Bucket(), { roomId } = auth();
  const names = ['chromesync-aa-1.csync', 'chromesync-bb-1.csync', 'chromesync-cc-1.csync'];
  for (let i = 0; i < names.length; i++) { const key = blobKey(roomId, names[i]); await bucket.put(key, new Uint8Array([1])); bucket.objects.get(key).uploaded = new Date(3000 - i * 1000); }
  const result = await list(bucket, { maxBlobsPerRoom: 2 }, roomId, 4000);
  assert.deepEqual(result.items.map(r => r.name), [names[2], names[1]]);
});
