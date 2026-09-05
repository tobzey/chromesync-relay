// Drop-in compatibility: companion/relay-client.js against the Worker
// handler via a tiny node:http bridge. Offline; synthetic data only.

import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { createHandler } from "../worker/index.js";
import { MemoryR2Bucket } from "./r2-stub.js";
import { deriveRelayAuth, clearRelayAuthCache } from "../companion/relay-auth.js";
import { relayPush, relayList, relayGet, relayDelete, RelayClientError } from "../companion/relay-client.js";
import { blobFilename, generateHostId } from "../companion/drop-store.js";

const SECRET = "test-pairing-secret-not-real";

function startBridge(handler) {
  const server = http.createServer((req, res) => {
    Promise.resolve()
      .then(async () => {
        const chunks = [];
        for await (const c of req) chunks.push(c);
        const raw = Buffer.concat(chunks);
        const { port } = server.address();
        const headers = new Headers();
        for (const [k, v] of Object.entries(req.headers)) {
          if (k === "host" || v == null) continue;
          if (Array.isArray(v)) for (const item of v) headers.append(k, item);
          else headers.set(k, v);
        }
        const init = { method: req.method, headers };
        if (raw.length && req.method !== "GET" && req.method !== "HEAD") init.body = raw;
        const response = await handler(new Request(`http://127.0.0.1:${port}${req.url}`, init));
        const out = {};
        response.headers.forEach((value, key) => {
          out[key] = value;
        });
        const buf = Buffer.from(await response.arrayBuffer());
        res.writeHead(response.status, out);
        res.end(buf);
      })
      .catch(() => {
        if (!res.headersSent) res.writeHead(500);
        res.end();
      });
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      resolve({
        url: `http://127.0.0.1:${port}`,
        close: () => new Promise((r, j) => server.close((e) => (e ? j(e) : r()))),
      });
    });
  });
}

async function withBridge(fn) {
  const bucket = new MemoryR2Bucket();
  const handler = createHandler({
    config: { rateIpCapacity: 10_000, rateRoomCapacity: 10_000 },
    log: () => {},
    bucket,
  });
  const bridge = await startBridge(handler);
  try {
    await fn(bridge, bucket);
  } finally {
    await bridge.close();
  }
}

test("relayPush/list/get/delete round-trip through the Worker http bridge", async () => {
  await withBridge(async (bridge) => {
    clearRelayAuthCache();
    const { token, roomId } = deriveRelayAuth(SECRET);
    const name = blobFilename(generateHostId(), 1);
    const blob = Buffer.from("CSYNC-opaque-fixture-not-cookies");
    await relayPush({ relayUrl: bridge.url, token, roomId, name, blob });
    const listed = await relayList({ relayUrl: bridge.url, token, roomId });
    assert.equal(listed.length, 1);
    assert.equal(listed[0].name, name);
    const pulled = await relayGet({ relayUrl: bridge.url, token, roomId, name });
    assert.equal(pulled.equals(blob), true);
    await relayDelete({ relayUrl: bridge.url, token, roomId, name });
    await assert.rejects(
      () => relayGet({ relayUrl: bridge.url, token, roomId, name }),
      (e) => e instanceof RelayClientError && e.message === "not found" && e.status === 404,
    );
  });
});

test("404 → RelayClientError not found; 403 → wrong pairing code or server", async () => {
  await withBridge(async (bridge) => {
    clearRelayAuthCache();
    const { token, roomId } = deriveRelayAuth(SECRET);
    const name = blobFilename(generateHostId(), 1);
    await assert.rejects(
      () => relayGet({ relayUrl: bridge.url, token, roomId, name }),
      (e) => e instanceof RelayClientError && e.message === "not found" && e.status === 404,
    );
    await assert.rejects(
      () =>
        relayList({
          relayUrl: bridge.url,
          token: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
          roomId,
        }),
      (e) =>
        e instanceof RelayClientError && e.message === "wrong pairing code or server" && e.status === 403,
    );
  });
});
