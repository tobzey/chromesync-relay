#!/usr/bin/env node
// Native messaging host (stdio transport). Chrome frames each message with a
// 32-bit little-endian length prefix. This wrapper reads one request, runs it
// against host-messages, writes one response, and (for one-shot ops) exits.
//
// SECURITY: only known message types are handled; no arbitrary command
// execution; cookie values are never logged.

import { handleNativeMessage } from "./host-messages.js";

function writeMessage(obj) {
  const json = Buffer.from(JSON.stringify(obj), "utf8");
  const header = Buffer.alloc(4);
  header.writeUInt32LE(json.length, 0);
  process.stdout.write(header);
  process.stdout.write(json);
}

function readMessages(onMessage) {
  let buf = Buffer.alloc(0);
  process.stdin.on("data", (chunk) => {
    buf = Buffer.concat([buf, chunk]);
    while (buf.length >= 4) {
      const len = buf.readUInt32LE(0);
      if (len > 8 * 1024 * 1024) {
        writeMessage({ ok: false, error: 'native message too large' });
        process.exit(1);
      }
      if (buf.length < 4 + len) break;
      const body = buf.subarray(4, 4 + len);
      buf = buf.subarray(4 + len);
      let msg;
      try {
        msg = JSON.parse(body.toString("utf8"));
      } catch {
        writeMessage({ ok: false, error: "invalid JSON" });
        continue;
      }
      onMessage(msg);
    }
  });
}

const cmd = process.argv[2];
if (cmd === "import-drop" || cmd === "relay-pull") {
  process.stdout.write(JSON.stringify({ ok: false, error: 'Legacy shared-secret transport disabled; use terminal v2 pairing' }) + "\n");
  process.exit(1);
} else {
  readMessages(async (msg) => {
    const res = await handleNativeMessage(msg);
    writeMessage(res);
    // One-shot: exit after responding so we don't leak Chrome processes.
    process.exit(res.ok ? 0 : 1);
  });
}
