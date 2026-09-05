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
if (cmd === "import-drop") {
  const env = process.env;
  const res = await handleNativeMessage(
    {
      type: "importDrop",
      dropDir: env.CHROMESYNC_DROP_DIR,
      pairingSecret: env.CHROMESYNC_PAIRING_SECRET,
      userDataDir: env.CHROMESYNC_USER_DATA_DIR,
      port: Number(env.CHROMESYNC_PORT) || 0,
      statePath: env.CHROMESYNC_STATE_PATH || "",
      maxAgeMs: env.CHROMESYNC_MAX_AGE_MS ? Number(env.CHROMESYNC_MAX_AGE_MS) : undefined,
    },
    { env },
  );
  // Counts + generic errors only — never cookie values or the pairing secret.
  process.stdout.write(JSON.stringify({ ok: res.ok, imported: res.imported, written: res.written, skipped: res.skipped, errors: res.errors }) + "\n");
  process.exit(res.ok ? 0 : 1);
} else if (cmd === "relay-pull") {
  const env = process.env;
  const res = await handleNativeMessage(
    {
      type: "relayPull",
      relayUrl: env.CHROMESYNC_RELAY_URL,
      pairingSecret: env.CHROMESYNC_PAIRING_SECRET,
      userDataDir: env.CHROMESYNC_USER_DATA_DIR,
      port: Number(env.CHROMESYNC_PORT) || 0,
      statePath: env.CHROMESYNC_STATE_PATH || "",
      maxAgeMs: env.CHROMESYNC_MAX_AGE_MS ? Number(env.CHROMESYNC_MAX_AGE_MS) : undefined,
    },
    { env },
  );
  // Counts + generic errors only — never cookie values or the pairing secret.
  process.stdout.write(JSON.stringify({ ok: res.ok, imported: res.imported, written: res.written, skipped: res.skipped, errors: res.errors }) + "\n");
  process.exit(res.ok ? 0 : 1);
} else {
  readMessages(async (msg) => {
    const res = await handleNativeMessage(msg);
    writeMessage(res);
    // One-shot: exit after responding so we don't leak Chrome processes.
    process.exit(res.ok ? 0 : 1);
  });
}
