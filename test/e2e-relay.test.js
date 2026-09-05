// Transport C end-to-end: push synthetic cookies through the real local relay,
// pull, inject into a throwaway Chrome. Skip (do not fail) when Chrome is not
// installed. Dummy domains only; no plaintext cookie files.

import { test } from "node:test";
import assert from "node:assert/strict";
import os from "node:os";
import fs from "node:fs";
import path from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { resolveChromePath, launchChrome, applyCookies, readCookies } from "../companion/host-core.js";
import { mapCookies } from "../src/cookies.js";
import { syntheticCookies } from "./fixtures.js";
import { handleNativeMessage } from "../companion/host-messages.js";
import { startRelay } from "../server/server.js";

const chrome = resolveChromePath();
const SECRET = "test-pairing-secret-not-real";

async function cleanup(proc, dir) {
  if (proc) {
    try {
      proc.kill();
    } catch {}
    await new Promise((r) => (proc.exitCode != null ? r() : proc.once("exit", r)));
  }
  for (let i = 0; i < 10; i++) {
    try {
      fs.rmSync(dir, { recursive: true, force: true });
      return;
    } catch {
      await delay(200);
    }
  }
}

function walkFiles(root) {
  const out = [];
  if (!fs.existsSync(root)) return out;
  const walk = (d) => {
    for (const n of fs.readdirSync(d)) {
      const p = path.join(d, n);
      const st = fs.statSync(p);
      if (st.isDirectory()) walk(p);
      else out.push(p);
    }
  };
  walk(root);
  return out;
}

test(
  "push → real server → pull → inject synthetic cookies via throwaway Chrome",
  { skip: chrome ? false : "no Chrome installed" },
  async () => {
    const userDataDir = fs.mkdtempSync(path.join(os.tmpdir(), "chromesync-relay-e2e-"));
    const tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), "chromesync-home-"));
    const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "chromesync-relay-"));
    const env = { HOME: tmpHome };
    const { cookies } = mapCookies(syntheticCookies);
    const relay = await startRelay({
      host: "127.0.0.1",
      port: 0,
      dataDir,
      sweepIntervalMs: 0,
      rateIpCapacity: 10_000,
      rateRoomCapacity: 10_000,
      log: () => {},
    });
    const { proc, wsUrl } = await launchChrome({ userDataDir });
    try {
      const cfg = {
        relayUrl: relay.url,
        pairingSecret: SECRET,
        sourceHostId: "",
        statePath: "",
      };
      const pushed = await handleNativeMessage(
        { type: "relayPush", ...cfg, cookies },
        { env },
      );
      assert.equal(pushed.ok, true, pushed.error);
      assert.ok(pushed.written > 0);

      for (const fp of walkFiles(dataDir)) {
        const raw = fs.readFileSync(fp);
        for (const c of syntheticCookies) {
          assert.equal(raw.includes(c.value), false, "plaintext cookie value on server disk");
        }
        assert.throws(() => {
          const parsed = JSON.parse(raw.toString("utf8"));
          if (Array.isArray(parsed)) throw new Error("plaintext json cookies");
        });
      }

      const pulled = await handleNativeMessage(
        { type: "relayPull", ...cfg },
        {
          env,
          inject: async (decrypted) => {
            assert.deepEqual(decrypted, cookies);
            return applyCookies(wsUrl, decrypted);
          },
        },
      );
      assert.equal(pulled.ok, true, (pulled.errors || []).join(", "));
      assert.equal(pulled.injected, true);
      assert.ok(pulled.written > 0);

      const present = await readCookies(wsUrl);
      const names = new Set(present.map((c) => c.name));
      assert.ok(names.has("session_id"), "session_id cookie should be present");
      assert.ok(names.has("__Host-token"), "__Host-token cookie should be present");
      assert.equal(present.every((c) => !("value" in c)), true);

      for (const fp of walkFiles(tmpHome)) {
        const text = fs.readFileSync(fp);
        for (const c of syntheticCookies) {
          assert.equal(text.includes(c.value), false, "plaintext cookie file in companion state");
        }
      }
    } finally {
      await cleanup(proc, userDataDir);
      await relay.close();
      fs.rmSync(tmpHome, { recursive: true, force: true });
      fs.rmSync(dataDir, { recursive: true, force: true });
    }
  },
);
