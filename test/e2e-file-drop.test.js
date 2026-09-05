// Transport A end-to-end: encrypt synthetic cookies into a fake drop store,
// decrypt, and inject through the existing throwaway-Chrome harness
// (launchChrome + applyCookies + readCookies). Skip (do not fail) when Chrome
// is not installed. Dummy domains only; no plaintext cookie files.

import { test } from "node:test";
import assert from "node:assert/strict";
import os from "node:os";
import fs from "node:fs";
import path from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { resolveChromePath, launchChrome, applyCookies, readCookies } from "../companion/host-core.js";
import { mapCookies } from "../src/cookies.js";
import { syntheticCookies } from "./fixtures.js";
import { generateHostId } from "../companion/drop-store.js";
import { emptyState, exportCookies, importBlob } from "../companion/drop.js";

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

test(
  "encrypt → decrypt → inject synthetic cookies via throwaway Chrome",
  { skip: chrome ? false : "no Chrome installed" },
  async () => {
    const userDataDir = fs.mkdtempSync(path.join(os.tmpdir(), "chromesync-drop-e2e-"));
    const dropDir = fs.mkdtempSync(path.join(os.tmpdir(), "chromesync-drop-store-"));
    const { cookies } = mapCookies(syntheticCookies);
    const sourceHostId = generateHostId();
    const { proc, wsUrl } = await launchChrome({ userDataDir });
    try {
      const exported = exportCookies({
        dropDir,
        secret: SECRET,
        sourceHostId,
        cookies,
        counter: 1,
      });
      const raw = fs.readFileSync(exported.path);
      for (const c of syntheticCookies) {
        assert.equal(raw.includes(c.value), false, "plaintext cookie value on disk");
      }

      const res = await importBlob({
        filePath: exported.path,
        sourceHostId,
        secret: SECRET,
        state: emptyState(),
        inject: async (decrypted) => {
          assert.deepEqual(decrypted, cookies);
          return applyCookies(wsUrl, decrypted);
        },
      });
      assert.equal(res.ok, true);
      assert.equal(res.injected, true);
      assert.ok(res.written > 0, "expected at least one cookie written");

      const present = await readCookies(wsUrl);
      const names = new Set(present.map((c) => c.name));
      assert.ok(names.has("session_id"), "session_id cookie should be present");
      assert.ok(names.has("__Host-token"), "__Host-token cookie should be present");
      assert.equal(present.every((c) => !("value" in c)), true);
    } finally {
      await cleanup(proc, userDataDir);
      fs.rmSync(dropDir, { recursive: true, force: true });
    }
  },
);

test(
  "wrong pairing secret does not inject into throwaway Chrome",
  { skip: chrome ? false : "no Chrome installed" },
  async () => {
    const userDataDir = fs.mkdtempSync(path.join(os.tmpdir(), "chromesync-drop-e2e-"));
    const dropDir = fs.mkdtempSync(path.join(os.tmpdir(), "chromesync-drop-store-"));
    const { cookies } = mapCookies(syntheticCookies);
    const sourceHostId = generateHostId();
    const { proc, wsUrl } = await launchChrome({ userDataDir });
    try {
      const exported = exportCookies({
        dropDir,
        secret: SECRET,
        sourceHostId,
        cookies,
        counter: 1,
      });
      let injectCalls = 0;
      const res = await importBlob({
        filePath: exported.path,
        sourceHostId,
        secret: "wrong-pairing-secret-not-real",
        state: emptyState(),
        inject: async (decrypted) => {
          injectCalls++;
          return applyCookies(wsUrl, decrypted);
        },
      });
      assert.equal(res.ok, false);
      assert.equal(res.injected, false);
      assert.equal(injectCalls, 0);

      const present = await readCookies(wsUrl);
      assert.equal(present.length, 0);
    } finally {
      await cleanup(proc, userDataDir);
      fs.rmSync(dropDir, { recursive: true, force: true });
    }
  },
);
