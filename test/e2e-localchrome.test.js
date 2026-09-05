// Sink B end-to-end: launch a THROWAWAY Chrome with a temp --user-data-dir and
// remote debugging port, inject synthetic cookies over CDP, and read them back.
// Zero real login, dummy domains only. Skips (does not fail) if no Chrome is
// installed on the machine.

import { test } from "node:test";
import assert from "node:assert/strict";
import os from "node:os";
import fs from "node:fs";
import path from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { resolveChromePath, setCookiesOp, readCookies, launchChrome, applyCookies } from "../companion/host-core.js";
import { mapCookies } from "../src/cookies.js";
import { syntheticCookies } from "./fixtures.js";

const chrome = resolveChromePath();

// Chrome flushes profile files during shutdown, so a naive rmSync races it.
// Wait for exit, then retry the removal a few times.
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

test("injects synthetic cookies into a temp Chrome and reads them back", { skip: chrome ? false : "no Chrome installed" }, async () => {
  const userDataDir = fs.mkdtempSync(path.join(os.tmpdir(), "chromesync-e2e-"));
  const { cookies } = mapCookies(syntheticCookies);

  // Launch once, keep open, apply + verify against the same instance.
  const { proc, wsUrl } = await launchChrome({ userDataDir });
  try {
    const result = await applyCookies(wsUrl, cookies);
    assert.ok(result.written > 0, "expected at least one cookie written");

    const present = await readCookies(wsUrl);
    const names = new Set(present.map((c) => c.name));
    assert.ok(names.has("session_id"), "session_id cookie should be present");
    assert.ok(names.has("__Host-token"), "__Host-token cookie should be present");

    // Read-back must expose names/domains only (no values) from our helper.
    assert.equal(present.every((c) => !("value" in c)), true);
  } finally {
    await cleanup(proc, userDataDir);
  }
});

test("setCookiesOp launches, applies, and tears down its own Chrome", { skip: chrome ? false : "no Chrome installed" }, async () => {
  const userDataDir = fs.mkdtempSync(path.join(os.tmpdir(), "chromesync-e2e-"));
  const { cookies } = mapCookies(syntheticCookies);
  try {
    const res = await setCookiesOp({ userDataDir, cookies });
    assert.equal(res.ok, true);
    assert.ok(res.written > 0);
  } finally {
    await cleanup(null, userDataDir);
  }
});
