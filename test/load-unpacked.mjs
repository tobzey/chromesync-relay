// Load-unpacked verification: start Chrome with --load-extension pointing at the
// repo, then query CDP Targets for our service worker to confirm Chrome accepted
// the manifest and started the MV3 background worker. Standalone (not part of the
// node --test suite) because it needs a persistent profile + extension loading.

import os from "node:os";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { setTimeout as delay } from "node:timers/promises";
import { resolveChromePath } from "../companion/host-core.js";

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));

if (!resolveChromePath()) {
  console.log("SKIP: no Chrome installed");
  process.exit(0);
}

const userDataDir = fs.mkdtempSync(path.join(os.tmpdir(), "chromesync-load-"));
let proc;
try {
  // --load-extension is ignored under --headless=new, so launch headed-but-offscreen.
  ({ proc } = await bespokeLaunch());

  const port = proc.__debugPort;
  let found = null;
  for (let i = 0; i < 25; i++) {
    const targets = await fetch(`http://127.0.0.1:${port}/json`).then((r) => r.json()).catch(() => []);
    found = targets.find((t) => t.type === "service_worker" && t.url.startsWith("chrome-extension://"));
    if (found) break;
    await delay(300);
  }

  if (found) {
    const id = found.url.split("/")[2];
    console.log(`PASS: extension loaded unpacked; service worker running (extension id ${id})`);
    process.exitCode = 0;
  } else {
    console.log("FAIL: no extension service worker target appeared");
    process.exitCode = 1;
  }
} finally {
  try {
    proc && proc.kill();
  } catch {}
  await delay(500);
  fs.rmSync(userDataDir, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 });
}

async function bespokeLaunch() {
  const { spawn } = await import("node:child_process");
  const net = await import("node:net");
  const bin = resolveChromePath();
  const port = await new Promise((res) => {
    const s = net.createServer();
    s.listen(0, "127.0.0.1", () => {
      const p = s.address().port;
      s.close(() => res(p));
    });
  });
  const p = spawn(bin, [
    `--user-data-dir=${userDataDir}`,
    `--remote-debugging-port=${port}`,
    "--remote-debugging-address=127.0.0.1",
    "--no-first-run",
    "--no-default-browser-check",
    `--load-extension=${root}`,
    `--disable-extensions-except=${root}`,
    "--window-position=-2400,-2400",
  ], { stdio: "ignore" });
  p.__debugPort = port;
  // Wait for debugger.
  for (let i = 0; i < 50; i++) {
    try {
      const r = await fetch(`http://127.0.0.1:${port}/json/version`);
      if (r.ok) break;
    } catch {}
    await delay(200);
  }
  return { proc: p };
}
