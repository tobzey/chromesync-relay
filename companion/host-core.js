// Host core: launch/attach a target Chrome with a dedicated user-data-dir and
// remote debugging port, then apply cookies over CDP. Kept separate from the
// stdio transport so it can be exercised directly in the E2E test.
//
// SECURITY: Chrome is launched with a FIXED set of arguments. Nothing from the
// extension message is passed as a shell command; userDataDir/port are the only
// caller-controlled values and are passed as argv (no shell). Cookie values are
// never logged.

import { spawn } from "node:child_process";
import { setTimeout as delay } from "node:timers/promises";
import net from "node:net";
import fsDefault from "node:fs";
import { CdpClient } from "./cdp.js";

const DEFAULT_CHROME_CANDIDATES = [
  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
  "/Applications/Google Chrome Dev.app/Contents/MacOS/Google Chrome Dev",
  "/usr/bin/google-chrome",
  "/usr/bin/google-chrome-stable",
  "/usr/bin/chromium",
  "/usr/bin/chromium-browser",
];

export function resolveChromePath(env = process.env, fs = fsDefault) {
  if (env.CHROMESYNC_CHROME && fs.existsSync(env.CHROMESYNC_CHROME)) return env.CHROMESYNC_CHROME;
  for (const p of DEFAULT_CHROME_CANDIDATES) {
    try {
      if (fs.existsSync(p)) return p;
    } catch {}
  }
  return null;
}

async function findFreePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.listen(0, "127.0.0.1", () => {
      const { port } = srv.address();
      srv.close(() => resolve(port));
    });
    srv.on("error", reject);
  });
}

async function waitForDebugger(port, timeoutMs = 15000) {
  const deadline = Date.now() + timeoutMs;
  let lastErr;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(`http://127.0.0.1:${port}/json/version`, { signal: AbortSignal.timeout(2000) });
      if (res.ok) return await res.json();
    } catch (e) {
      lastErr = e;
    }
    await delay(200);
  }
  throw new Error("timed out waiting for Chrome debugger" + (lastErr ? "" : ""));
}

/**
 * Launch a throwaway/target Chrome. Returns { proc, port, wsUrl }.
 */
export async function launchChrome({ userDataDir, port, chromePath, extraArgs = [] } = {}) {
  const bin = chromePath || resolveChromePath();
  if (!bin) throw new Error("Chrome binary not found (set CHROMESYNC_CHROME)");
  if (!userDataDir) throw new Error("userDataDir required");
  const usePort = port && port > 0 ? port : await findFreePort();

  const args = [
    `--user-data-dir=${userDataDir}`,
    `--remote-debugging-port=${usePort}`,
    "--remote-debugging-address=127.0.0.1",
    "--no-first-run",
    "--no-default-browser-check",
    "--headless=new",
    "--disable-gpu",
    ...extraArgs,
  ];

  const proc = spawn(bin, args, { stdio: "ignore" });
  proc.on("error", () => {});
  const version = await waitForDebugger(usePort);
  return { proc, port: usePort, wsUrl: version.webSocketDebuggerUrl };
}

/**
 * Apply cookies to a running Chrome via CDP. cookies are CDP CookieParam shape.
 * Returns { written, skipped, errors } — never cookie values.
 */
export async function applyCookies(wsUrl, cookies) {
  // Storage.setCookies works on the browser-level CDP endpoint (unlike
  // Network.setCookie, which needs an attached page target). One cookie per call
  // so a single bad cookie is counted as skipped instead of failing the batch.
  const client = await CdpClient.connect(wsUrl);
  let written = 0;
  let skipped = 0;
  const errors = [];
  try {
    for (const c of cookies) {
      try {
        await client.send("Storage.setCookies", { cookies: [c] });
        written++;
      } catch (e) {
        skipped++;
        errors.push(genericError(e));
      }
    }
  } finally {
    client.close();
  }
  return { written, skipped, errors };
}

/** Read back cookies (names + domains only) for verification in tests. */
export async function readCookies(wsUrl) {
  const client = await CdpClient.connect(wsUrl);
  try {
    const res = await client.send("Storage.getCookies", {});
    return (res.cookies || []).map((c) => ({ name: c.name, domain: c.domain, path: c.path }));
  } finally {
    client.close();
  }
}

/**
 * Attach to an already-running Chrome with remote debugging enabled.
 * Returns { proc: null, port, wsUrl } or throws.
 */
export async function attachChrome({ port } = {}) {
  if (!port || port <= 0) throw new Error("port required for attach");
  const version = await waitForDebugger(port, 2500);
  return { proc: null, port, wsUrl: version.webSocketDebuggerUrl };
}

/** Full operation used by the host: attach if possible, else launch, apply, close. */
export async function setCookiesOp({ userDataDir, port, cookies, chromePath, keepOpen = false }) {
  let proc = null;
  let wsUrl;
  let usedPort;
  if (port && port > 0) {
    try {
      ({ proc, wsUrl, port: usedPort } = await attachChrome({ port }));
    } catch {
      // Port configured but nothing listening — fall through to launch.
    }
  }
  if (!wsUrl) {
    ({ proc, wsUrl, port: usedPort } = await launchChrome({ userDataDir, port, chromePath }));
  }
  try {
    const result = await applyCookies(wsUrl, cookies);
    return { ok: true, port: usedPort, wsUrl, ...result };
  } finally {
    if (proc && !keepOpen) {
      try {
        proc.kill();
      } catch {}
    }
  }
}

function genericError(e) {
  return e && e.message ? String(e.message) : "unknown error";
}
