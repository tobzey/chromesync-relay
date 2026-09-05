// profile-use CLI wrap for Sink A. Gated: missing key / missing binary /
// old version / bad profile dir → disabled with a clear error, never throws.
// The CLI reads Chrome's on-disk cookie DB from --user-data-dir; we never pass
// the collected cookie array. API key is child-env only (never argv, never logged).

import { spawn, spawnSync } from "node:child_process";
import fsDefault from "node:fs";
import path from "node:path";

export const MIN_PROFILE_USE_VERSION = "1.0.5";
const BIN_NAME = "profile-use";

export function findOnPath(name, env = process.env, fs = fsDefault) {
  const pathEnv = env && typeof env.PATH === "string" ? env.PATH : "";
  const dirs = pathEnv.split(path.delimiter).filter(Boolean);
  for (const dir of dirs) {
    const candidate = path.join(dir, name);
    try {
      if (fs.existsSync(candidate)) {
        fs.accessSync(candidate, fs.constants.X_OK);
        return candidate;
      }
    } catch {
      // not executable or vanished
    }
  }
  return null;
}

export function parseSemver(text) {
  const m = String(text || "").match(/(\d+)\.(\d+)\.(\d+)/);
  if (!m) return null;
  return [Number(m[1]), Number(m[2]), Number(m[3])];
}

export function compareSemver(a, b) {
  for (let i = 0; i < 3; i++) {
    if (a[i] > b[i]) return 1;
    if (a[i] < b[i]) return -1;
  }
  return 0;
}

export function validateProfileDir(dir, fs = fsDefault) {
  if (!dir || typeof dir !== "string" || !dir.trim()) {
    return "profileUseDir not configured";
  }
  if (!path.isAbsolute(dir)) {
    return "profileUseDir must be an absolute path";
  }
  let st;
  try {
    st = fs.statSync(dir);
  } catch {
    return "profileUseDir not found";
  }
  if (!st.isDirectory()) return "profileUseDir must be a directory";
  return null;
}

/**
 * Enablement gate. Never throws. Does not run `profile-use sync`.
 * @returns {{ok: boolean, error?: string, bin?: string}}
 */
export function validateProfileUse(config, deps = {}) {
  const env = deps.env || process.env;
  const fs = deps.fs || fsDefault;
  const spawnSyncFn = deps.spawnSync || spawnSync;

  const key = env && typeof env.BROWSER_USE_API_KEY === "string" ? env.BROWSER_USE_API_KEY.trim() : "";
  if (!key) {
    return { ok: false, error: "BROWSER_USE_API_KEY is not set" };
  }

  const bin = findOnPath(BIN_NAME, env, fs);
  if (!bin) {
    return { ok: false, error: "profile-use not found on PATH" };
  }

  let out;
  try {
    out = spawnSyncFn(bin, ["--version"], {
      encoding: "utf8",
      timeout: 5000,
      env: versionEnv(env),
    });
  } catch {
    return { ok: false, error: "profile-use --version failed" };
  }
  if (!out || out.error || (out.status !== 0 && out.status != null)) {
    return { ok: false, error: "profile-use --version failed" };
  }

  const found = parseSemver(out.stdout || "");
  const min = parseSemver(MIN_PROFILE_USE_VERSION);
  if (!found) {
    return { ok: false, error: `profile-use >= ${MIN_PROFILE_USE_VERSION} required, found unknown` };
  }
  if (compareSemver(found, min) < 0) {
    return { ok: false, error: `profile-use >= ${MIN_PROFILE_USE_VERSION} required, found ${found[0]}.${found[1]}.${found[2]}` };
  }

  const dirErr = validateProfileDir(config && config.profileUseDir, fs);
  if (dirErr) return { ok: false, error: dirErr };

  return { ok: true, bin };
}

/**
 * Run `profile-use sync --user-data-dir <dir>`. Re-checks the gate first.
 * Returns counts + generic errors only — never cookie values, never the key,
 * never CLI stdout/stderr.
 */
export async function runProfileUseSync(config, deps = {}) {
  const env = deps.env || process.env;
  const spawnFn = deps.spawn || spawn;
  const gate = validateProfileUse(config, deps);
  if (!gate.ok) {
    return { written: 0, skipped: 0, errors: [gate.error] };
  }

  const key = env.BROWSER_USE_API_KEY;
  const childEnv = { ...process.env, ...env, BROWSER_USE_API_KEY: key };
  if (env.PATH && process.env.PATH && env.PATH !== process.env.PATH) {
    childEnv.PATH = env.PATH + path.delimiter + process.env.PATH;
  }

  const args = ["sync", "--user-data-dir", config.profileUseDir];
  return spawnSyncCommand(spawnFn, gate.bin, args, childEnv, deps.timeoutMs || 60000);
}

function versionEnv(env) {
  const out = { ...process.env };
  if (env && env.BROWSER_USE_API_KEY) out.BROWSER_USE_API_KEY = env.BROWSER_USE_API_KEY;
  return out;
}

function spawnSyncCommand(spawnFn, bin, args, env, timeoutMs) {
  return new Promise((resolve) => {
    let settled = false;
    const done = (result) => {
      if (settled) return;
      settled = true;
      resolve(result);
    };

    let child;
    try {
      child = spawnFn(bin, args, { env, stdio: ["ignore", "pipe", "pipe"] });
    } catch {
      done({ written: 0, skipped: 0, errors: ["profile-use failed"] });
      return;
    }

    // Drain and discard. CLI output must never be surfaced (may contain cookies).
    if (child.stdout) child.stdout.on("data", () => {});
    if (child.stderr) child.stderr.on("data", () => {});

    const t = setTimeout(() => {
      try {
        child.kill();
      } catch {}
    }, timeoutMs);

    child.on("error", () => {
      clearTimeout(t);
      done({ written: 0, skipped: 0, errors: ["profile-use failed"] });
    });
    child.on("close", (code) => {
      clearTimeout(t);
      if (code === 0) {
        done({ written: 0, skipped: 0, errors: [] });
      } else {
        done({ written: 0, skipped: 0, errors: ["profile-use failed"] });
      }
    });
  });
}
