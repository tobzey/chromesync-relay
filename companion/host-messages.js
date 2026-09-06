// Native-host message handlers, extracted from the stdio wrapper so tests can
// exercise Options-shaped exportDrop/importDrop without attaching stdin.
// Cookie values are never logged.

import { setCookiesOp, launchChrome } from "./host-core.js";
import { validateProfileUse, runProfileUseSync } from "./profile-use.js";
import { terminalMessage } from "./terminal.js";

export async function handleNativeMessage(msg, deps = {}) {
  if (['dropValidate', 'exportDrop', 'importDrop', 'relayValidate', 'relayPush', 'relayPull'].includes(msg?.type)) {
    return { ok: false, written: 0, skipped: 0, errors: ['Legacy shared-secret transport disabled; use terminal v2 pairing'], error: 'Legacy shared-secret transport disabled; use terminal v2 pairing' };
  }

  try {
    switch (msg && msg.type) {
      case "terminalProfiles":
      case "terminalBind":
      case "terminalPush":
        return await terminalMessage(msg, deps.terminal || {});
      case "ping": {
        const { proc } = await launchChrome({ userDataDir: msg.userDataDir, port: msg.port });
        try {
          proc.kill();
        } catch {}
        return { ok: true };
      }
      case "setCookies": {
        const res = await setCookiesOp({
          userDataDir: msg.userDataDir,
          port: msg.port,
          cookies: Array.isArray(msg.cookies) ? msg.cookies : [],
        });
        return res;
      }
      case "profileUseValidate": {
        return validateProfileUse({ profileUseDir: msg.profileUseDir });
      }
      case "profileUseSync": {
        const res = await runProfileUseSync({ profileUseDir: msg.profileUseDir });
        if (res.errors && res.errors.length) {
          return { ok: false, written: res.written, skipped: res.skipped, errors: res.errors };
        }
        return { ok: true, written: res.written, skipped: res.skipped, errors: [] };
      }
      default:
        return { ok: false, error: "unknown message type" };
    }
  } catch (e) {
    return { ok: false, error: e && e.message ? String(e.message) : "host error" };
  }
}
