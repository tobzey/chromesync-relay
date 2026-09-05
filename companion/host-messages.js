// Native-host message handlers, extracted from the stdio wrapper so tests can
// exercise Options-shaped exportDrop/importDrop without attaching stdin.
// Cookie values are never logged.

import fsDefault from "node:fs";
import { setCookiesOp, launchChrome } from "./host-core.js";
import {
  exportCookies,
  exportWithState,
  exportBlobWithState,
  importFromDrop,
  importBlob,
  parseBlobFilename,
  resolveStatePath,
  ensureStateWritable,
  loadState,
  saveState,
} from "./drop.js";
import { deriveRelayAuth } from "./relay-auth.js";
import { parseRelayUrl, relayList, relayPush, relayGet } from "./relay-client.js";
import { validateProfileUse, runProfileUseSync } from "./profile-use.js";
import { terminalMessage } from "./terminal.js";

const HOST_ID_RE = /^[a-f0-9]+$/;

function mapRelayError(e) {
  if (e && (e.status === 401 || e.status === 403)) return "wrong pairing code or server";
  if (e && e.status === 429) return "sync server busy";
  return "cannot reach sync server";
}

export async function handleNativeMessage(msg, deps = {}) {
  const env = deps.env || process.env;
  const fs = deps.fs || fsDefault;
  const listBlobs = deps.relayList || relayList;
  const pushBlob = deps.relayPush || relayPush;
  const getBlob = deps.relayGet || relayGet;

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
      case "dropValidate": {
        if (!msg.pairingSecret) return { ok: false, error: "pairing secret not configured" };
        if (!msg.dropDir) return { ok: false, error: "drop folder not configured" };
        try {
          if (!fs.existsSync(msg.dropDir) || !fs.statSync(msg.dropDir).isDirectory()) {
            return { ok: false, error: "drop folder not found" };
          }
        } catch {
          return { ok: false, error: "drop folder not found" };
        }
        if (msg.sourceHostId && !HOST_ID_RE.test(msg.sourceHostId)) {
          return { ok: false, error: "invalid source host id" };
        }
        try {
          ensureStateWritable(resolveStatePath(msg.statePath, env), fs);
        } catch {
          return { ok: false, error: "companion state is not writable" };
        }
        return { ok: true };
      }
      case "exportDrop": {
        const cookies = Array.isArray(msg.cookies) ? msg.cookies : [];
        if (Number.isInteger(msg.counter) && msg.sourceHostId) {
          const res = exportCookies({
            dropDir: msg.dropDir,
            secret: msg.pairingSecret,
            sourceHostId: msg.sourceHostId,
            cookies,
            counter: msg.counter,
            createdAt: msg.createdAt,
            fs,
          });
          return { ok: true, filename: res.filename, counter: res.counter };
        }
        const res = exportWithState({
          dropDir: msg.dropDir,
          secret: msg.pairingSecret,
          cookies,
          statePath: typeof msg.statePath === "string" ? msg.statePath : "",
          sourceHostId: msg.sourceHostId || "",
          createdAt: msg.createdAt,
          fs,
          env,
        });
        return { ok: true, filename: res.filename, counter: res.counter, sourceHostId: res.sourceHostId };
      }
      case "importDrop": {
        const res = await importFromDrop({
          dropDir: msg.dropDir,
          secret: msg.pairingSecret,
          statePath: typeof msg.statePath === "string" ? msg.statePath : "",
          maxAgeMs: msg.maxAgeMs,
          fs,
          env,
          inject:
            deps.inject ||
            ((cookies) =>
              setCookiesOp({
                userDataDir: msg.userDataDir,
                port: msg.port,
                cookies,
              })),
        });
        return {
          ok: res.ok,
          imported: res.imported,
          written: res.written,
          skipped: res.skipped,
          errors: res.errors,
          injected: res.injected,
        };
      }
      case "relayValidate": {
        if (!msg.pairingSecret) return { ok: false, error: "pairing secret not configured" };
        if (!msg.relayUrl) return { ok: false, error: "sync server address not configured" };
        try {
          parseRelayUrl(msg.relayUrl);
        } catch {
          return { ok: false, error: "invalid sync server address" };
        }
        if (msg.sourceHostId && !HOST_ID_RE.test(msg.sourceHostId)) {
          return { ok: false, error: "invalid source host id" };
        }
        try {
          ensureStateWritable(resolveStatePath(msg.statePath, env), fs);
        } catch {
          return { ok: false, error: "companion state is not writable" };
        }
        try {
          const { token, roomId } = deriveRelayAuth(msg.pairingSecret);
          await listBlobs({
            relayUrl: msg.relayUrl,
            token,
            roomId,
            timeoutMs: 5000,
          });
          return { ok: true };
        } catch (e) {
          return { ok: false, error: mapRelayError(e) };
        }
      }
      case "relayPush": {
        const cookies = Array.isArray(msg.cookies) ? msg.cookies : [];
        if (!msg.pairingSecret) return { ok: false, error: "pairing secret not configured", written: 0, skipped: 0, errors: ["pairing secret not configured"] };
        if (!msg.relayUrl) return { ok: false, error: "sync server address not configured", written: 0, skipped: 0, errors: ["sync server address not configured"] };
        try {
          parseRelayUrl(msg.relayUrl);
        } catch {
          return { ok: false, error: "invalid sync server address", written: 0, skipped: 0, errors: ["invalid sync server address"] };
        }
        const persistPath = resolveStatePath(typeof msg.statePath === "string" ? msg.statePath : "", env);
        try {
          ensureStateWritable(persistPath, fs);
        } catch {
          return { ok: false, error: "companion state is not writable", written: 0, skipped: 0, errors: ["companion state is not writable"] };
        }
        const st = loadState(persistPath, fs);
        const exported = exportBlobWithState({
          secret: msg.pairingSecret,
          cookies,
          state: st,
          sourceHostId: msg.sourceHostId || "",
          createdAt: msg.createdAt,
          fs,
          env,
        });
        try {
          const { token, roomId } = deriveRelayAuth(msg.pairingSecret);
          await pushBlob({
            relayUrl: msg.relayUrl,
            token,
            roomId,
            name: exported.filename,
            blob: exported.blob,
          });
        } catch (e) {
          const err = mapRelayError(e);
          return { ok: false, written: 0, skipped: 0, errors: [err], error: err };
        }
        saveState(persistPath, exported.state, fs);
        return { ok: true, written: cookies.length, skipped: 0, errors: [], filename: exported.filename, counter: exported.counter, sourceHostId: exported.sourceHostId };
      }
      case "relayPull": {
        if (!msg.pairingSecret) return { ok: false, error: "pairing secret not configured", imported: 0, written: 0, skipped: 0, errors: ["pairing secret not configured"] };
        if (!msg.relayUrl) return { ok: false, error: "sync server address not configured", imported: 0, written: 0, skipped: 0, errors: ["sync server address not configured"] };
        try {
          parseRelayUrl(msg.relayUrl);
        } catch {
          return { ok: false, error: "invalid sync server address", imported: 0, written: 0, skipped: 0, errors: ["invalid sync server address"] };
        }
        const persistPath = resolveStatePath(typeof msg.statePath === "string" ? msg.statePath : "", env);
        try {
          ensureStateWritable(persistPath, fs);
        } catch {
          return { ok: false, error: "companion state is not writable", imported: 0, written: 0, skipped: 0, errors: ["companion state is not writable"] };
        }
        const st = loadState(persistPath, fs);
        const inject =
          deps.inject ||
          ((cookies) =>
            setCookiesOp({
              userDataDir: msg.userDataDir,
              port: msg.port,
              cookies,
            }));
        let listed;
        try {
          const { token, roomId } = deriveRelayAuth(msg.pairingSecret);
          listed = await listBlobs({ relayUrl: msg.relayUrl, token, roomId });
          const errors = [];
          let imported = 0;
          let written = 0;
          let skipped = 0;
          for (const item of listed) {
            const parsed = parseBlobFilename(item && item.name);
            if (!parsed) continue;
            const last = st.replay && st.replay[parsed.sourceHostId];
            if (last != null && Number.isFinite(last) && parsed.counter <= last) continue;
            let bytes;
            try {
              bytes = await getBlob({
                relayUrl: msg.relayUrl,
                token,
                roomId,
                name: item.name,
              });
            } catch (e) {
              errors.push(mapRelayError(e));
              continue;
            }
            const res = await importBlob({
              blob: bytes,
              sourceHostId: parsed.sourceHostId,
              secret: msg.pairingSecret,
              state: st,
              maxAgeMs: msg.maxAgeMs,
              inject,
            });
            if (!res.ok) {
              errors.push(res.error);
              continue;
            }
            imported++;
            written += res.written || 0;
            skipped += res.skipped || 0;
          }
          saveState(persistPath, st, fs);
          return {
            ok: errors.length === 0,
            imported,
            written,
            skipped,
            errors,
            injected: imported > 0,
          };
        } catch (e) {
          const err = mapRelayError(e);
          return { ok: false, imported: 0, written: 0, skipped: 0, errors: [err], error: err };
        }
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
