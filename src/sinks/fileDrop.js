import { Sink } from "./sink.js";

const NATIVE_HOST = "io.chromesync.host";

/**
 * FileDropSink — source side of cross-machine transport A. Sends CDP-shaped
 * cookies to the native host, which AEAD-encrypts them into the configured
 * drop folder. The extension never writes cookie files itself.
 *
 * Required Options fields: drop folder + pairing secret. Blank sourceHostId
 * and statePath are valid — the companion generates a host id once and stores
 * it with replay counters in its local app-state file.
 */
export class FileDropSink extends Sink {
  #sendImpl;

  constructor(opts = {}) {
    super();
    this.#sendImpl = opts.send || null;
  }

  get id() {
    return "file-drop";
  }

  get label() {
    return "Encrypted file drop";
  }

  async validate(config) {
    if (!config || !config.pairingSecret) {
      return { ok: false, error: "pairing secret not configured" };
    }
    if (!config.dropDir) {
      return { ok: false, error: "drop folder not configured" };
    }
    try {
      const res = await this.#send(this.#exportFields(config, { type: "dropValidate" }));
      return res && res.ok ? { ok: true } : { ok: false, error: (res && res.error) || "host did not respond ok" };
    } catch (e) {
      return { ok: false, error: genericError(e) };
    }
  }

  async writeCookies(cookies, config) {
    try {
      const res = await this.#send(this.#exportFields(config, { type: "exportDrop", cookies }));
      if (!res || !res.ok) {
        return { written: 0, skipped: 0, errors: [(res && res.error) || "host error"] };
      }
      return { written: cookies.length, skipped: 0, errors: [] };
    } catch (e) {
      return { written: 0, skipped: 0, errors: [genericError(e)] };
    }
  }

  #exportFields(config, extra) {
    return {
      dropDir: config.dropDir,
      pairingSecret: config.pairingSecret,
      sourceHostId: config.sourceHostId || "",
      statePath: config.statePath || "",
      ...extra,
    };
  }

  #send(message) {
    if (this.#sendImpl) return this.#sendImpl(message);
    return new Promise((resolve, reject) => {
      let settled = false;
      const port = chrome.runtime.connectNative(NATIVE_HOST);
      const done = (fn, arg) => {
        if (settled) return;
        settled = true;
        try {
          port.disconnect();
        } catch {}
        fn(arg);
      };
      port.onMessage.addListener((msg) => done(resolve, msg));
      port.onDisconnect.addListener(() => {
        const err = chrome.runtime.lastError;
        done(reject, new Error(err ? err.message : "native host disconnected"));
      });
      port.postMessage(message);
    });
  }
}

function genericError(e) {
  return e && e.message ? String(e.message) : "unknown error";
}
