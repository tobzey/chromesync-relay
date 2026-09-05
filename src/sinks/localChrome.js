import { Sink } from "./sink.js";

const NATIVE_HOST = "io.chromesync.host";

/**
 * LocalChromeSink — writes cookies into a separate local Chrome profile via a
 * native-messaging companion that speaks CDP. The extension itself only sends
 * cookies over stdio to the host; all Chrome launching + CDP happens in the
 * companion (fixed args, no arbitrary commands).
 */
export class LocalChromeSink extends Sink {
  get id() {
    return "local-chrome";
  }

  get label() {
    return "Local Chrome profile";
  }

  async validate(config) {
    if (!config || !config.userDataDir) {
      return { ok: false, error: "userDataDir not configured" };
    }
    try {
      const res = await this.#send({ type: "ping", userDataDir: config.userDataDir, port: config.port || 0 });
      return res && res.ok ? { ok: true } : { ok: false, error: (res && res.error) || "host did not respond ok" };
    } catch (e) {
      return { ok: false, error: genericError(e) };
    }
  }

  async writeCookies(cookies, config) {
    try {
      const res = await this.#send({
        type: "setCookies",
        userDataDir: config.userDataDir,
        port: config.port || 0,
        cookies,
      });
      if (!res || !res.ok) {
        return { written: 0, skipped: 0, errors: [(res && res.error) || "host error"] };
      }
      return { written: res.written || 0, skipped: res.skipped || 0, errors: res.errors || [] };
    } catch (e) {
      return { written: 0, skipped: 0, errors: [genericError(e)] };
    }
  }

  // Single request/response over a native-messaging port. Injected in tests via
  // #transport override is not possible on private fields, so tests target the
  // host module directly; here we use chrome.runtime.
  #send(message) {
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
  // Never include cookie data; keep it to the message string only.
  return e && e.message ? String(e.message) : "unknown error";
}
