import { Sink } from "./sink.js";

const NATIVE_HOST = "io.chromesync.host";

/**
 * BrowserUseSink — OPTIONAL. Two paths:
 * 1) profile-use CLI (the verified sync mechanism) when `profileUseDir` is set.
 *    The extension asks the native host to spawn `profile-use`; Node tests may
 *    inject the companion runner. Gate failures disable the sink — never crash.
 * 2) Unverified HTTPS session flow, tested only against mock/bu-api.js.
 *
 * Nothing BU-specific is hardcoded beyond the documented default base in
 * DEFAULT_CONFIG. Live real-cookie sync is not performed here.
 */
export class BrowserUseSink extends Sink {
  #fetch;
  #env;
  #profileUse;

  constructor(fetchImpl, deps = {}) {
    super();
    this.#fetch = fetchImpl || globalThis.fetch.bind(globalThis);
    this.#env = deps.env || (typeof process !== "undefined" ? process.env : {});
    this.#profileUse = deps.profileUse || null;
  }

  get id() {
    return "browser-use";
  }

  get label() {
    return "Browser Use Cloud (stub)";
  }

  async validate(config) {
    if (config && config.profileUseDir) {
      return this.#validateProfileUse(config);
    }
    if (!config || !config.apiKey) return { ok: false, error: "apiKey not configured" };
    if (!config.baseUrl) return { ok: false, error: "baseUrl not configured" };
    try {
      const res = await this.#fetch(`${config.baseUrl}/profiles`, {
        method: "GET",
        headers: this.#headers(config),
      });
      if (!res.ok) return { ok: false, error: `profiles list returned ${res.status}` };
      return { ok: true };
    } catch (e) {
      return { ok: false, error: genericError(e) };
    }
  }

  async writeCookies(cookies, config) {
    if (config && config.profileUseDir) {
      return this.#writeProfileUse(cookies, config);
    }
    if (!config || !config.apiKey) {
      return { written: 0, skipped: cookies.length, errors: ["apiKey not configured"] };
    }
    if (!config.profileId) {
      return { written: 0, skipped: cookies.length, errors: ["profileId not configured"] };
    }
    try {
      // UNVERIFIED flow (mock-backed): open a session bound to the profile,
      // push cookies, then stop the session to persist.
      const openRes = await this.#fetch(`${config.baseUrl}/browsers`, {
        method: "POST",
        headers: this.#headers(config),
        body: JSON.stringify({ profileId: config.profileId }),
      });
      if (!openRes.ok) return { written: 0, skipped: 0, errors: [`open session ${openRes.status}`] };
      const session = await openRes.json();

      const pushRes = await this.#fetch(`${config.baseUrl}/browsers/${session.id}/cookies`, {
        method: "POST",
        headers: this.#headers(config),
        body: JSON.stringify({ cookies }),
      });
      if (!pushRes.ok) return { written: 0, skipped: 0, errors: [`push cookies ${pushRes.status}`] };
      const pushed = await pushRes.json();

      await this.#fetch(`${config.baseUrl}/browsers/${session.id}`, {
        method: "PATCH",
        headers: this.#headers(config),
        body: JSON.stringify({ action: "stop" }),
      });

      return { written: pushed.written || 0, skipped: pushed.skipped || 0, errors: pushed.errors || [] };
    } catch (e) {
      return { written: 0, skipped: 0, errors: [genericError(e)] };
    }
  }

  #headers(config) {
    return {
      "Content-Type": "application/json",
      "X-Browser-Use-API-Key": config.apiKey,
    };
  }

  async #validateProfileUse(config) {
    try {
      if (this.#profileUse && this.#profileUse.validate) {
        return await this.#profileUse.validate(config, { env: this.#env });
      }
      const res = await this.#send({ type: "profileUseValidate", profileUseDir: config.profileUseDir });
      return res && res.ok ? { ok: true } : { ok: false, error: (res && res.error) || "profile-use unavailable" };
    } catch (e) {
      return { ok: false, error: genericError(e) };
    }
  }

  async #writeProfileUse(cookies, config) {
    try {
      let res;
      if (this.#profileUse && this.#profileUse.write) {
        res = await this.#profileUse.write(config, { env: this.#env });
      } else {
        res = await this.#send({ type: "profileUseSync", profileUseDir: config.profileUseDir });
      }
      if (!res) {
        return { written: 0, skipped: cookies.length, errors: ["profile-use unavailable"] };
      }
      if (res.errors && res.errors.length) {
        return { written: res.written || 0, skipped: res.skipped || 0, errors: res.errors };
      }
      if (res.ok === false) {
        return { written: 0, skipped: cookies.length, errors: [res.error || "profile-use unavailable"] };
      }
      return { written: res.written || 0, skipped: res.skipped || 0, errors: res.errors || [] };
    } catch (e) {
      return { written: 0, skipped: 0, errors: [genericError(e)] };
    }
  }

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
  return e && e.message ? String(e.message) : "unknown error";
}
