import { filterByAllowlist, mapCookies } from "./cookies.js";

/**
 * SyncEngine: collect cookies once, fan out to every enabled sink. Core is
 * sink-agnostic — nothing BU- or Chrome-specific lives here. One sink failing
 * must never abort the others.
 */
export class SyncEngine {
  #registry;
  #getAllCookies;

  constructor({ registry, getAllCookies }) {
    this.#registry = registry;
    // getAllCookies: () => Promise<chrome.cookies.Cookie[]>. Injectable for tests.
    this.#getAllCookies = getAllCookies;
  }

  /** Collect + map cookies for the given allowlist. */
  async collect(allowlist) {
    const raw = await this.#getAllCookies();
    const filtered = filterByAllowlist(raw, allowlist);
    return mapCookies(filtered); // { cookies, skipped }
  }

  /**
   * Run a full sync across enabled sinks.
   * @param {object} config full config object (see storage.DEFAULT_CONFIG)
   * @returns {Promise<object>} summary: counts + generic per-sink status, no values.
   */
  async sync(config) {
    const { cookies, skipped: mapSkipped } = await this.collect(config.allowlist);
    const sinkResults = {};

    for (const sink of this.#registry.all()) {
      const sinkCfg = (config.sinks && config.sinks[sink.id]) || {};
      if (!sinkCfg.enabled) continue;

      const valid = await sink.validate(sinkCfg);
      if (!valid.ok) {
        sinkResults[sink.id] = { ok: false, written: 0, skipped: cookies.length, errors: [valid.error || "invalid config"] };
        continue;
      }

      try {
        const res = await withBackoff(() => sink.writeCookies(cookies, sinkCfg));
        sinkResults[sink.id] = {
          ok: res.errors.length === 0,
          written: res.written,
          skipped: res.skipped,
          errors: res.errors,
        };
      } catch (e) {
        sinkResults[sink.id] = { ok: false, written: 0, skipped: cookies.length, errors: [String(e && e.message || e)] };
      }
    }

    return {
      at: Date.now(),
      collected: cookies.length,
      mappingSkipped: mapSkipped,
      sinks: sinkResults,
    };
  }
}

/** Retry with exponential backoff on thrown errors (not on soft error results). */
async function withBackoff(fn, { retries = 2, baseMs = 200 } = {}) {
  let lastErr;
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      return await fn();
    } catch (e) {
      lastErr = e;
      if (attempt < retries) await sleep(baseMs * 2 ** attempt);
    }
  }
  throw lastErr;
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}
