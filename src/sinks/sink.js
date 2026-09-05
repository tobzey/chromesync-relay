/**
 * Sink base class. A sink receives already-mapped CDP-shaped cookies and
 * writes them somewhere. Implementations must NEVER log cookie values and
 * must report results as counts + generic error strings only.
 */
export class Sink {
  /** Stable slug, e.g. "local-chrome". */
  get id() {
    throw new Error("Sink.id not implemented");
  }

  /** Human-readable label for the options UI. */
  get label() {
    throw new Error("Sink.label not implemented");
  }

  /**
   * Cheap connectivity/config check.
   * @returns {Promise<{ok: boolean, error?: string}>}
   */
  async validate(_config) {
    throw new Error("Sink.validate not implemented");
  }

  /**
   * Write cookies to the sink target.
   * @param {Array<object>} _cookies CDP CookieParam-shaped cookies
   * @param {object} _config per-sink config
   * @returns {Promise<{written: number, skipped: number, errors: string[]}>}
   */
  async writeCookies(_cookies, _config) {
    throw new Error("Sink.writeCookies not implemented");
  }
}
