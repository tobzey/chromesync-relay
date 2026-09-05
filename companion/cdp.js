// Minimal CDP client over a WebSocket. Node 22 has a global WebSocket, so no
// third-party deps. Used by the native host to talk to a target Chrome's
// remote debugging endpoint. Never logs cookie values.

export class CdpClient {
  #ws;
  #id = 0;
  #closed = false;
  #pending = new Map();

  constructor(ws) {
    this.#ws = ws;
    this.#ws.addEventListener("message", (ev) => this.#onMessage(ev));
    this.#ws.addEventListener("close", () => this.#failPending());
    this.#ws.addEventListener("error", () => this.#failPending());
  }

  static async connect(wsUrl, { WebSocketImpl, timeoutMs = 10000 } = {}) {
    // Node 22+ supplies WebSocket without any runtime dependency.
    if (!WebSocketImpl) {
      if (typeof globalThis.WebSocket === "function") {
        WebSocketImpl = globalThis.WebSocket;
      } else {
        throw new Error("Node.js 22 or later is required for Chrome connections");
      }
    }
    const ws = new WebSocketImpl(wsUrl);
    await new Promise((resolve, reject) => {
      const t = setTimeout(() => { try { ws.close(); } catch {} reject(new Error("CDP connect timeout")); }, timeoutMs);
      ws.addEventListener("open", () => {
        clearTimeout(t);
        resolve();
      });
      ws.addEventListener("error", (e) => {
        clearTimeout(t);
        reject(new Error("CDP connect error"));
      });
    });
    return new CdpClient(ws);
  }

  #onMessage(ev) {
    let msg;
    try {
      msg = JSON.parse(typeof ev.data === "string" ? ev.data : ev.data.toString());
    } catch {
      return;
    }
    if (msg.id != null && this.#pending.has(msg.id)) {
      const { resolve, reject, timer } = this.#pending.get(msg.id);
      clearTimeout(timer);
      this.#pending.delete(msg.id);
      if (msg.error) reject(new Error("Chrome rejected the CDP operation"));
      else resolve(msg.result);
    }
  }

  send(method, params = {}, { sessionId, timeoutMs = 10000 } = {}) {
    if (this.#closed) return Promise.reject(new Error("CDP connection closed"));
    const id = ++this.#id;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.#pending.delete(id);
        reject(new Error("CDP operation timed out"));
      }, timeoutMs);
      this.#pending.set(id, { resolve, reject, timer });
      try { this.#ws.send(JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) })); }
      catch { clearTimeout(timer); this.#pending.delete(id); reject(new Error("CDP connection closed")); }
    });
  }

  close() {
    this.#failPending();
    try {
      this.#ws.close();
    } catch {}
  }

  #failPending() {
    this.#closed = true;
    for (const { reject, timer } of this.#pending.values()) {
      clearTimeout(timer);
      reject(new Error("CDP connection closed"));
    }
    this.#pending.clear();
  }
}
