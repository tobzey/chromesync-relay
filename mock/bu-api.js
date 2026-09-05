// Local mock of the Browser Use Cloud REST API — for tests only. It never
// reaches the real service and contains no real profile IDs or keys. It accepts
// any non-empty X-Browser-Use-API-Key so tests can pass a dummy key.

import http from "node:http";

export function createMockBuServer() {
  const state = { sessions: new Map(), profiles: [{ id: "test-profile", name: "Test Profile", userId: "test-user" }] };
  let seq = 0;

  const server = http.createServer((req, res) => {
    const key = req.headers["x-browser-use-api-key"];
    if (!key) return send(res, 401, { error: "missing api key" });

    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      const body = chunks.length ? safeJson(Buffer.concat(chunks).toString("utf8")) : {};
      route(req, res, body);
    });
  });

  function route(req, res, body) {
    const url = req.url;

    if (req.method === "GET" && url === "/profiles") {
      return send(res, 200, { profiles: state.profiles });
    }

    if (req.method === "POST" && url === "/browsers") {
      const id = `sess-${++seq}`;
      state.sessions.set(id, { profileId: body.profileId, cookies: [], stopped: false });
      return send(res, 201, { id, profileId: body.profileId });
    }

    const pushMatch = url.match(/^\/browsers\/([^/]+)\/cookies$/);
    if (req.method === "POST" && pushMatch) {
      const sess = state.sessions.get(pushMatch[1]);
      if (!sess) return send(res, 404, { error: "no session" });
      const cookies = Array.isArray(body.cookies) ? body.cookies : [];
      sess.cookies = cookies;
      return send(res, 200, { written: cookies.length, skipped: 0, errors: [] });
    }

    const stopMatch = url.match(/^\/browsers\/([^/]+)$/);
    if (req.method === "PATCH" && stopMatch) {
      const sess = state.sessions.get(stopMatch[1]);
      if (!sess) return send(res, 404, { error: "no session" });
      sess.stopped = body.action === "stop";
      return send(res, 200, { id: stopMatch[1], stopped: sess.stopped });
    }

    send(res, 404, { error: "not found" });
  }

  return {
    server,
    state,
    listen() {
      return new Promise((resolve) => {
        server.listen(0, "127.0.0.1", () => {
          const { port } = server.address();
          resolve(`http://127.0.0.1:${port}`);
        });
      });
    },
    close() {
      return new Promise((resolve) => server.close(resolve));
    },
  };
}

function send(res, status, obj) {
  const json = JSON.stringify(obj);
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(json);
}

function safeJson(s) {
  try {
    return JSON.parse(s);
  } catch {
    return {};
  }
}
