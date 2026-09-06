import http from 'node:http';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';

const ASSETS = new Map([
  ['/', ['index.html', 'text/html; charset=utf-8']],
  ['/app.js', ['app.js', 'text/javascript; charset=utf-8']],
  ['/style.css', ['style.css', 'text/css; charset=utf-8']],
]);
const OWNER_OPERATIONS = new Set(['requests', 'request.status', 'request.decide', 'request.retry', 'policies', 'policy.revoke', 'enrollments', 'enrollment.put', 'provider.put', 'providers', 'provider.check', 'provider.discovery', 'peers', 'peer.revoke', 'takeover.start', 'takeover.observe', 'takeover.click', 'takeover.type', 'takeover.key', 'takeover.finish', 'passkey.observe', 'passkey.click', 'passkey.type', 'passkey.key']);

function send(res, status, value, type = 'application/json') {
  const body = type === 'application/json' ? JSON.stringify(value) : value;
  res.writeHead(status, {
    'Content-Type': type, 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer', 'Cross-Origin-Resource-Policy': 'same-origin',
    'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
  });
  res.end(body);
}
async function readBody(req) {
  const chunks = [];
  let bytes = 0;
  for await (const chunk of req) {
    bytes += chunk.length;
    if (bytes > 128 * 1024) throw new Error('Request too large');
    chunks.push(chunk);
  }
  return JSON.parse(Buffer.concat(chunks).toString());
}

// This server runs on the trusted approval device only. It never exposes a
// remote admin listener or bearer credential in its URL or startup output.
export async function startApprovalInbox({ call, port = 0, role = 'approver' }) {
  if (!['approver', 'executor'].includes(role)) throw new Error('Approval identity required');
  const session = crypto.randomBytes(32).toString('base64url');
  const csrf = crypto.randomBytes(32).toString('base64url');
  let origin;
  const server = http.createServer(async (req, res) => {
    try {
      if (req.headers.host !== new URL(origin).host) return send(res, 403, { error: 'Request rejected' });
      const route = req.url?.split('?')[0];
      if (req.method === 'GET' && ASSETS.has(route)) {
        const [file, type] = ASSETS.get(route);
        if (route === '/') res.setHeader('Set-Cookie', `cs_auth_inbox=${session}; HttpOnly; SameSite=Strict; Path=/`);
        return send(res, 200, await fs.readFile(new URL(`./ui/${file}`, import.meta.url)), type);
      }
      const cookies = (req.headers.cookie || '').split(';').map(value => value.trim());
      if (!cookies.includes(`cs_auth_inbox=${session}`) || (req.headers['sec-fetch-site'] && req.headers['sec-fetch-site'] !== 'same-origin')) return send(res, 403, { error: 'Request rejected' });
      if (req.method === 'GET' && route === '/api/bootstrap') return send(res, 200, { csrf, role });
      if (req.method !== 'POST' || route !== '/api' || req.headers.origin !== origin || req.headers['x-csrf-token'] !== csrf || req.headers['content-type'] !== 'application/json') return send(res, 403, { error: 'Request rejected' });
      const body = await readBody(req);
      if (!OWNER_OPERATIONS.has(body.operation)) return send(res, 403, { error: 'Operation unavailable' });
      const result = await call(body.operation, body.args || {});
      return send(res, 200, { result });
    } catch (error) { send(res, 400, { error: 'Operation failed. Check the executor connection and enrollment.', code: typeof error?.code === 'string' && /^[A-Z_]{1,40}$/.test(error.code) ? error.code : 'OPERATION_REJECTED' }); }
  });
  server.requestTimeout = 100000;
  server.headersTimeout = 5000;
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen({ host: '127.0.0.1', port }, resolve); });
  origin = `http://127.0.0.1:${server.address().port}`;
  return { url: origin, server, close: () => new Promise(resolve => { server.close(resolve); server.closeIdleConnections(); }) };
}
