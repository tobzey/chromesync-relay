> Historical design note. For current setup and supported behavior, see the root README.

# Plan: Port the ChromeSync relay to Cloudflare Workers + R2

Status: PLAN ONLY — no code written. To be executed by the Developer agent and
validated by the Tester agent.

## 1. Goal and context

Provide a Cloudflare Workers + R2 implementation of the encrypted-blob relay
that is a **drop-in replacement** for the Node VPS relay in `server/`. The
Worker speaks the exact same HTTP API that `companion/relay-client.js` already
speaks, stores only opaque E2E ciphertext, and never sees pairing secrets or
cookie plaintext. Rooms remain the multi-tenancy boundary: every blob key is
prefixed by the authenticated room, and auth is verified before any store
access.

Everything committed to the repo stays OSS-clean: placeholder hostnames,
placeholder bucket names, no account IDs, no credentials. Real values live in
a gitignored config copy (§9).

### Headline decisions (details in later sections)

| Decision | Choice | Why |
|---|---|---|
| Keep or remove `server/`? | **Keep** | It is the local test relay: `test/e2e-relay.test.js`, `test/relay-wiring.test.js`, `test/relay-client.test.js` all spin up `startRelay()` on 127.0.0.1 and need a real listener. It also remains the self-host option for users without Cloudflare, and the Worker reuses its `TokenBucket`. Zero new maintenance cost — it is frozen. |
| Rate limiting on Workers | **Per-isolate in-memory `TokenBucket`** (reuse `server/ratelimit.js`) + documented optional Cloudflare zone rate-limiting rule as edge backstop | Simplest thing that preserves the security properties (§7). Durable Objects and the ratelimit binding rejected there. |
| Blob TTL on Workers | **`expiresAt` custom metadata checked on read/list (lazy delete)** + documented R2 lifecycle rule as a coarse storage backstop | Deterministic and unit-testable without Cloudflare; lifecycle rule guarantees storage is actually reclaimed. No cron trigger needed (§6). |
| Worker code style | **Web-platform APIs only** (Request/Response, `crypto.subtle`, TextEncoder). No `node:` imports, no `nodejs_compat` flag | Node ≥ 20 exposes the same globals, so the Node test runner imports and tests the Worker modules directly — no miniflare, no vitest, zero new dependencies. |
| Extension / companion changes | **None** | `relayUrl` is already configurable: `DEFAULT_CONFIG.sinks.relay.relayUrl` defaults to `""`, the options UI sets it, and `parseRelayUrl()` accepts any `https:` URL — which a Worker custom domain is. Verified by `test/relay-wiring.test.js`. |
| New npm dependencies | **Zero** | Tests use an in-memory R2 stub. `wrangler` is invoked via `npx wrangler@4` at deploy time only and is not added to `package.json`. |

## 2. HTTP API contract to preserve (source of truth: `server/server.js`)

The Worker must reproduce this exactly. Clients: `companion/relay-client.js`
(never follows redirects, treats 3xx as error, expects these codes).

| Route | Method | Success | Errors |
|---|---|---|---|
| `/health` | GET | `200` body `ok`, `text/plain` | — (bypasses rate limit and auth) |
| `/rooms/:roomId/blobs` | GET | `200` JSON array `[{name, size, mtime}]`, sorted by `name`, capped at `MAX_BLOBS_PER_ROOM`; `[]` for an empty/unknown room | see shared errors |
| `/rooms/:roomId/blobs` | non-GET | — | `405` with `Allow: GET` |
| `/rooms/:roomId/blobs/:name` | PUT | `204`, empty body | `413` if body > `MAX_BODY_BYTES`; `507` if room over count/byte quota after write |
| `/rooms/:roomId/blobs/:name` | GET | `200`, `application/octet-stream`, exact bytes | `404` if absent (or expired) |
| `/rooms/:roomId/blobs/:name` | DELETE | `204` | `404` if absent |
| `/rooms/:roomId/blobs/:name` | other | — | `405` with `Allow: GET, PUT, DELETE` |
| anything else | any | — | `404` |

Shared error semantics, in this exact order of evaluation (parity with
`server/server.js` — the order is itself a tested security property):

1. `/health` short-circuits with `200`.
2. **Per-IP rate limit** → `429` + header `Retry-After: 1`. IP source on
   Workers: `request.headers.get("cf-connecting-ip") ?? "unknown"` (Cloudflare
   sets this; the Node `TRUST_PROXY`/XFF logic does not carry over).
3. Path parsing: split pathname on `/`, `decodeURIComponent` each segment
   (fall back to raw on decode error); any segment equal to `..`/`.` or
   containing `/` or `\0` → `400`. Wrong shape (`parts[0] !== "rooms"` or
   `parts[2] !== "blobs"` or length not 3–4) → `404`.
4. `roomId` must match `/^[A-Za-z0-9_-]{22}$/` → else `400`. `name` (when
   present) must match `/^chromesync-[a-f0-9]+-\d+\.csync$/` → else `400`.
5. **Auth**: bearer token from `Authorization` (regex
   `/^Bearer\s+(\S+)\s*$/i`). Missing/malformed/charset-invalid token →
   `401`. Token that does not hash to `roomId` (constant-time compare) →
   `403`.
6. **Per-room rate limit** (only after successful auth, so forged room IDs
   never seed a bucket — tested by relay-server.test.js) → `429` +
   `Retry-After: 1`.
7. Route dispatch per the table above. Unexpected exception → `500`.

Response headers on every response: `X-Content-Type-Options: nosniff`,
`Content-Type`, `Content-Length` (Workers sets Content-Length automatically
for fixed bodies — do not fight it). Error bodies are the short plain-text
status strings from `STATUS_TEXT` in `server/server.js` (reuse the same map).

Logging parity: log **only** `method roomId name status size` — never tokens,
never headers, never body bytes (via `console.log`; visible in
`wrangler tail`).

### Accepted behavioral deltas (document in worker/README.md, do not fight)

- **Raw `..` in the path**: `new URL()` (and Cloudflare edge normalization)
  collapses `/rooms/x/blobs/../y` before the handler sees it, so it yields
  `404` (wrong shape) instead of the Node server's `400`. Percent-encoded
  traversal (`%2e%2e`, `%2f`) still reaches the decode-then-validate step and
  yields `400` as before. Both are hard failures for the client; the
  validation code stays in the handler as defense in depth regardless of edge
  behavior.
- `mtime` in list responses is the R2 `uploaded` timestamp (ms) instead of
  file mtime. Blobs are write-once-per-name in practice, so identical
  semantics for the client's freshness logic.
- `413` responses do not carry `Connection: close` (connection handling
  belongs to Cloudflare). No client reads it.
- Node-only transport knobs (`headersTimeoutMs`, `maxConnections`, TLS certs,
  `maxHeaderSize`) have no Worker equivalent and are dropped.

## 3. Files to create / modify / delete

**Create**

| File | Contents |
|---|---|
| `worker/index.js` | `export default { fetch(request, env, ctx) }` + `export function createHandler(overrides)` for tests (mirrors how `startRelay(overrides)` accepts `ipLimiter`, `roomLimiter`, `log`, config overrides). Routing exactly per §2. Module-scope limiters (per-isolate) built lazily from `env` on first request. |
| `worker/auth.js` | WebCrypto port of `server/auth.js`: `ROOM_ID_RE`, `TOKEN_RE`, `bearerToken()` (sync, same regex), `base64url()`, `async roomIdForToken(token)` (`crypto.subtle.digest("SHA-256", ...)`), `async verifyRoomAuth(roomId, token)` returning the same `{ok}` / `{ok:false, status:400|401|403}` shapes. Constant-time compare: after the length/charset gates, XOR-accumulate over all bytes (no `node:crypto.timingSafeEqual` on Workers without compat flag). |
| `worker/store.js` | R2-backed store (§5): `put/get/list/del` + retention + quota + expiry filtering. Takes the bucket and config as arguments — no globals — so tests pass the in-memory stub. |
| `worker/config.js` | `configFromEnv(env)` parsing the vars in §8 with the same defaults as `server/config.js` (only the vars that still apply). Values may arrive as TOML numbers or strings; coerce with `Number()`. |
| `worker/wrangler.toml` | Placeholder deploy config (§9). |
| `worker/README.md` | API summary, behavioral deltas (§2), config matrix (§8), full deploy runbook (§10), rate-limit tradeoff statement (§7). Placeholders only. |
| `test/r2-stub.js` | In-memory R2Bucket stub (§11). Named so the `test/*.test.js` glob does NOT pick it up as a test. |
| `test/worker-auth.test.js` | Parity + negative tests for `worker/auth.js` (§11). |
| `test/worker-relay.test.js` | Endpoint-conformance suite against `worker.fetch(new Request(...))` + stub (§11). |
| `test/worker-client.test.js` | `companion/relay-client.js` driven through a ~20-line `node:http` bridge onto the Worker handler (§11). |

**Modify**

| File | Change |
|---|---|
| `.gitignore` | Add `.wrangler/`, `worker/wrangler.local.toml`, `.dev.vars`, `worker/.dev.vars`. (Currently none are covered — verified.) |
| `package.json` | Add `"test:worker": "node --test test/worker-auth.test.js test/worker-relay.test.js test/worker-client.test.js"`; append the three worker test files to `test:unit` and `test:relay`. `npm test` picks them up automatically via the `test/*.test.js` glob. |
| `server/README.md` | One paragraph: `server/` is the self-host/local-test relay; `worker/` is the managed Cloudflare deployment of the same protocol. |
| `README.md` | Mention the Worker relay option in the transport-C section (placeholder URL `https://sync.example.com`). |

**Delete** — nothing. `server/` stays (rationale in §1).

**Not touched** — `src/` (extension), `companion/`, `mock/`, `options/`,
`popup/`, all existing tests.

## 4. Worker request flow (`worker/index.js`)

```
export default {
  async fetch(request, env, ctx) { return handle(request, env, ctx, defaults) }
}
export function createHandler({ config?, ipLimiter?, roomLimiter?, log?, bucket? })
```

- `createHandler` returns an `async (request) => Response` closure so tests
  inject a stub bucket, deterministic limiters, and a silent log — the same
  override pattern `startRelay()` uses. The default export builds one handler
  per isolate from `env.BLOBS` + `configFromEnv(env)` and caches it in module
  scope (this is what makes the token buckets per-isolate).
- `TokenBucket` is imported from `../server/ratelimit.js` — it has zero
  `node:` imports (verified) and wrangler bundles relative imports outside
  `worker/` without complaint. Single source of truth, already covered by
  `test/relay-ratelimit.test.js`.
- PUT body handling: reject early with `413` when the `Content-Length` header
  parses to > `maxBodyBytes`; then `await request.arrayBuffer()` and re-check
  actual byte length (covers chunked/absent length). Only then hand bytes to
  the store.
- Never construct log lines from anything except
  `method / roomId / name / status / size`.

## 5. R2 key schema and store semantics (`worker/store.js`)

**Key schema:** `rooms/<roomId>/<blobName>` — e.g.
`rooms/AAAAAAAAAAAAAAAAAAAAAA/chromesync-ab12cd-7.csync`.
Both segments are regex-validated *before* key construction, so no traversal
or cross-room key is constructible; the room prefix is the tenancy wall.
A shared helper `roomPrefix(roomId) = "rooms/" + roomId + "/"` is used for
every list.

Operations (bucket = the R2 binding or the test stub):

- **put(bucket, config, roomId, name, bytes, now)**
  1. `bucket.put(key, bytes, { customMetadata: { expiresAt: String(now + config.blobTtlMs) } })`
     (omit `expiresAt` when `blobTtlMs <= 0`).
  2. Retention: list `roomPrefix(roomId)`, parse each name with the same
     `parseBlobName` regex (`chromesync-<sourceHostId>-<counter>.csync`),
     keep the newest `retentionPerHost` (default 3) per `sourceHostId` by
     `counter` descending, delete the rest.
  3. Quota: from the same listing compute count/bytes (excluding what
     retention just deleted, including the new object). If count >
     `maxBlobsPerRoom` or bytes > `maxRoomBytes`: delete the just-written
     key and throw a 507 error object (`{statusCode: 507}` like
     `server/store.js` does).
  - Concurrency note for the README: without transactions this is
    best-effort under concurrent PUTs to one room — same room = same paired
    user, so races only ever transiently over/under-count that user's own
    quota. Accepted; do not add Durable Objects for this.
- **get(bucket, config, roomId, name, now)** — `bucket.get(key)`; if null →
  null (404). If `customMetadata.expiresAt` is present and `< now`: fire a
  lazy `bucket.delete(key)` (via `ctx.waitUntil` in the handler) and return
  null (404).
- **list(bucket, config, roomId, now)** — `bucket.list({ prefix, limit: 1000 })`
  (room cap ≤ 100 ≪ 1000, so one page always suffices; still loop on
  `truncated` for correctness). For each object whose basename matches
  `BLOB_NAME_RE` and is not expired: `{ name, size: obj.size, mtime: obj.uploaded.getTime() }`.
  Sort by `name`, cap at `maxBlobsPerRoom`. Unknown room → `[]` (an R2
  prefix listing of nothing is naturally empty — matches Node).
- **del(bucket, roomId, name)** — `bucket.head(key)` first; null → `false`
  (handler answers 404). Else `bucket.delete(key)` → `true` (204). (R2
  `delete` alone cannot report prior existence, and the 404-on-missing-DELETE
  behavior is tested.)

**Expiry / cleanup strategy** (decision): lazy expiry via `expiresAt`
metadata on GET/list (deterministic, testable in-memory), plus an **R2
lifecycle rule** applied to the bucket at deploy time (delete objects 7 days
after creation — matching the default `BLOB_TTL_MS`) so storage for
abandoned rooms is reclaimed even if nobody ever reads them again. The
lifecycle rule is bucket configuration, not code (§10). No cron trigger:
it would re-implement what the lifecycle rule already does, cost a scheduled
handler + list-all scans, and add nothing testable. If an operator lowers
`BLOB_TTL_MS` below 7 days, read-time filtering enforces the precise TTL and
the lifecycle rule stays as the coarse backstop.

## 6. Auth (`worker/auth.js`)

Same derivation contract as `server/auth.js` / `companion/relay-auth.js`:
`roomId = base64url(sha256(token)).slice(0, 22)`. The relay never sees the
pairing secret (scrypt runs only in the companion) and never stores tokens.
The only differences from `server/auth.js` are mechanical: `crypto.subtle`
makes `roomIdForToken`/`verifyRoomAuth` async, and constant-time equality is
a manual XOR loop guarded by the same length/charset pre-checks. A parity
test (§11) pins the Worker derivation to `companion/relay-auth.js` output so
drift is impossible.

## 7. Rate limiting: options considered, choice, tradeoff

| Option | Verdict |
|---|---|
| **Per-isolate in-memory `TokenBucket` (chosen)** | Reuses the audited `server/ratelimit.js` unchanged (bounded map, lossless idle eviction). Limits are per-isolate: a client hitting multiple colos/isolates gets N× the nominal budget. |
| Cloudflare rate-limiting binding | Still per-colo (same weakness), lives under `[unsafe.bindings]`, fixed limits not env-tunable, and cannot be exercised by plain-Node tests. More moving parts, no property gained. |
| Durable Objects | The only globally exact option, but adds a stateful class, per-request DO round-trip latency, billing, and miniflare-or-cloud-only testing — for a relay whose auth cannot be brute-forced anyway. |

Why best-effort is sufficient here (state this in `worker/README.md`): the
limiter is not what protects rooms — auth is. Reaching a room requires a
token whose SHA-256 prefix matches the 22-char room ID; guessing is
cryptographically infeasible at any request rate a Worker could serve. The
limiter's real jobs are (a) throttling junk traffic cost and (b) keeping one
noisy client from hammering R2 — both fine at per-isolate granularity, and
storage abuse is independently capped by the per-room quota/retention.
Operators who want a hard global limit add a Cloudflare **WAF rate-limiting
rule** on the zone (documented in the runbook as an optional step, since the
custom domain is on a zone they control) — configuration, not code.

Evaluation-order property preserved from Node: per-IP limit before auth,
per-room limit strictly after successful auth (unauthenticated requests must
not create room buckets — `test/worker-relay.test.js` re-asserts this with an
injected `roomLimiter`).

## 8. Config / env matrix

Set as `[vars]` in wrangler config; parsed by `worker/config.js`. Same names
and defaults as `server/config.js` where the concept survives:

| Var | Default | Worker meaning |
|---|---|---|
| `MAX_BODY_BYTES` | `1048576` | PUT body cap → 413 |
| `MAX_BLOBS_PER_ROOM` | `100` | quota → 507; also list cap |
| `MAX_ROOM_BYTES` | `10485760` | quota → 507 |
| `BLOB_TTL_MS` | `604800000` (7 d) | `expiresAt` metadata; `0` disables |
| `RETENTION_PER_HOST` | `3` | newest-K per sourceHostId on PUT |
| `RATE_IP_CAPACITY` / `RATE_IP_REFILL` | `60` / `1` | per-isolate IP bucket |
| `RATE_ROOM_CAPACITY` / `RATE_ROOM_REFILL` | `120` / `2` | per-isolate room bucket |

Dropped (no Worker equivalent): `HOST`, `PORT`, `DATA_DIR`, `TRUST_PROXY`,
`TLS_CERT/TLS_KEY`, `HEADERS_TIMEOUT_MS`, `REQUEST_TIMEOUT_MS`,
`MAX_CONNECTIONS`, `SWEEP_INTERVAL_MS`, `MAX_HEADER_SIZE`.

Bindings: `BLOBS` (R2 bucket). No secrets, no KV, no DO, no cron.

## 9. `worker/wrangler.toml` (committed, placeholders only) + override mechanism

```toml
# ChromeSync relay — Cloudflare Worker deploy config.
# OSS-CLEAN: every value below is a placeholder. Do NOT put real hostnames,
# bucket names, or account IDs here. Copy this file to wrangler.local.toml
# (gitignored), edit the real values there, and deploy with:
#   npx wrangler@4 deploy --config worker/wrangler.local.toml
# Account selection comes from `npx wrangler login` or the
# CLOUDFLARE_ACCOUNT_ID / CLOUDFLARE_API_TOKEN environment variables —
# never from a committed file.

name = "chromesync-relay"
main = "index.js"
compatibility_date = "2026-09-01"

# Worker custom domain on a zone already on Cloudflare (creates DNS + cert).
routes = [
  { pattern = "sync.example.com", custom_domain = true }
]

[[r2_buckets]]
binding = "BLOBS"
bucket_name = "chromesync-relay-blobs"   # placeholder — real name in wrangler.local.toml

[vars]
MAX_BODY_BYTES = "1048576"
MAX_BLOBS_PER_ROOM = "100"
MAX_ROOM_BYTES = "10485760"
BLOB_TTL_MS = "604800000"
RETENTION_PER_HOST = "3"
RATE_IP_CAPACITY = "60"
RATE_IP_REFILL = "1"
RATE_ROOM_CAPACITY = "120"
RATE_ROOM_REFILL = "2"
```

Override mechanism: `worker/wrangler.local.toml` — a full gitignored copy
(wrangler has no config-merge; `--config` swaps the whole file). Credentials
never touch any file: OAuth via `wrangler login` or
`CLOUDFLARE_API_TOKEN`/`CLOUDFLARE_ACCOUNT_ID` env vars. `.gitignore` gains
`.wrangler/` (wrangler cache), `worker/wrangler.local.toml`, and `.dev.vars`
patterns (§3).

## 10. Deployment runbook (documentation only — NOT part of the dev work)

Goes in `worker/README.md`, placeholders throughout:

1. `npx wrangler@4 login` (or export `CLOUDFLARE_API_TOKEN` + `CLOUDFLARE_ACCOUNT_ID`).
2. `npx wrangler@4 r2 bucket create <real-bucket-name>`
3. Lifecycle backstop (7-day expiry, matching default `BLOB_TTL_MS`):
   `npx wrangler@4 r2 bucket lifecycle add <real-bucket-name> --expire-days 7`
   (or dashboard → R2 → bucket → Settings → Object lifecycle rules, if the
   CLI subcommand differs in the installed wrangler version).
4. `cp worker/wrangler.toml worker/wrangler.local.toml`, set the real
   `pattern` (custom domain on the Cloudflare zone) and `bucket_name`.
5. `npx wrangler@4 deploy --config worker/wrangler.local.toml`
6. Smoke: `curl -fsS https://<real-domain>/health` → `ok`;
   unauthenticated `curl -i https://<real-domain>/rooms/AAAAAAAAAAAAAAAAAAAAAA/blobs` → `401`.
7. Point the extension's relay sink URL / companion `relayUrl` at
   `https://<real-domain>` (existing options UI — no code change).
8. Optional: add a zone WAF rate-limiting rule for the relay hostname (§7).

Local dev loop (optional, not used by tests):
`npx wrangler@4 dev --config worker/wrangler.toml` (placeholder config works
locally; `wrangler dev` simulates R2 in `.wrangler/`, which is gitignored).

## 11. Test plan (no network, no new dependencies, `node --test`)

Node ≥ 20 provides `Request`, `Response`, `Headers`, `crypto.subtle`, and
`URL` as globals, so the Worker's handler and modules are imported and
exercised directly by the existing test runner. No miniflare/vitest — not
needed because the Worker uses only web-platform APIs (this is a checked
invariant, see §12 step V6).

**`test/r2-stub.js`** — in-memory R2Bucket:
`Map<key, {bytes: Uint8Array, uploaded: Date, customMetadata}>` implementing
exactly the subset the store uses: `put(key, value, opts)`, `get(key)`
(returns `{ body-ish arrayBuffer(), size, uploaded, customMetadata }`),
`head(key)`, `delete(key)`, `list({prefix, limit, cursor})` (sorted keys,
`truncated`/`cursor` honored so the pagination loop is testable). Exposes the
map for direct inspection/mutation (e.g. backdating `uploaded`, rewriting
`expiresAt` for TTL tests — replaces the Node tests' `fs.utimesSync`).

**`test/worker-auth.test.js`**
- Parity: for several tokens (including a real `deriveRelayAuth("test-pairing-secret-not-real")`
  token from `companion/relay-auth.js`), `await workerAuth.roomIdForToken(t)`
  equals the companion's `roomIdForToken(t)`.
- `bearerToken` extraction cases; `verifyRoomAuth` → 400 (bad roomId), 401
  (missing/charset-invalid token), 403 (wrong token, valid-token-wrong-room),
  ok case.

**`test/worker-relay.test.js`** — conformance suite mirroring
`test/relay-server.test.js` case-for-case, but via
`handler(new Request("https://relay.test/...", {...}))` with the stub bucket
and generous limiters (helper mirrors `withRelay`). Cases: PUT→list→GET
byte-for-byte (assert stub bytes = ciphertext = uploaded bytes, and that the
stored bytes never contain the pairing secret); wrong token 403; valid token +
wrong room 403; missing/blank auth 401; oversized body 413 (both via
content-length and via actual bytes); bad name 400 (`not-a-blob.txt`,
`chromesync-../1.csync` percent-encoded); raw `../` traversal → assert 400
**or** 404 (normalization delta, §2); bad roomId 400; IP limit 429 +
`Retry-After`; no room bucket seeded by unauthenticated/forged requests
(injected `roomLimiter`, assert `buckets.size === 0` then 1); retention
prunes oldest per host; quota → 507 and the overflowing object is gone from
the stub; TTL: expired `expiresAt` → GET 404, list omits, object lazily
deleted; DELETE 204 then GET 404; DELETE of missing → 404; PATCH → 405 with
`Allow`; `/nope` → 404; `/health` → 200 `ok` with no auth and with limiter
exhausted; `X-Content-Type-Options: nosniff` present on responses.

**`test/worker-client.test.js`** — proves drop-in compatibility with the real
client, still offline: a ~20-line `node:http` server that adapts each
incoming Node request to a `Request`, calls the Worker handler, and writes
the `Response` back. Then drive `relayPush`/`relayList`/`relayGet`/
`relayDelete` from `companion/relay-client.js` against
`http://127.0.0.1:<port>` (allowed by `parseRelayUrl`'s localhost exception)
end-to-end, including a 404 → `RelayClientError("not found")` and a
403 → `"wrong pairing code or server"` mapping.

**Untouched and still green:** all existing tests, unchanged — they target
the kept Node server. `npm test`'s `test/*.test.js` glob picks up the three
new files automatically.

## 12. Ordered implementation steps (Developer agent)

1. `.gitignore`: add `.wrangler/`, `worker/wrangler.local.toml`, `.dev.vars`,
   `worker/.dev.vars`.
2. `worker/auth.js` + `test/worker-auth.test.js`; run
   `node --test test/worker-auth.test.js`.
3. `worker/config.js` (small; covered indirectly by the relay tests).
4. `test/r2-stub.js`, then `worker/store.js`; store behavior is asserted
   through the endpoint suite (no separate store test file needed — keeps
   file count down; add one only if the dev finds the endpoint suite awkward
   for a store edge case).
5. `worker/index.js` (`createHandler` + default export) +
   `test/worker-relay.test.js`; iterate until green.
6. `test/worker-client.test.js` (http bridge + real relay-client).
7. `worker/wrangler.toml` (verbatim from §9) + `worker/README.md`
   (API/deltas/config/runbook/rate-limit statement).
8. `package.json`: `test:worker` script; extend `test:unit` and `test:relay`
   lists. `server/README.md` + root `README.md` notes.
9. Full `npm test` green; run the verification checklist below; commit.

## 13. Verification checklist (Tester agent — exact commands)

Run from the repo root:

```bash
# 1. Full suite (includes new worker tests via glob) — must be all pass/skip
npm test

# 2. Focused runs
npm run test:relay
npm run test:worker
node --test test/relay-server.test.js test/relay-client.test.js   # Node relay untouched

# 3. e2e (skips cleanly when Chrome absent; must pass when present)
node --test test/e2e-relay.test.js

# 4. Worker is web-API-only (no node: imports anywhere under worker/)
! grep -RInE "(from|import) *[\"']node:" worker/

# 5. TokenBucket reuse still dependency-free
! grep -n "node:" server/ratelimit.js

# 6. OSS-clean: placeholders present, nothing operator-tied
git grep -In "example.com" worker/wrangler.toml            # expect: the routes pattern
! git grep -InE "[0-9a-f]{32}" -- . ':!*.md'               # no 32-hex account IDs
! git grep -IniE "workers\.dev/|\.cfargotunnel\.|account_id *= *[\"'][0-9a-f]"
git check-ignore worker/wrangler.local.toml .wrangler .dev.vars   # all three print

# 7. No secret/plaintext leakage in worker logs or code paths
! git grep -InE "console\.(log|error).*(token|secret|body|blob)" worker/
node --test test/worker-relay.test.js                       # includes stored-bytes leak assertions

# 8. package.json wiring
node -e "const p=require('./package.json');['test:worker'].forEach(k=>{if(!p.scripts[k])throw k});['test:unit','test:relay'].forEach(k=>{if(!p.scripts[k].includes('worker'))throw k});console.log('scripts ok')"
```

Manual review items for the Tester: status-code table of §2 vs
`worker/index.js`; evaluation order (health → IP limit → parse → auth → room
limit); DELETE-missing → 404 via `head`; 507 removes the written object;
list sorted/capped; `Retry-After` and `Allow` headers present.

## 14. Out of scope (do not let the dev drift)

- No live cookie sync, no real pairing secrets/cookies/profiles — synthetic
  fixtures only (`test/fixtures.js`), per standing project rules.
- No extension/companion/options changes (relay URL is already configurable).
- No actual Cloudflare deploy, bucket creation, DNS, or `wrangler login` —
  §10 is documentation for the operator to run later.
- No new npm dependencies, no miniflare/vitest, no Durable Objects, no cron
  triggers, no KV.
- No real hostnames/zones/account IDs/bucket names anywhere in tracked files.
