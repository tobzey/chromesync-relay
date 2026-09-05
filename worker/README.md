# ChromeSync relay (Cloudflare Workers + R2)

Managed deployment of the same encrypted-blob protocol as `server/`. The
Worker is a drop-in replacement: `companion/relay-client.js` already speaks
this HTTP API, and the CLI and extension accept any `https:` URL.

The Worker stores **opaque E2E ciphertext only**. It never sees pairing
secrets or cookie plaintext. Rooms are the multi-tenancy boundary: every
object key is `rooms/<roomId>/<blobName>`, and auth is verified before any
store access.

Point both devices at `https://sync.example.com` (replace with your Worker
custom domain) and enter the same pairing code on each.

`server/` remains the self-host / local-test relay. This Worker is the
managed Cloudflare option of the same protocol.

## HTTP API

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

Shared evaluation order (parity with `server/server.js`):

1. `/health` short-circuits with `200`.
2. Per-IP rate limit → `429` + `Retry-After: 1`. IP source is
   `cf-connecting-ip` (or `"unknown"`).
3. Path parse. `..` / `.` / `/` / NUL in a decoded segment → `400`. Wrong
   shape → `404`.
4. `roomId` must match `/^[A-Za-z0-9_-]{22}$/`; `name` (when present) must
   match `/^chromesync-[a-f0-9]+-\d+\.csync$/` → else `400`.
5. Bearer auth. Missing/malformed/charset-invalid token → `401`. Token that
   does not hash to `roomId` → `403`.
6. Per-room rate limit (only after successful auth) → `429` + `Retry-After: 1`.
7. Route dispatch. Unexpected exception → `500`.

Every response includes `X-Content-Type-Options: nosniff`. Logs are
`method roomId name status size` only — never tokens, headers, or body bytes.

## Behavioral deltas vs the Node relay

Accepted; do not fight them:

- **Raw `..` in the path.** `new URL()` (and Cloudflare edge normalization)
  collapses `/rooms/x/blobs/../y` before the handler sees it, so it yields
  `404` (wrong shape) instead of the Node server's `400`. Percent-encoded
  traversal (`%2e%2e`, `%2f`) still reaches the decode-then-validate step
  and yields `400`. Both are hard failures for the client.
- `mtime` in list responses is the R2 `uploaded` timestamp (ms), not a
  filesystem mtime. Blobs are write-once-per-name in practice.
- `413` responses do not carry `Connection: close` (connection handling
  belongs to Cloudflare).
- Node-only transport knobs (`HOST`/`PORT`, `DATA_DIR`, `TRUST_PROXY`, TLS
  certs, `headersTimeoutMs`, `maxConnections`, `maxHeaderSize`) have no
  Worker equivalent and are dropped.
- PUT quota/retention is best-effort under concurrent PUTs to one room:
  R2 has no transactions. Same room = same paired user, so races only ever
  transiently over/under-count that user's own quota.

## Config

Set as `[vars]` in wrangler config; parsed by `worker/config.js`. Values
may be TOML numbers or strings.

| Var | Default | Worker meaning |
|---|---|---|
| `MAX_BODY_BYTES` | `1048576` | PUT body cap → 413 |
| `MAX_BLOBS_PER_ROOM` | `100` | quota → 507; also list cap |
| `MAX_ROOM_BYTES` | `10485760` | quota → 507 |
| `BLOB_TTL_MS` | `604800000` (7 d) | `expiresAt` custom metadata; `0` disables |
| `RETENTION_PER_HOST` | `3` | newest-K per sourceHostId on PUT |
| `RATE_IP_CAPACITY` / `RATE_IP_REFILL` | `60` / `1` | per-isolate IP bucket |
| `RATE_ROOM_CAPACITY` / `RATE_ROOM_REFILL` | `120` / `2` | per-isolate room bucket |

Bindings: `BLOBS` (R2 bucket). No secrets, no KV, no Durable Objects, no cron.

TTL is enforced on GET/list via `expiresAt` metadata (lazy delete). An R2
lifecycle rule (7-day expiry, matching the default TTL) is the coarse
storage backstop for abandoned rooms. If an operator lowers `BLOB_TTL_MS`
below 7 days, read-time filtering still enforces the precise TTL.

## Rate limiting

Limits are **per-isolate in-memory** `TokenBucket` (reused from
`server/ratelimit.js`). A client hitting multiple colos/isolates gets N×
the nominal budget.

That is sufficient here: the limiter is not what protects rooms — **auth
is**. Reaching a room requires a token whose SHA-256 prefix matches the
22-char room ID; guessing is cryptographically infeasible at any request
rate a Worker could serve. The limiter's jobs are (a) throttling junk
traffic cost and (b) keeping one noisy client from hammering R2. Storage
abuse is independently capped by the per-room quota/retention.

Operators who want a hard global limit add a Cloudflare **WAF rate-limiting
rule** on the zone (optional runbook step below). That is configuration,
not code.

Per-IP limit runs before auth; per-room limit runs strictly after
successful auth so forged room IDs never seed a bucket.

## Deploy

The [Deploy to Cloudflare button](https://deploy.workers.cloudflare.com/?url=https://github.com/tobzey/chromesync-relay)
in the main README clones the whole repository, reads the root `wrangler.jsonc`,
and provisions the Worker and `BLOBS` R2 binding. It requires a public source repo
and your own Cloudflare account with R2 enabled. No custom domain or pairing
secret is required during deployment. Copy the resulting HTTPS Workers URL into
`chromesync setup` on your source device.

For a terminal deployment, run these commands **from the repository root**:

```sh
npx wrangler@4 login
npx wrangler@4 r2 bucket create chromesync-relay
npm run deploy:check
npm run deploy
```

Use an existing bucket instead of creating it again if it already exists. The
committed configuration has no account ID, private domain or credentials. OAuth
or `CLOUDFLARE_API_TOKEN` / `CLOUDFLARE_ACCOUNT_ID` environment variables supply
authorization. For a custom domain or bucket, copy `wrangler.jsonc` to the ignored
`wrangler.local.jsonc`, edit it, then pass `--config wrangler.local.jsonc` to Wrangler.
A copy is a complete configuration; Wrangler does not merge the two files.

After deployment:

1. Verify `curl -fsS https://YOUR-WORKER.workers.dev/health` returns `ok`.
2. Configure a seven-day object expiration rule in R2 → bucket → Settings →
   Object lifecycle rules, matching the relay's default TTL. Expiry in code is
   lazy; the lifecycle rule also clears abandoned rooms.
3. Set up Cloudflare usage alerts and suitable abuse controls. Anyone can create
   their own authenticated room, so per-room limits are not global storage/cost
   limits. See [the deployment security boundaries](../SECURITY.md).
4. Pair a source and receiver with `chromesync setup` and test with synthetic
   sessions before relying on the deployment.

Local development simulates R2 without uploading cookies:

```sh
npx wrangler@4 dev
```

The root config intentionally includes the complete repository: the Worker shares
its rate limiter with `server/`. A deploy button aimed at the `worker/` subdirectory
would lose that dependency. [Cloudflare's deploy-button documentation](https://developers.cloudflare.com/workers/platform/deploy-buttons/)
describes repository cloning and automatic resource setup.

## Tests

No network, no miniflare. Node ≥ 22 exposes `Request` / `Response` /
`crypto.subtle`, so the handler is imported directly:

```sh
npm run test:worker
```
