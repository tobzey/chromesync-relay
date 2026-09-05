> Historical design note. For current setup and supported behavior, see the root README.

# ChromeSync — Implementation Plan (thin MVP)

Chrome MV3 extension that reads the user's logged-in cookies and fans them out to
pluggable **sinks**. The extension is the SOURCE; sinks are independently
enable-able. Ship a thin working MVP, not perfect research.

## Non-negotiable rules (bake into all code, tests, docs)
- **Open-source ready.** NO hardcoded Browser Use profile UUIDs, real profile
  names, API keys, personal IDs, or private domains anywhere (code, comments,
  tests, fixtures, README). Placeholders only. Generic defaults only (e.g. sync
  interval minutes).
- **Never use real operator data in tests.** Synthetic cookies, dummy domains
  (`example.com`, `example.org`, `test.invalid`), mock BU API, isolated temp
  Chrome `--user-data-dir` only. "First sync green" = FAKE end-to-end. A live
  test happens only when the operator explicitly says go. Do not ask for his key,
  profile IDs, or cookies.
- **Security.** Never log cookie values. No telemetry. No custom cookie server.
  Sink A: HTTPS to official BU API only. Sink B: local IPC (native-messaging
  stdio) + localhost CDP only. API key/config in `chrome.storage.session`
  (documented opt-in to `chrome.storage.local`, tradeoff noted). Cookies only,
  never passwords. Explicit per-sink config; never mix profiles.

## Architecture
```
chrome.cookies (source)
      │  collect once
      ▼
  SyncEngine  ──fan out──►  Sink[]  (each: id, label, validate(), writeCookies(cookies, config))
                              ├─ LocalChromeSink  (REQUIRED)  → native host → CDP Network.setCookie
                              └─ BrowserUseSink   (OPTIONAL, stub/mock)  → HTTPS + CDP (unverified)
```
Core engine is sink-agnostic. Sinks self-register. Nothing BU-specific in core.

### Sink interface
```js
// sinks/sink.js
export class Sink {
  get id() {}          // stable slug, e.g. "local-chrome"
  get label() {}       // human label for options UI
  async validate(cfg) {}                 // -> {ok, error?}  cheap connectivity/config check
  async writeCookies(cookies, cfg) {}    // -> {written, skipped, errors:[]}  NEVER logs values
}
```

## Verified API contract (Sink A) — facts vs assumptions
- **Fact.** BU Cloud REST v3 base `https://api.browser-use.com/api/v3`. Auth header
  `X-Browser-Use-API-Key: <key>` (confirm casing at integration time). Profiles:
  `GET /profiles` (list; fields `id, name, userId, cookieDomains, lastUsedAt`),
  `PATCH /profiles/{id}`, `DELETE /profiles/{id}`.
- **Fact.** There is **no public HTTPS endpoint that uploads a cookie jar into a
  profile.** `cookieDomains` is read-only; writable profile surface is `{name, userId}`.
  The official sync mechanism is the closed-source `profile-use` binary that reads
  Chrome's cookie DB from disk.
- **Assumption (UNVERIFIED).** Cookies could be injected API-only by: create a
  browser session bound to `profileId` → push cookies over the returned CDP/WS URL
  → `PATCH /browsers/{id} {"action":"stop"}` to persist. Whether `POST /browsers`
  returns a connectable CDP URL is unconfirmed.
- **Decision for this MVP.** `BrowserUseSink` ships as an **optional stub tested
  against a local mock only.** It implements `validate()` (GET /profiles) and a
  `writeCookies()` that targets the mock. No real BU calls in tests. Real-API
  wiring is a follow-up gated on verifying the CDP path.

## Sink B — Local Chrome (REQUIRED, primary deliverable)
A Chrome extension cannot write another Chrome's encrypted cookie SQLite directly
(locked file, OS-keychain AES-GCM, Chrome must be closed). **Chosen approach:
native-messaging companion + CDP** (no SQLite/keychain surgery, cross-platform):

1. Extension collects cookies, connects to the native host via
   `chrome.runtime.connectNative("io.chromesync.host")`.
2. Native host (Node, stdlib only if possible) launches/attaches a **target Chrome**
   with a dedicated `--user-data-dir=<configured path>` and
   `--remote-debugging-port=<port>` (or attaches to an already-running debug Chrome).
3. Host speaks CDP to that Chrome and calls `Network.setCookie` (or
   `Network.setCookies`) per cookie, then `Network.getCookies` to verify.
4. Result summary (counts only, no values) returns to the extension over stdio.

**Fallback (documented, not primary):** a manual `import` CLI in the companion for
users who prefer to run it standalone.

### Native messaging manifest (`companion/io.chromesync.host.json`)
```json
{
  "name": "io.chromesync.host",
  "description": "ChromeSync local cookie sink",
  "path": "<abs path to host launcher>",
  "type": "stdio",
  "allowed_origins": ["chrome-extension://<EXTENSION_ID>/"]
}
```
Install locations: macOS
`~/Library/Application Support/Google/Chrome/NativeMessagingHosts/`, Linux
`~/.config/google-chrome/NativeMessagingHosts/`. Provide `companion/install.sh`
that writes the manifest with the real extension ID and host path (placeholders
until the user runs it).

### Cookie mapping: `chrome.cookies.Cookie` → CDP `Network.setCookie`
| chrome.cookies | CDP setCookie |
|---|---|
| `name`, `value` | `name`, `value` |
| `domain` (leading `.`) | `domain` |
| `path` | `path` |
| `secure` | `secure` |
| `httpOnly` | `httpOnly` |
| `sameSite` (`no_restriction`/`lax`/`strict`/unspecified) | `sameSite` (`None`/`Lax`/`Strict`/omit) |
| `expirationDate` (float sec) | `expires` (sec) |
| session cookie (no expiry) | omit `expires` |
Handle `__Host-`/`__Secure-` prefixes: require `secure:true`; `__Host-` requires
`path:"/"` and no `domain`. Skip cookies that violate prefix rules rather than fail
the whole sync.

## Cookie collection strategy
- `chrome.cookies.getAll({})` then filter by optional **domain allowlist** (options
  UI). Default when no allowlist: sync cookies of domains actually used (derive from
  history/tabs is out of MVP scope — default to allowlist-or-all with a clear note).
- Never write plaintext cookie exports to files. Never log values.

## File layout
```
manifest.json                 MV3 manifest (permissions: cookies, alarms, storage,
                              nativeMessaging; host_permissions minimal)
src/background.js             service worker: alarm + onStartup + onIdle → SyncEngine
src/engine.js                 SyncEngine.collect() + fanOut(enabledSinks)
src/cookies.js                pure: getAll wrapper, filter, mapping helpers (unit-tested)
src/storage.js               config get/set (session default; local opt-in)
src/sinks/sink.js            Sink base class
src/sinks/localChrome.js     LocalChromeSink (native messaging client)
src/sinks/browserUse.js      BrowserUseSink (stub, mock-targeted)
src/sinks/registry.js        sink registration/lookup
options/options.html|js|css  key entry, sink enable toggles, profile mapping, allowlist, interval
popup/popup.html|js          sync-now + last-sync status
companion/host.js            native messaging host (stdio ↔ CDP)
companion/cdp.js             minimal CDP client (WebSocket)
companion/io.chromesync.host.json  manifest template
companion/install.sh         register native host (Mac + Linux)
test/                        unit + integration (mocks + fakes only)
mock/bu-api.js               local mock Browser Use API server
README.md                    install, key, sinks, schedule, security (placeholders only)
```

## Scheduling
`chrome.alarms.create("sync", {periodInMinutes: <cfg, default 45>})` +
`chrome.runtime.onStartup` + `chrome.idle.onStateChanged` (active→idle triggers sync).

## Error handling & rate limiting
Exponential backoff on sink errors; partial-failure reporting in popup (counts +
generic messages, never cookie values); one sink failing must not abort others.

## Test plan (synthetic data ONLY)
1. **Unit** (node test runner or vitest, no browser): `cookies.js` filtering,
   sameSite/expiry mapping, `__Host-`/`__Secure-` rules, allowlist — synthetic
   `Cookie` objects.
2. **Sink A integration:** `BrowserUseSink.validate()`/`writeCookies()` against
   `mock/bu-api.js`. Assert requests shaped correctly; no network to real BU.
3. **Sink B end-to-end (the "first sync green"):** launch a throwaway Chrome with a
   temp `--user-data-dir` + `--remote-debugging-port`, run the native host path (or
   the host's CDP module directly), inject synthetic cookies for `example.com`,
   assert presence via CDP `Network.getCookies`. Zero real login.
4. **Load check:** `manifest.json` validates; extension loads unpacked (documented
   manual step + a JSON-schema sanity test).

## Test data policy
No real cookies, keys, profile UUIDs, or logins, ever, in any test/fixture/doc.
Dummy domains only. Live test only on explicit operator "go".

## Security checklist (final reviewer verifies)
- [ ] No UUIDs/keys/real domains/personal IDs in tree (grep clean).
- [ ] `allowed_origins` in native manifest scoped to the one extension ID.
- [ ] Host never executes arbitrary commands from the extension; fixed Chrome launch args.
- [ ] No cookie values in any log/error/telemetry (there is no telemetry).
- [ ] Key only in `chrome.storage.session` by default.
- [ ] Sink A HTTPS-only; Sink B localhost/stdio-only.

## README outline (placeholders only)
Install unpacked → set API key (optional, Sink A) → enable sinks → configure target
Chrome user-data-dir (Sink B) → register native host (`install.sh`) → schedule →
security notes.

## Success bar for THIS run
Extension loads unpacked + fake E2E green for the Local Chrome sink. Thin working
MVP over perfect research. Do not invent green.

## Follow-up: cross-machine sync + profile-use wrap
Two new capabilities layered on the existing companion. Native messaging stays
per-host exactly as today (`LocalChromeSink` → `io.chromesync.host` → CDP). Build
in the stated order: transport A first and green before starting the Sink A wrap.

### 1) Cross-machine transport A — encrypted file drop (build FIRST)
Sync cookies between two machines by dropping an AEAD-encrypted blob into a
user-chosen shared folder (Syncthing / iCloud Drive / any synced dir). The folder
sync is out of our code — we only write/read blob files in it.

- **Pairing secret.** One shared secret string, entered on BOTH machines (Options /
  companion config field, never hardcoded, never logged). No secret ever leaves the
  two hosts; no network.
- **KDF + AEAD (pick ONE, chosen):** **scrypt (`crypto.scryptSync`, N=2^15, r=8,
  p=1) → 32-byte key + AES-256-GCM (`crypto.createCipheriv("aes-256-gcm", …)`).**
  Justification (one line): both are in stock Node `crypto` with zero new deps;
  scrypt is memory-hard against brute-forcing a human-typed pairing secret and
  AES-256-GCM gives authenticated encryption with a built-in 16-byte tag.
  (Note: XChaCha20-Poly1305 is NOT in stock Node `crypto`, so it is rejected.)
- **Per-blob salt + nonce.** Fresh random 16-byte scrypt salt AND fresh random
  12-byte GCM IV per blob (`crypto.randomBytes`), both stored in the header. Key is
  re-derived per blob from (secret, salt) — never reuse an (key, IV) pair.
- **Blob format (facts, not negotiable):**
  - Filename scheme: `chromesync-<sourceHostId>-<counter>.csync` written to the drop
    folder; `sourceHostId` is a random non-identifying slug generated once per host
    (no machine name, no user id).
  - Header (plaintext, authenticated as GCM AAD so tamper is caught): magic ASCII
    `CSYNC`, `version` byte `0x01`, 16-byte salt, 12-byte IV, `counter` (u64), and
    `createdAt` (u64 epoch ms). Then ciphertext, then 16-byte GCM tag.
  - Ciphertext payload = JSON of the CDP-shaped cookie array (same shape
    `mapCookies` in `src/cookies.js` already produces) — NOT the raw MV3 array.
  - **Atomic write:** write to `*.csync.tmp` in the same folder, `fsync`, then
    `fs.renameSync` to the final name so a reader never sees a partial blob.
- **Tamper behavior = HARD FAIL.** GCM auth-tag or AAD mismatch → reject the whole
  blob, inject nothing (no partial inject), surface a generic error (no cookie
  data, no secret). Same hard-fail for bad magic / unknown version.
- **Target side reuse (name the real path):** target companion watches/reads the
  drop folder, decrypts + verifies, parses the cookie array, and injects by reusing
  the EXISTING Sink B path — `setCookiesOp(...)` in `companion/host-core.js` (which
  calls `launchChrome` + `applyCookies` → `Storage.setCookies` via
  `CdpClient` in `companion/cdp.js`) into the configured local
  `--user-data-dir`. No new CDP code.
- **No plaintext on disk, ever.** Decrypted cookies live only in memory on the way
  to `applyCookies`. No plaintext cookie file is written; cookie values never appear
  in logs or error messages (reuse the existing `genericError` discipline).

**Facts vs assumptions**
- Fact: `crypto.scryptSync`, `createCipheriv`/`createDecipheriv` with `aes-256-gcm`,
  `setAAD`, `getAuthTag`/`setAuthTag`, and `randomBytes` are all in stock Node.
- Fact: `setCookiesOp`/`applyCookies`/`readCookies` already exist and are unit/E2E
  exercised in `test/e2e-localchrome.test.js`.
- Assumption (UNVERIFIED): shared-folder tools deliver whole files atomically enough
  that temp-write+rename is sufficient; mitigated because a torn read fails the GCM
  check and is hard-rejected anyway.

**Test plan (fake store, synthetic data only)**
- [ ] Unit: fake drop store = a `fs.mkdtempSync` temp dir; encrypt `syntheticCookies`
  (`test/fixtures.js`) → write blob → list dir → read/decrypt → assert byte-equal
  cookie array. Dummy domains only (`example.com`, `example.org`, `test.invalid`).
- [ ] Round-trip encrypt→decrypt→inject against the EXISTING throwaway-Chrome harness
  in `test/e2e-localchrome.test.js` (`launchChrome` + `applyCookies` + `readCookies`
  on a temp `--user-data-dir`); skip (not fail) when no Chrome, matching that file.
- [ ] Negative: wrong pairing secret → decrypt throws → hard fail, nothing injected.
- [ ] Negative: corrupted/truncated blob (flip a ciphertext byte; drop trailing
  bytes) → auth-tag/format mismatch → hard fail.
- [ ] Negative: replayed/stale blob → rejected by a **monotonic freshness check**:
  target persists the highest `counter` seen per `sourceHostId` and rejects any blob
  whose `counter` is <= the last accepted one (and may also reject `createdAt` older
  than a configurable staleness window). Assert a replayed blob is refused.

### 2) Sink A wrap of the `profile-use` CLI (start ONLY after 1 is green)
`BrowserUseSink` gains a real path that shells out to the closed-source
`profile-use` binary instead of the unverified HTTPS session flow. Gated, never
crashes.

- **Enablement gate (all must hold, else DISABLED):**
  - Env `BROWSER_USE_API_KEY` is set (non-empty). Missing → disabled with actionable
    error, no shell-out.
  - A `profile-use` binary is found on `PATH` (resolve via `which profile-use` /
    scan `PATH` entries; no hardcoded path).
  - **Version check:** invoke `profile-use --version`, capture stdout, parse the
    first `\d+\.\d+\.\d+` semver, compare numerically (major, then minor, then
    patch) against a `MIN_PROFILE_USE_VERSION = "1.0.5"` constant. `< 1.0.5` →
    disabled with "profile-use >= 1.0.5 required, found X.Y.Z".
  - On any gate failure the sink returns `{ ok:false, error: <clear message> }` from
    `validate()` and refuses `writeCookies()` gracefully — NEVER throws/crashes.
- **Source is a Chrome profile DIRECTORY, not the MV3 cookie array.** `profile-use
  sync` reads Chrome's on-disk cookie DB. The companion selects that dir from an
  explicit config/message field (e.g. `profileUseDir` in the sink config, same
  channel `userDataDir` arrives on for `LocalChromeSink`). Validate it: non-empty,
  absolute, exists, is a directory — else disabled with a clear error. Do NOT feed
  it the collected `chrome.cookies` array.
- **Invocation:** `spawn("profile-use", ["sync", "--user-data-dir", <dir>, ...])`
  with `BROWSER_USE_API_KEY` passed via the child env (never on argv, never logged),
  fixed args only (mirror the "no arbitrary commands" rule). Non-zero exit → generic
  error, counts-only result, no cookie/key data leaked.

**Test plan (fake CLI, mock HTTPS retained)**
- [ ] Keep the existing mock HTTPS stub **`createMockBuServer`** in `mock/bu-api.js`
  (used by `test/browserUse.test.js`) for the existing `validate()`/session-flow
  tests — do not delete it.
- [ ] New tests use a **FAKE `profile-use` executable** placed on a temp `PATH`: a
  tiny script that records `argv` + relevant env to a file and exits with a
  controlled code. Cover:
  - [ ] Happy path: key set, fake binary v1.0.5, valid dir → shell-out invoked with
    expected argv; env carries the key; success result.
  - [ ] Missing binary (empty PATH) → disabled, actionable error, no crash.
  - [ ] Version too old (fake reports `1.0.4`) → disabled with version message.
  - [ ] Missing `BROWSER_USE_API_KEY` → disabled, no shell-out.
  - [ ] CLI nonzero exit → generic error surfaced, counts-only, no leak.

### 3) Out of scope (explicit)
- Tailscale (or any VPN/mesh) relay as the transport — NOT in this job.
- Browser Use Cloud as the mesh bus / message broker between machines — NOT in this
  job. Transport A is dumb file drops only.

### 4) Hard rules (restated for this follow-up)
- Open-source ready: nothing hardcoded — no private IDs, keys, UUIDs, real domains,
  real profile names, machine names. Pairing secret, drop-folder path, profile dir,
  and API key are all runtime config/env, placeholders in the repo.
- Never real operator data in tests: no real cookies/keys, no `amazon.de` or other
  real sessions, no real profile UUIDs. Synthetic cookies (`test/fixtures.js`),
  dummy domains, fake drop store (temp dir), fake `profile-use` CLI only.
- No plaintext cookie files on disk; decrypt-to-memory only.
- No cookie-value logging anywhere (blobs, errors, CLI stdout/stderr handling).
- Live real-cookie Browser Use sync is NOT in this job — it requires a later,
  explicit operator "go".

### Success bar for THIS run
- [ ] PLAN appended (this section).
- [ ] Encrypted file-drop transport A tests green against the fake store (temp dir),
  including the three negative cases.
- [ ] `profile-use` wrap tests green against the fake CLI (happy + all gate/failure
  cases), mock HTTPS stub retained.
- [ ] Extension still loads unpacked (`npm run test:load` / `manifest.test.js`
  unaffected).

## Transport C — VPS relay (self-hosted, no iCloud/Syncthing)

A third cross-machine transport that needs no shared folder and no third-party
sync tool: a tiny self-hosted relay on the operator's own VPS that clients
**push** encrypted blobs to and **pull** them from. Layered on the existing
companion exactly like transports A/B — **`companion/drop-crypto.js` and its
`CSYNC` blob are reused byte-for-byte and are NOT changed.** The relay is
**untrusted storage/transport**: it only ever holds opaque ciphertext, never the
plaintext, never the encryption key, never the pairing secret. Same-machine Sink
B, encrypted file-drop transport A, and the `profile-use` wrap (commit 535fd41)
stay exactly as-is.

### Threat model (state it plainly)
- The relay is honest-but-curious **and** may be fully breached. It sees: TLS
  metadata, the `Authorization` bearer token, the room id, blob names
  (`chromesync-<hostId>-<counter>.csync`), blob sizes/mtimes, and the opaque
  `CSYNC` bytes (which include a **plaintext scrypt salt** in the header).
- **What the relay CANNOT do:** read cookies (AES-256-GCM, key never sent),
  forge a blob another client will accept (AEAD auth + AAD over the header),
  or read/write a room whose token it does not possess.
- **What an untrusted relay CAN do (accepted, documented):** (1) **availability
  attacks** — drop/withhold blobs; we protect integrity + confidentiality, not
  availability. (2) **offline brute-force of the pairing secret** — it holds the
  ciphertext and the per-blob salt, so it can run a scrypt-bounded dictionary
  attack. This is the SAME exposure transport A already accepts (Syncthing/iCloud
  also hold the blob), so it is not a regression — but it makes **pairing-secret
  entropy the linchpin.** Decision below: the invite/generate path mints a
  **high-entropy random secret**, and manual entry warns that a weak code is
  brute-forceable by whoever hosts or breaches the relay.

### Facts vs assumptions
- **Fact.** `crypto.scryptSync`, `createHmac`, `createHash`, `timingSafeEqual`,
  `randomBytes`, and `node:http`/`node:https` are all stock Node — **zero new
  deps**, client and server.
- **Fact.** The extension already talks ONLY to the native host
  (`chrome.runtime.connectNative("io.chromesync.host")`); the companion performs
  all HTTP. So **no new `host_permissions` and no new manifest permissions are
  required** for the relay (the existing `<all_urls>` host permission is for
  reading cookies, unrelated). Confirmed against `manifest.json`.
- **Fact.** `setCookiesOp`/`applyCookies`/`launchChrome` (`companion/host-core.js`)
  and `importBlob`/`checkFreshness`/`recordAccepted`/`allocateExport`
  (`companion/drop.js`, `companion/drop-store.js`) already exist and are E2E
  exercised — the inject + replay-protection path is reused unchanged in behavior.
- **Assumption (UNVERIFIED).** A 30–60 s `chrome.alarms` poll is "low latency
  enough" for the target. No websocket/long-poll push channel is used, to keep
  the relay stateless and dependency-free. Mitigated: poll cadence is config.
- **Assumption (UNVERIFIED).** The reverse proxy (nginx/Forge/Let's Encrypt)
  terminates TLS with a valid cert. The client keeps Node's default cert
  validation ON (never `rejectUnauthorized:false`); a self-signed cert is
  rejected by design.

### Blob (reused, not negotiable)
The exact `CSYNC` blob from transport A: `MAGIC "CSYNC"` + version `0x01` + 16-byte
random scrypt salt + 12-byte random GCM IV + `counter` (u64) + `createdAt` (u64) as
authenticated header/AAD, then AES-256-GCM ciphertext of the CDP-shaped cookie
JSON, then the 16-byte tag. Filenames stay `chromesync-<sourceHostId>-<counter>.csync`
(`blobFilename`, `FILENAME_RE`). The relay stores/serves these bytes verbatim.

### Auth + room derivation (stateless, capability-based — final)
The relay needs **no account DB** and never learns the encryption key. Everything
is derived from the shared pairing secret; two machines with the same secret land
in the same room deterministically. Put derivation in **one** module
(`companion/relay-auth.js`) so client and tests agree; the server recomputes only
the last step (`server/auth.js`), with a parity test asserting the two match.

- `relayMaster = scryptSync(secret, "chromesync-relay-v1", 32, {N:2^15,r:8,p:1,
  maxmem:64MiB})` — a **fixed context salt**, so it is deterministic across
  machines. Computed **once per secret and cached** (module-level, keyed by
  `sha256(secret)`, single entry) — scrypt is expensive; never per request.
  This is a **separate derivation** from the encryption key
  (`scrypt(secret, per-blob RANDOM salt)`), so possessing the token does not help
  decrypt.
- `token = base64url(HMAC-SHA256(relayMaster, "chromesync-relay-token"))` —
  a 256-bit bearer, sent ONLY as `Authorization: Bearer <token>` over TLS,
  **never in a URL, never logged.** HMAC is a PRF: the token leaks nothing about
  `relayMaster`/secret beyond scrypt-bounded brute force.
- `roomId = base64url(SHA-256(token)).slice(0, 22)` — ~128-bit non-identifying id
  (no host/user info). Goes in the URL path. Because `SHA-256` is preimage- and
  second-preimage-resistant, knowing a `roomId` does not yield a `token`, and a
  stranger cannot craft a token that hashes to a victim's `roomId` (2^128 work).
- **Server verification (every request, stateless):** validate the `:roomId` path
  segment matches `^[A-Za-z0-9_-]{22}$` (reject otherwise → 400); require a
  well-formed bearer token (else 401); recompute `base64url(sha256(token))[:22]`
  and `crypto.timingSafeEqual` it (equal-length buffers only) against the path
  `:roomId`; mismatch → 403. A stranger without the secret cannot produce a valid
  `(token, roomId)` pair. Blobs are AEAD-encrypted regardless, so even a
  hypothetical roomId collision cannot leak plaintext (defense in depth).
- **Multi-tenancy:** every list/get/put/delete is scoped to `DATA_DIR/<roomId>/`
  and gated by the hash check, so room X can never see or touch room Y.
- **Rotation:** no key rotation; if a secret leaks, pick a new secret → new room.
  Documented, not automated.

### Relay HTTP API (Node stdlib `http` only, no framework)
Paths, all under a verified room. `:name` MUST match the existing
`^chromesync-[a-f0-9]+-\d+\.csync$` (reuse `parseBlobFilename`); anything else
(`..`, `/`, wrong pattern, over-long) → **400** (blocks path traversal). Resolve
the on-disk path as `join(DATA_DIR, roomId, name)` AND assert the resolved
realpath is still inside `DATA_DIR/roomId` (belt-and-suspenders).

- `PUT /rooms/:roomId/blobs/:name` — body = raw `CSYNC` bytes. Enforce **max body
  1 MiB by counting streamed bytes** (do not trust `Content-Length`; abort at the
  cap → 413). On success apply **per-room retention** (see limits) → 204/200.
- `GET /rooms/:roomId/blobs` — JSON list of `{name, size, mtime}` only (never
  bodies). Bounded output.
- `GET /rooms/:roomId/blobs/:name` — raw bytes (opaque), `application/octet-stream`.
- `DELETE /rooms/:roomId/blobs/:name` — optional manual cleanup → 204. **Pull is
  NOT destructive** (another target machine may still need the blob); routine
  bounding is server-side retention + TTL, not delete-on-read.
- Unknown method → 405; unknown path → 404; missing/blank token → 401.

**Limits / DoS (all env-configured, sane defaults):**
- `MAX_BODY_BYTES` = 1 MiB (streamed enforcement → 413).
- **Per-`(roomId, sourceHostId)` retention:** on PUT, keep only the newest `K`
  (default 3) blobs of that host prefix, delete older — bounds storage and gives
  latest-wins regardless of client cleanup. (`sourceHostId`/`counter` parsed from
  the regex-validated name.)
- `MAX_BLOBS_PER_ROOM`, `MAX_ROOM_BYTES` → 413/507 when exceeded.
- `BLOB_TTL_MS` → periodic sweep deletes blobs older than TTL.
- **Token-bucket rate limit per IP and per room** → 429. IP taken from the socket
  by default; `TRUST_PROXY` (off by default) enables a trusted `X-Forwarded-For`
  parse for the reverse-proxy case (spoofable if trusted blindly — documented).
- Request header/body timeouts (slowloris), max header size, connection cap.
- **TLS** terminated by the reverse proxy by default (server binds plain HTTP on
  loopback/private behind the proxy); OPTIONAL native TLS via `TLS_CERT`/`TLS_KEY`
  env cert paths — document both.
- **No redirects ever** (stdlib `http` does not auto-issue them). **Logging:**
  method, roomId (public), name, status, size ONLY — never the `Authorization`
  header, token, secret, or blob bytes.

### Client: new `relay` sink + companion push/pull
- **`src/sinks/relay.js` — `RelaySink`** mirrors `FileDropSink`: `id "relay"`,
  `label "Encrypted sync server"`. `validate(cfg)` → native `{type:"relayValidate"}`;
  `writeCookies(cookies, cfg)` → native `{type:"relayPush", cookies, ...}`. Same
  `connectNative("io.chromesync.host")` transport, same generic-error discipline,
  same `#exportFields`-style config marshalling (relayUrl, pairingSecret,
  sourceHostId, statePath, userDataDir/port for the pull side, mode). Register in
  `src/sinks/registry.js`. Push runs inside the existing `SyncEngine` fan-out.
- **Companion HTTP client `companion/relay-client.js`** (stdlib `https`/`http`,
  zero deps): `relayPush`, `relayList`, `relayGet`, `relayDelete`, each taking
  `{relayUrl, token, roomId, name?, blob?}`. **SSRF/open-redirect guards:** parse
  with `new URL`; require `https:` OR (`http:` AND hostname ∈
  {`localhost`,`127.0.0.1`,`::1`}) for local tests only; reject any URL carrying
  `username`/`password`; build request paths from a fixed template +
  `encodeURIComponent(roomId)`/`encodeURIComponent(name)` (both already
  regex-validated); treat any `3xx` as an error (never follow); keep default cert
  validation ON; cap response bodies (blob ≤ 1 MiB, list bounded); never log the
  token or a secret-bearing URL.
- **`companion/host-messages.js` new cases:**
  - `relayValidate`: config checks (secret + relayUrl present, scheme allowed,
    `sourceHostId` matches `HOST_ID_RE` if given, companion state writable via
    `ensureStateWritable`), then a cheap `relayList` with a short timeout —
    map network error → "cannot reach sync server", 401/403 → "wrong pairing code
    or server", 2xx → ok. Generic strings only.
  - `relayPush`: derive `{token, roomId}` (cached `relayMaster`); **encrypt +
    allocate counter WITHOUT writing a folder** via a new
    `exportBlobWithState(...)` in `drop.js` (reuses `allocateExport` +
    `encryptCookies`, returns `{blob, filename, counter, sourceHostId, state}`);
    `relayPush` the bytes to `PUT /rooms/:roomId/blobs/:filename`; **persist the
    incremented counter to state only on 2xx** (so a failed push retries the same
    counter); best-effort ignore of retention. Return counts, no values.
  - `relayPull`: derive `{token, roomId}`; `relayList`; for each name whose
    `counter` exceeds the last accepted for its `sourceHostId` (parse via
    `parseBlobFilename`, compare to `state.replay`), `relayGet` the bytes and run
    `importBlob({blob, sourceHostId, secret, state, maxAgeMs, inject})` where
    `inject = setCookiesOp({userDataDir, port, cookies})`. `importBlob` enforces
    AEAD auth + monotonic counter (tamper/replay → rejected, nothing injected) and
    `recordAccepted` runs only after a fully successful inject. Persist state.
    **Non-destructive** (no DELETE). Return counts.
- **`companion/drop.js` edits:** add `exportBlobWithState(...)` (folder-free blob
  producer described above) and **extend `importBlob` to accept `{ blob }` bytes**
  in addition to `{ filePath }` (if `blob` is given, skip `fs.readFileSync`);
  fully backward compatible with the file-drop callers. No change to
  `drop-crypto.js`.
- **`companion/host.js` edit:** add a `relay-pull` CLI mode mirroring the existing
  `import-drop` mode, reading `CHROMESYNC_RELAY_URL`, `CHROMESYNC_PAIRING_SECRET`,
  `CHROMESYNC_USER_DATA_DIR`, `CHROMESYNC_PORT`, `CHROMESYNC_STATE_PATH`,
  `CHROMESYNC_MAX_AGE_MS`; prints counts + generic errors only, for cron/manual use
  on a target machine.

### Background auto-sync (cookie `onChanged` debounce + poll) — MV3-safe
The service worker can be evicted, so **debounce/throttle must use
`chrome.storage` + `chrome.alarms`, never a `setTimeout` timer** (a JS timer dies
with the SW). Extract the pure decision logic to `src/autosync.js` for unit
testing; wire it in `src/background.js`.
- **Coalesced push on change:** `chrome.cookies.onChanged` sets a `pendingSync`
  flag in storage and creates a **one-shot coalescing alarm** (e.g.
  `sync-coalesce`, ~30 s) if one is not already pending. When it fires, run one
  sync and clear the flag — so a burst of cookie writes collapses into a single
  sync. Add a **min-interval throttle:** persist `lastSyncAt`; if a change arrives
  within the throttle window, defer to the next alarm instead of syncing again.
- Keep the existing `chrome.alarms` periodic sync + `onStartup` + `idle` triggers.
- **Target poll:** schedule a `relay-pull` alarm from `relay.pollMinutes` (default
  1); on fire, if the relay sink is enabled and `mode` includes pull, open a native
  port and post `{type:"relayPull", ...}`. Pull is inbound, so it does NOT go
  through the sink fan-out.
- **No feedback loop:** the extension's `chrome.cookies` watches its OWN browser;
  the companion injects into a SEPARATE target `--user-data-dir`, so injection
  never re-triggers the source's `onChanged` (true even in `mode:"both"`, since
  source and target are different profiles). Documented.
- New top-level config `syncOnChange` (default `true`).

### Config + Options UX (non-techie, no crypto jargon)
- **`src/storage.js` `DEFAULT_CONFIG`:** add `syncOnChange: true` and a `"relay"`
  sink: `{ enabled:false, relayUrl:"", pairingSecret:"", mode:"push"
  ("push"|"pull"|"both"), sourceHostId:"", statePath:"", userDataDir:"", port:0,
  pollMinutes:1, maxAgeMs:0 }` (`maxAgeMs:0` = counter-only freshness, no staleness
  window). `deepMerge` handles the new sink automatically.
- **`options/options.html` + `options/options.js`:** a "Sync server" card with
  plain labels — "Sync server address" (relayUrl), "Pairing code" (pairingSecret),
  "This device" (Send changes / Receive changes / Both = mode), "Target Chrome
  folder" + "port" (pull side), "Auto-sync when cookies change" (`syncOnChange`).
  No "AEAD/scrypt/HMAC/nonce" words anywhere in the UI.
- **One-line invite (`src/invite.js`, pure + tested):** `buildInvite({relayUrl,
  secret})` → `csync1.<base64url(json)>`; `parseInvite(str)` validates the
  `csync1.` prefix, base64url-decodes, JSON-parses, checks `relayUrl` scheme and a
  non-empty length-bounded `secret`. Options shows **"Copy invite link"** (source)
  and **"Paste invite"** (target, one paste fills both fields) with a clear warning
  that the link **contains the pairing code — share it privately** (base64 is
  encoding, not encryption). Manual two-field entry stays the primary path.
- **Strong-secret default:** a "Generate a strong pairing code" button mints
  `base64url(randomBytes(16))` (~128-bit). Copy points back to the threat model:
  the untrusted relay can brute-force a weak human-chosen code offline.

### Server layout + Dockerfile + deploy (placeholders only)
```
server/
  server.js        node:http router, limits, TLS-optional, graceful shutdown
  auth.js          roomIdForToken(token) + timingSafeEqual verify (parity-tested
                   against companion/relay-auth.js)
  store.js         fs ops scoped to DATA_DIR/<roomId>; retention + quota + TTL sweep
  ratelimit.js     token-bucket per IP + per room
  config.js        env parsing (PORT, DATA_DIR, MAX_BODY_BYTES, MAX_BLOBS_PER_ROOM,
                   MAX_ROOM_BYTES, BLOB_TTL_MS, RATE_*, TRUST_PROXY, TLS_CERT,
                   TLS_KEY) with safe defaults
  Dockerfile       node:22-alpine, non-root user, EXPOSE, HEALTHCHECK, CMD node server.js
  .dockerignore
  README.md        run/deploy notes — PLACEHOLDERS ONLY (relay.example.com,
                   DATA_DIR=/var/lib/chromesync-relay), nginx TLS-termination
                   snippet, docker/systemd, "point the extension at https://<your-host>"
```
Zero new npm deps (stdlib only). **Open-source clean:** no real hostname/IP/Forge
project baked into any file — the concrete first deploy target is tracked
**out-of-repo** in operator notes, never committed. README and code use
`https://relay.example.com` and generic paths.

### Test plan (synthetic data only, real local relay)
Start the **real** `server.js` on `127.0.0.1:0` (ephemeral) with a `mkdtempSync`
`DATA_DIR`; use `test/fixtures.js` `syntheticCookies` and dummy domains only.
- **`test/relay-auth.test.js`** — determinism: same secret ⇒ same `token`/`roomId`
  (two independent derives); different secret ⇒ different room; `token ≠ roomId`;
  `roomId` matches `^[A-Za-z0-9_-]{22}$`; **parity** between
  `companion/relay-auth.js` and `server/auth.js` `roomIdForToken`; assert the token
  reveals nothing usable to decrypt (encryption key path is independent).
- **`test/relay-server.test.js`** — PUT→list→GET round-trip preserves bytes
  **byte-for-byte** (opaque store); on-disk file bytes == uploaded bytes; wrong
  token ⇒ 403; valid token but wrong `:roomId` ⇒ 403; missing/blank auth ⇒ 401;
  oversized body ⇒ 413; bad `:name` (`../`, wrong pattern) ⇒ 400; bad `:roomId`
  (not 22 base64url) ⇒ 400; rate limit ⇒ 429; per-host retention prunes the oldest
  when > K; TTL sweep removes an aged blob; DELETE ⇒ 204.
- **`test/relay-client.test.js`** — against the real server: push→list→pull happy
  path with `syntheticCookies` through encrypt/decrypt (byte-equal cookie array);
  SSRF guards: non-loopback `http:` rejected, URL with credentials rejected, a
  server returning `302` rejected (no redirect follow); **replay** — pulling the
  same blob twice, second rejected by the monotonic counter; **tamper** — flip one
  ciphertext byte server-side ⇒ AEAD auth fail, nothing injected.
- **`test/e2e-relay.test.js`** — full push → real server → pull → inject into a
  throwaway Chrome (reuse the `e2e-file-drop.test.js` harness: `launchChrome` +
  `readCookies`), assert `session_id`/`__Host-token` present; assert **no stored
  blob on the server contains any plaintext cookie value** and **no plaintext
  cookie file exists**; `{ skip: no Chrome }` like the existing E2E files.
- **`test/relay-wiring.test.js`** — `RelaySink` posts the correct native messages
  (mirror `file-drop-wiring.test.js`); `DEFAULT_CONFIG` includes the `relay` sink;
  `buildRegistry` returns it.
- **`test/invite.test.js`** — `buildInvite`→`parseInvite` round-trip; malformed
  prefix / bad base64 / bad scheme / empty secret rejected.
- **`test/autosync.test.js`** — `src/autosync.js` coalesces a burst of cookie
  changes into one sync and the throttle blocks a too-soon re-sync (fake
  alarms/storage, no browser).

### File-by-file change list (for the Developer)
**New files**
- `src/sinks/relay.js` — `RelaySink` (mirrors `FileDropSink`).
- `src/invite.js` — `buildInvite` / `parseInvite`.
- `src/autosync.js` — pure coalesce/throttle decision helper.
- `companion/relay-auth.js` — `deriveRelayAuth(secret)` → `{relayMaster(cached),
  token, roomId}`, plus `roomIdForToken(token)`.
- `companion/relay-client.js` — `relayPush`/`relayList`/`relayGet`/`relayDelete`
  with SSRF/redirect/TLS guards.
- `server/server.js`, `server/auth.js`, `server/store.js`, `server/ratelimit.js`,
  `server/config.js`, `server/Dockerfile`, `server/.dockerignore`, `server/README.md`.
- Tests: `test/relay-auth.test.js`, `test/relay-server.test.js`,
  `test/relay-client.test.js`, `test/e2e-relay.test.js`,
  `test/relay-wiring.test.js`, `test/invite.test.js`, `test/autosync.test.js`.

**Edited files**
- `src/sinks/registry.js` — register `RelaySink`.
- `src/storage.js` — add `syncOnChange` + `"relay"` sink to `DEFAULT_CONFIG`.
- `companion/drop.js` — add `exportBlobWithState(...)`; extend `importBlob` to
  accept `{ blob }` bytes. **Do NOT touch `companion/drop-crypto.js`.**
- `companion/host-messages.js` — add `relayValidate` / `relayPush` / `relayPull`.
- `companion/host.js` — add `relay-pull` CLI mode.
- `src/background.js` — `chrome.cookies.onChanged` coalesce+throttle (alarms+storage);
  `relay-pull` alarm scheduler + native-port handler.
- `options/options.html`, `options/options.js` — relay fields, auto-sync toggle,
  invite generate/copy/paste + strong-code button + private-share warning.
- `manifest.json` — **confirm no new permissions needed** (expected: no change).
- `package.json` — extend `test:unit`/`test:e2e` script lists with the new tests;
  optional `relay:serve` and `test:relay` scripts.
- `README.md` — relay setup section, placeholders only.

**New dependencies:** none (client and server are stock Node `crypto` + `http`).

**Developer cautions**
- Never modify `drop-crypto.js`; reuse the `CSYNC` blob byte-for-byte.
- Debounce/throttle MUST be alarms+storage, never `setTimeout` (SW eviction).
- `timingSafeEqual` needs equal-length buffers — validate `roomId` length/charset
  BEFORE comparing.
- Never disable TLS verification; never log the token, pairing secret, or blob.
- Persist the export counter only after a successful PUT; keep pull non-destructive.
- Bound storage on the server (retention + quota + TTL) so a chatty source can't
  fill the disk.
- Keep the repo placeholder-clean; the real deploy target lives out-of-repo.

### Success bar for THIS run (Transport C)
- [x] PLAN appended (this section).
- [x] Real local relay round-trip green: push → list → pull → inject synthetic
  cookies (E2E skips cleanly with no Chrome).
- [x] Auth/room negatives green: wrong token 403, token/roomId mismatch 403,
  missing auth 401, oversized 413, bad name/roomId 400, rate limit 429.
- [x] Replay rejected by monotonic counter; tampered blob fails AEAD, nothing
  injected; server stores only opaque bytes (no plaintext value on disk).
- [x] `relay-auth` determinism + client/server parity green; SSRF/redirect guards
  green; invite round-trip green; autosync coalesce/throttle green.
- [x] Extension still loads unpacked; no new manifest permissions; zero new deps.
