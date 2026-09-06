# ChromeSync private Cloudflare relay

The Worker stores opaque encrypted snapshots in R2. All room operations require
both a valid room capability and an exact ID in operator-managed `ALLOWED_ROOMS`.
The default admits no rooms. `/health` is public. The relay never receives source
signing keys or cookie plaintext. Each receiver uses a separate room; receiver
signatures and replay validation happen at the endpoints.

See [relay operations](../docs/relay-operations.md) for the required lifecycle,
alert worker, webhook secrets, room admission, budget controls and verification.
Deploy the alert worker before the main worker. `BLOBS` is the R2 binding;
`ALERT_WEBHOOK_URL` is a secret; `ALERT_STORAGE_BYTES` controls the hourly audit.
`wrangler.jsonc` attaches the Tail Worker for denial/rate/quota alerts.

`npm run deploy:check` builds without deployment. `npm run test:worker` exercises
R2 conformance, limits, expiry and the HTTP client using synthetic data.
Per-room quotas and isolate rate limits remain best effort across concurrent
requests. They do not impose an account-wide spending ceiling. Physical expiry
of unvisited objects depends on applying the provided R2 lifecycle policy.
