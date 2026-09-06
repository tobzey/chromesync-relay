# Private relay operations

Room IDs are public identifiers; bearer capabilities stay on paired endpoints.
`chromesync approve` and `chromesync devices --name work` print the room IDs for
operator admission. Configure a comma-separated `ALLOWED_ROOMS` on either Node
or Workers. Empty/missing configuration denies every room even for a valid
self-generated bearer token. `/health` stays public and is not an admission test.
Remove a revoked device's room from this list as well as running `chromesync revoke`.

## Cloudflare deployment

Use a private account/bucket. These commands change your own infrastructure;
choose the account, webhook receiver, threshold and admitted rooms explicitly.
No keys or destinations are supplied by the repository.

1. Create the `chromesync-relay` R2 bucket (or change its binding).
2. Export `CLOUDFLARE_ACCOUNT_ID`, `CLOUDFLARE_API_TOKEN` with R2 lifecycle permissions,
   and optionally `R2_BUCKET`. Run `node scripts/relay-ops.js apply`. It preserves
   unrelated lifecycle rules and reads the policy back. `node scripts/relay-ops.js`
   only checks. Supplied policy expires `rooms/` objects at seven days and aborts
   incomplete uploads at one day. Provider deletion is asynchronous.
3. Deploy the alert consumer first: `npx wrangler@4 deploy --config deploy/alerts.wrangler.jsonc`.
   Set `ALERT_WEBHOOK_URL` using `npx wrangler@4 secret put ALERT_WEBHOOK_URL --config deploy/alerts.wrangler.jsonc`.
   Use an HTTPS receiver accepting JSON, with deduplication and notification
   rate limits. The URL is a secret; do not put it into vars or Git.
4. Set exact `ALLOWED_ROOMS` in your private Wrangler configuration. Deploy the
   relay with `npx wrangler@4 deploy`; set its `ALERT_WEBHOOK_URL` secret too.
   The main configuration attaches `chromesync-alerts` as its Tail Worker and
   schedules the storage audit hourly. Keep logging at sampling rate 1 for alerts.
5. `ALERT_STORAGE_BYTES` defaults to 100 MiB across all `rooms/` objects.
   Tail alerts notify on quota failures and admission/rate-limit events. The
   optional `ALERT_ABUSE_EVENTS` threshold counts events per delivered tail batch,
   not a durable global time window. Default 1 avoids missing low-volume abuse;
   deduplicate at the alert destination. Alert delivery failure is a Worker error.
6. Configure Cloudflare account usage/budget notifications and edge WAF/rate
   limits appropriate to your plan. Storage thresholds do not bound request costs
   or impose a provider spending cap. Tail Workers also incur usage.
7. Verify an unadmitted generated room returns 403 without an R2 write, admit a
   synthetic room and exercise upload/list/download, then remove it. Temporarily
   set the storage threshold low in a staging deployment to verify actual alert
   delivery; trigger an admission denial and verify the Tail Worker alert. Confirm
   lifecycle and budget notifications in the account dashboard before production.

`npm run deploy:check` validates/bundles without deploying. It cannot establish
that your real account has a lifecycle policy, alert secrets, delivery endpoint,
budget alerts or an installed provider WAF rule. Deployment is not complete until
those checks pass. Node emits the same `relay-security-alert` JSON events; route
its stdout to your existing log alerting system for reason `admission`,
`rate-limit` or `quota`. Node's expiry sweep runs independently of reads.

Sources: [R2 lifecycle](https://developers.cloudflare.com/r2/buckets/object-lifecycles/),
[Cloudflare notification availability](https://developers.cloudflare.com/notifications/notification-available/).
