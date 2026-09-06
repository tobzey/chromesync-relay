# ChromeSync private Node relay

```sh
ALLOWED_ROOMS=OPERATOR_APPROVED_ROOM_ID DATA_DIR=/private/relay-data HOST=127.0.0.1 PORT=8787 node server/server.js
```

Use Node 22+ behind your HTTPS reverse proxy. Configure `TRUST_PROXY=true` only
when an actually trusted reverse proxy owns the final forwarded hop. Never expose
an unencrypted non-loopback endpoint. `TLS_CERT`/`TLS_KEY` optionally provide TLS.

All `/rooms/ID/blobs` operations require a capability that hashes to ID **and**
operator admission in `ALLOWED_ROOMS`. Empty configuration denies every room.
No endpoint creates/adopts arbitrary rooms. Approval and `chromesync devices`
print public room IDs; never put endpoint bearer tokens in server config.

Defaults: 1 MiB body, 100 blobs / 10 MiB per room, latest 3 per source, seven-day
TTL, minute expiry sweep, bounded per-IP and per-room token buckets. The sweep
runs even for unvisited rooms. Remove a revoked room from admission and restart
the Node service. Stop future delivery on the source with `chromesync revoke`.

Metadata-only JSON `relay-security-alert` events report admission denials,
rate-limit and quota failures. Connect stdout to your operator's alert destination
and test delivery with synthetic denials. No cookie bodies, headers or tokens
are logged. See [operations](../docs/relay-operations.md) and [SECURITY](../SECURITY.md).
