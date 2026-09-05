# ChromeSync relay

`server/` is the self-host and local-test relay (`npm run relay:serve`, used
by the Node test suite). `worker/` is the managed Cloudflare Workers + R2
deployment of the same HTTP protocol.

A tiny self-hosted blob store for ChromeSync. It holds **opaque encrypted
files** only — it cannot read cookies and never sees the pairing code.

Point both devices at `https://relay.example.com` (replace with your host) and
enter the same pairing code on each.

## Run (local)

Run these commands from the `server/` directory, or use `npm run relay:serve`
from the repository root. Use Node.js 22+.

```sh
DATA_DIR=/var/lib/chromesync-relay PORT=8787 HOST=127.0.0.1 node server.js
```

The process speaks **plain HTTP**. Put a reverse proxy in front for TLS.

## Docker

```sh
docker build -t chromesync-relay .
docker run --rm -p 127.0.0.1:8787:8787 \
  -v /var/lib/chromesync-relay:/var/lib/chromesync-relay \
  -e DATA_DIR=/var/lib/chromesync-relay \
  chromesync-relay
```

## TLS (reverse proxy)

Terminate TLS at nginx / Caddy / your load balancer with a valid certificate.
The Node process binds loopback HTTP behind it. Self-signed certificates are
rejected by the ChromeSync companion (certificate checks stay on).

Example nginx snippet:

```nginx
server {
    listen 443 ssl;
    server_name relay.example.com;

    ssl_certificate     /etc/letsencrypt/live/relay.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/relay.example.com/privkey.pem;

    client_max_body_size 1m;

    location / {
        proxy_pass http://127.0.0.1:8787;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

If the proxy sets `X-Forwarded-For` and you want per-IP rate limits to use it,
set `TRUST_PROXY=1`. Only enable this when the proxy is the only way to reach
the process — the header is spoofable if clients can connect directly.

## Optional native TLS

If you do not have a reverse proxy, set `TLS_CERT` and `TLS_KEY` to PEM file
paths. The process then serves HTTPS itself.

## systemd (sketch)

```
[Service]
ExecStart=/usr/bin/node /opt/chromesync-relay/server.js
Environment=HOST=127.0.0.1
Environment=PORT=8787
Environment=DATA_DIR=/var/lib/chromesync-relay
Restart=on-failure
User=chromesync
```

## Environment

| Variable | Default | Meaning |
|---|---|---|
| `HOST` | `127.0.0.1` | Bind address |
| `PORT` | `8787` | Bind port |
| `DATA_DIR` | OS temp dir | Blob directory (`<DATA_DIR>/<roomId>/`) |
| `MAX_BODY_BYTES` | 1 MiB | Hard streamed body cap |
| `MAX_BLOBS_PER_ROOM` | 100 | Blob count quota per room |
| `MAX_ROOM_BYTES` | 10 MiB | Byte quota per room |
| `BLOB_TTL_MS` | 7 days | Age after which blobs are swept |
| `RETENTION_PER_HOST` | 3 | Newest blobs kept per source host |
| `RATE_IP_CAPACITY` / `RATE_IP_REFILL` | 60 / 1 | Token bucket per IP |
| `RATE_ROOM_CAPACITY` / `RATE_ROOM_REFILL` | 120 / 2 | Token bucket per room |
| `TRUST_PROXY` | off | Honor `X-Forwarded-For` |
| `TLS_CERT` / `TLS_KEY` | empty | Optional native TLS |

## Connect devices

Use `chromesync setup --name work --role source --relay https://relay.example.com`
on the source, then `chromesync pair` to create a private receiver invitation.
See the root README for the full CLI flow. The optional extension can use this
relay too, with its own relay URL and pairing code in Extension settings.

Rotation: if a pairing code leaks, generate a new one. That creates a new
room; old blobs are left until TTL.

## What the server sees

The relay is untrusted storage. It sees TLS metadata, the bearer token, the
room id, blob file names and sizes, and opaque ciphertext. It cannot decrypt
cookies. A weak pairing code can be guessed offline by whoever hosts or
breaches the server — use the generate button.
