# Security and privacy

ChromeSync copies authentication cookies. A receiving device can act as your
logged-in accounts. Pair only trusted devices and limit the source's domain
allowlist. Revoke website sessions if a receiver is compromised: removing a
ChromeSync device cannot invalidate cookies it already received.

## Supported boundary and migration

Protocol v2 is the supported pairing protocol. Shared-secret v1 CLI pairings,
secret-bearing extension invites, native relay and file-drop transports are
rejected. The terminal-managed extension source uses the same v2 publisher as
managed Chrome. Legacy crypto helpers remain only for historical format tests;
no supported native or CLI transport can invoke them.

Run `chromesync migrate` on existing installations. It moves v1 secrets into the
OS credential store, rewrites config without plaintext secrets, and disables
those profiles while preserving their browser directories and counters. Create
new v2 source profiles and pair every receiver. Remove old relay room admissions
and invite copies. Older installed software and previously copied data do not
become secure merely because this checkout changed.

## Credential storage

Private signing keys, device private keys, channel chains, bearer tokens,
pending redemption records and local recovery keys live in macOS Keychain or
Linux Secret Service. `config.json` contains profile metadata, public source
keys and opaque credential references. There is no file or environment fallback
if the credential store is locked or unavailable. The macOS helper uses the
Security framework; Linux uses the OS-packaged `python3-secretstorage` API. Writes use stdin, never secret
command-line arguments. Readback verifies writes before related state advances.

Config, transfer and state files are mode 0600 in mode 0700 directories. Extension
storage purges historical relay and file-drop secrets from local/session config
and disables those transports. Browser Use credentials have their separate,
explicit storage option. Chrome itself stores imported cookies in its profile.

## Invitations and device approval

A source invitation contains public identity, scope and a CSPRNG nonce, expires
in 15 minutes, and grants no cookie access by itself. Receiver setup creates its
own X25519 device key and a separate one-time bootstrap key. Compare the full
SHA-256 request fingerprint displayed on the receiver over a trusted channel,
then explicitly approve that fingerprint on the source. Never approve a
fingerprint supplied only by the same untrusted file-transfer channel.

The source compares the complete request invitation with its issuance record,
checks the original expiry and consumes the nonce under the profile's exclusive
OS lock before issuing activation. Copies, concurrent attempts and modified
scope/expiry cannot authorize another receiver. Retrying the identical approved
request within its original TTL re-exports the same encrypted activation from a
durable outbox, without generating another channel. Activation is signed by the
source and encrypted to the one-time bootstrap key. Receiver import verifies
its request binding and expiry, saves its channel, and deletes the bootstrap
private key. Successful imports delete the invite, request and activation files
at their respective receiving endpoints. A copied activation cannot be consumed
again after bootstrap-key erasure. Failed imports retain their input for diagnosis;
expired files remain inert. There is no online untrusted-relay redemption authority.

## Snapshot protocol and forward secrecy

Each device has a separate random relay capability and room. Only the source
holds the Ed25519 signing private key; receivers hold its public key. Each
snapshot has a fresh ephemeral X25519 source key, an AES-256-GCM nonce and a
per-device evolving chain. HKDF-SHA-256 combines the X25519 shared value with the
current chain, with separate context strings for snapshots, activation and
chain advancement. Signatures and GCM bind version, device, source, counter,
time and ephemeral key. Receivers cannot impersonate the source or decrypt
another device's channel. Room holders can still delete/withhold ciphertext in
their own room; source authenticity is enforced at the receiving endpoint.

Both ends overwrite the old chain after advancement. The source persists the
next chain before uploading, retaining only signed ciphertext for retry. The
receiver authenticates and checkpoints locally before erasing its old chain,
then applies cookies; CDP failures retry from the local encrypted checkpoint.
Receivers can skip missed chain steps (bounded at 100,000); source signatures
are checked before ratchet work. Replays and counter relabeling are rejected.

Compromise of current endpoint keys does not recover earlier network snapshots
once their chain keys and the bootstrap private key are erased. An old source
chain alone also lacks erased ephemeral X25519 private keys. This is forward
secrecy against later endpoint-state compromise, **not post-compromise recovery**:
a compromised live receiver can continue deriving its future channel until
revoked. Keychain backups, VM snapshots, copied initial states and restored old
counters defeat erasure guarantees. Do not clone or roll back live pairing state.
JavaScript cannot guarantee physical erasure of all heap/OS/SSD copies.

The latest local recovery snapshot is deliberately an exception: a separate
random key in the OS vault allows browser restart/offline restoration for up to
seven days. This is one overwritten checkpoint, not network history. Anyone
with the local recovery key and a checkpoint copy can decrypt that checkpoint.
Previously imported cookie identities (names/domains/paths), counters and keyed
digests remain in state for deletion tracking; cookie values are not plaintext.

## KDF and entropy decision

There are **no manually entered pairing passwords** in v2. Nonces, capabilities,
chains and recovery keys are generated by `crypto.randomBytes(32)` (256 bits),
and Ed25519/X25519 keypairs use Node's cryptographic key generation. No password
or `--secret` parameter can replace these generators. Canonical encoding/length
checks validate key representation; they cannot prove entropy of arbitrary input.

The old format used scrypt N=32768, r=8, p=1, maxmem=64 MiB. Raising its work factor
or switching to Argon2id would still leave shared-secret receiver forgery and
historical decryption, so the supported protocol removes that password path.
HKDF is appropriate for generated high-entropy key material and DH outputs;
Argon2id is a password KDF and provides no useful guessing defense for a uniformly
random 256-bit key. A future password-based protocol would require an explicit
PAKE/password-KDF design and new protocol version, not accepting short strings
in this protocol. See [Node crypto](https://nodejs.org/api/crypto.html) and
[RFC 5869](https://www.rfc-editor.org/rfc/rfc5869).

## Private relay operation

Both relay backends require exact operator-provisioned `ALLOWED_ROOMS` IDs for
all room operations, in addition to the room capability. Default is deny all;
there is no public self-admission endpoint. Limit is 256 admitted rooms, 32
receivers per source, bounded bodies, room retention and per-room quotas.
R2 quota checks and isolate-local rate limits remain best effort under concurrent
traffic; these are not an account spending cap. Apply provider WAF/rate limits
and billing alerts for your account and keep the deployment private.

[Relay operations](docs/relay-operations.md) covers enforced admission, supplied
seven-day R2 lifecycle / one-day multipart cleanup, alert worker, storage audits,
readback and synthetic alert checks. Unvisited R2 objects require the provider
lifecycle rule. Denials, rate-limit events and quota failures emit structured
metadata alerts; the Tail Worker forwards only aggregate counts. Never attach
request headers, tokens, cookies or blob bodies to alerts.

The relay sees IP/timing, room IDs, source identifiers, sizes and bearer tokens.
It can withhold/replay ciphertext; authenticated client counters/signatures
protect acceptance, not availability. HTTPS is required except explicit loopback
HTTP development. No telemetry is collected by the app.

## Distribution

The installer requires a full commit SHA and independently provisioned SSH
allowed-signers file. It verifies the signed commit before extracting or running
application code. There is no mutable `main` default, unsigned fallback or
unsigned Node bootstrap. The installer script itself must come from a verified
checkout; piping an unverified script into a shell defeats later verification.
Node comes from a trusted OS package manager or independently verified release.

App tar and extension ZIP artifacts use deterministic ordering, modes, ownership
and timestamps. Stored ZIP and uncompressed gzip blocks avoid compression-library
variance. CI compares two builds; release CI requires a trusted signed source,
runs tests and publishes Sigstore build attestations. Verify attestations for the
expected repository, workflow and source SHA, and independently rebuild the
artifacts from reviewed signed source. Reproducibility and provenance do not
make malicious signed source safe. [Release procedure](docs/releasing.md).

The unpacked extension's manifest key fixes its ID, not a code signature. Use the
verified extension artifact, or the extension files from verified installed
source. A local malicious extension copying that public ID remains a local
compromise. No automatic background updater runs.

## Remaining trust and reporting

CDP is loopback-only and grants full control of the selected managed browser.
Local malware, privileged users, compromised browsers and live authorized agents
are outside the protection boundary. Website token rotation, device binding and
non-cookie state can prevent session reuse. This protocol has regression tests
and implementation review, but no independent cryptographic audit.

Report vulnerabilities through GitHub **Security → Report a vulnerability**.
If unavailable, request a private contact channel without exploit details.
Never include real tokens, cookies, invitations or browser profiles in reports.
