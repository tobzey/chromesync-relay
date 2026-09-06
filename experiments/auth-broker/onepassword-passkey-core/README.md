# 1Password passkey core experiment

This research probe generates a new synthetic passkey and exercises the locally installed 1Password extension's shipped WASM core. It independently verifies the assertion signature, origin, RP ID hash, challenge, and credential ID, and checks several rejection cases.

Run from the repository root with Node.js 22:

```sh
node experiments/auth-broker/onepassword-passkey-core/probe.mjs \
  '/absolute/path/to/installed/1password-extension/8.12.34.34_1'
```

The directory argument must identify the user-supplied **1Password 8.12.34.34** extension code. The probe checks SHA-256 hashes for its manifest, background JavaScript, and WASM against the reviewed build. A different version or modified file is rejected and requires a fresh review. No proprietary bundle is distributed here; the probe reads the supplied code locally at runtime.

The experiment uses only a generated credential for `agent-auth.example`, empty mock storage, and denied network requests. It does not open Chrome, read browser storage or account data, access existing passkeys, modify the installed extension, or print/save key values or assertions. [result.json](result.json) records the completed successful run. This is research code, not a production authentication adapter.

**User-verification limitation:** the private core returned authenticator flags `0x1d`, including UV, despite the synthetic input specifying `didUnlock: false`. The core therefore assumes its caller enforces ceremony consent and verification. This result is not proof of user presence, biometric verification, a supported unattended flow, or permission to bypass an actual provider prompt. Production integration must enforce genuine consent and accurate authentication semantics separately.

See [the detailed findings](../../../docs/research/onepassword-extension-passkeys.md) for the call path, item format, scope boundaries, source hashes, and remaining live acceptance tests.
