# 1Password authentication with the daily driver offline

Research and isolated experiment, 2026-09-06. No real vault, item, account token, browser credential, or authentication session was accessed. Public documentation, official SDK source, and its distributed WASM were inspected. The existing browser-isolation/security workstream is a dependency, not duplicated here.

## Decision

**Passwords and TOTP can work while the user's daily driver is powered off.** Run the trusted credential executor and protected browser on an always-on host. Give the executor an independently provisioned, narrowly scoped 1Password Service Account. The daily driver becomes an enrollment and approval device; an existing valid “always allow” rule is evaluated by the executor without contacting it. Service accounts are explicitly intended for automated access without a present user. [SDK authentication concepts](https://www.1password.dev/sdks/concepts)

**Existing 1Password passkeys are not exposed by the public SDK, but this is not evidence of a cryptographic impossibility.** Static inspection shows its internal item model knows about passkey private-key data. Reusing those credentials in an always-on trusted signer is a plausible research route requiring a controlled provisioning test and WebAuthn compatibility validation. It is not yet a supported or proven API path.

An “offline daily driver” is distinct from “offline provider” or “offline executor”:

| Situation | Expected result |
| --- | --- |
| Daily driver off; executor and 1Password reachable; valid enrolled password/TOTP rule | Can authenticate unattended. |
| Daily driver off; request requires a new approval | Remains pending. A separately enrolled phone could approve it later. |
| Daily driver off; only desktop SDK authentication configured | Unavailable; there is no independent vault-access authority on the executor. |
| 1Password unreachable; Service Account adapter has no deliberate credential cache | Provider unavailable; do not claim an offline-cloud guarantee. |
| Connect cache available while provider connectivity fails | Potentially serves cached data; cold-start, revocation and staleness behavior must be tested. |
| Executor/protected browser off | No authentication occurs, regardless of stored policy. |

## Stable public API: Service Account + SDK

The service account receives vault-level permissions. The documented choices are `read_items`, `write_items` (requires read), and `share_items` (requires read). For ChromeSync choose read only, without vault-creation permission. Vault access and permissions are immutable; widening access requires a new account/token. Built-in Personal, Private, Employee and default Shared vaults cannot be selected. A custom enrollment vault is therefore intentional setup, not a workaround that grants access to the whole account. [Service account setup and restrictions](https://www.1password.dev/service-accounts/get-started), [CLI permission reference](https://www.1password.dev/cli/reference/management-commands/service-account)

The official JS contract is:

```js
const client = await sdk.createClient({
  auth: tokenFromTrustedSecretLoader,
  integrationName: 'ChromeSync trusted executor',
  integrationVersion: '0.0.1',
});
const password = await client.secrets.resolve('op://VAULT_ID/ITEM_ID/password');
const code = await client.secrets.resolve('op://VAULT_ID/ITEM_ID/SECTION_ID/FIELD_ID?attribute=otp');
```

These values belong only in the trusted executor and browser. The agent calls a separate operation such as `authenticate(sessionHandle, enrolledAccountAlias)` and gets a fixed outcome. The public SDK retrieves values; it is not an API that remotely fills a browser without any trusted application seeing them. [SDK configuration source](https://github.com/1Password/onepassword-sdk-js/blob/ec1e4625abca0a883ae31ceb3e17b71771b244bb/client/src/configuration.ts), [secret resolver source](https://github.com/1Password/onepassword-sdk-js/blob/ec1e4625abca0a883ae31ceb3e17b71771b244bb/client/src/secrets.ts), [OTP reference syntax](https://www.1password.dev/sdks/load-secrets)

`client.items.get(vaultId, itemId)` is another documented option. Its fields include `value`, and a TOTP field also has `details.type === 'Otp'` with `details.content.code` or `errorMessage`. Fetching a complete login is broader than required and can expose the stored TOTP seed to the trusted executor. Prefer field-specific secret resolution, with the OTP query selecting the generated code. This is API data minimization; it does not change what the token is authorized to retrieve. [Item/OTP documentation](https://www.1password.dev/sdks/manage-items), [item and field types](https://github.com/1Password/onepassword-sdk-js/blob/ec1e4625abca0a883ae31ceb3e17b71771b244bb/client/src/types.ts)

### What the provider enforces versus what ChromeSync enforces

1Password enforces the service account's permitted vaults and read/write/share capabilities. The public service-account permission does not encode a website origin, one particular item within an accessible vault, a browser tab, an agent identity, login versus sensitive action, or password versus TOTP. These are ChromeSync policy constraints.

If the requirement is that even the always-on executor must be unable to retrieve a certain second factor, do not give its token access to a vault containing that factor. Separate the automation credential into a restricted vault or separate enrollment record. A single readable item containing password and TOTP gives the executor access to both even if ChromeSync's policy only permits password use. For strict per-service provider isolation, use separate vaults/tokens for the chosen service boundaries. An item lookup or tag filter is not an authorization boundary. This follows from the documented vault-scoped permission model, rather than a claim of undocumented field-level access control.

### Enrollment and operation

Recommended implementation decisions:

1. Create a custom ChromeSync enrollment vault, then provision a read-only service-account token through the trusted installer or OS/cloud secret manager. Never send this token through an agent tool or expose it to the relay delivery process.
2. Have the user select/move or deliberately copy the desired login into that vault. Keeping a canonical item there avoids silent drift between duplicate password records; if copying is used, include explicit rotation/update reconciliation. The service account cannot perform initial retrieval from inaccessible Personal items.
3. Save a verified enrollment mapping: opaque account alias, provider vault/item/field IDs, exact allowed origins and IdP transitions. Browser-derived origins are checked at use time; the agent does not choose an arbitrary `op://` reference.
4. Save policy separately: permitted requester, account, factors, purpose, expiry and revocation version. Evaluate it on the executor. An “always” rule skips fresh human approval only within its scope.
5. Obtain a private browser lease, fetch the enrolled fields, perform the original session's authentication, and return a sanitized result. The form executor needs rollover-safe TOTP timing, clock health, bounded retries and crash recovery. A changed password should be fetched from the authoritative item on a later attempt rather than using an indefinite local copy.

Operational limits matter: Personal/Families accounts have 1,000 requests per day across service accounts, while Teams has 5,000 and Business 50,000. Hourly read limits are 1,000 per token except Business at 10,000. Avoid vault enumeration on every login and measure actual SDK request use. [Current rate limits](https://www.1password.dev/service-accounts/rate-limits)

## New API option: Credential Broker and custom OIDC

The June announcement described a private beta focused on GitHub Actions. Current official documentation is more advanced: the administration and GitHub guides are public preview, while the custom-workflow guide is labeled public beta. Do not infer current availability from the older announcement alone. [June announcement](https://1password.com/press/2026/june/credential-broker), [current administrator guide](https://www.1password.dev/brokered-access.md), [custom workflow guide](https://www.1password.dev/brokered-access/custom-workflow.md)

Verified current setup:

- Requires **1Password Business**. An administrator registers an OIDC issuer, verifies/discovers its JWKS endpoint, sets required claims and notes the expected audience.
- An integration key is still required to decrypt the secrets. This removes the need for a service-account token in the workload, but does not eliminate every provisioned decryption secret.
- A user connects a **1Password Environment** to the workload, optionally adding more access conditions.
- The JS SDK accepts `oidcFetcher(audience)` and `workloadDetails: { workloadUuid, customerManagedSecret }`. It retrieves environment variables with `client.environments.getVariables(environmentId)`.
- The custom-workflow guide currently calls for the latest desktop beta during setup and says only the JavaScript SDK supports this path. Its example mentions a base64-padding issue in `0.5.0-beta.1`; pin and test an appropriate version.

Evidence: [administrator guide](https://www.1password.dev/brokered-access.md), [custom workflow guide](https://www.1password.dev/brokered-access/custom-workflow.md), [SDK configuration](https://github.com/1Password/onepassword-sdk-js/blob/ec1e4625abca0a883ae31ceb3e17b71771b244bb/client/src/configuration.ts), [SDK workload details and initialization](https://github.com/1Password/onepassword-sdk-js/blob/ec1e4625abca0a883ae31ceb3e17b71771b244bb/client/src/core.ts)

**Inference for ChromeSync:** an always-on trusted executor with an eligible workload identity can obtain secrets without the daily driver being online. This is a promising provider adapter for Business deployments. It does not provide browser-login recognition, phone approvals, passkey assertions, or direct access to existing Login item fields: the documented payload is Environment variables. A TOTP seed could be deliberately enrolled as a variable and computed inside the executor, but that is a new enrollment/implementation path, not documented broker-native TOTP or passkey support. Keep service accounts as the simpler baseline while validating this beta separately.

The research web reader could not open these new broker pages, but direct HTTPS retrieval of their `.md` endpoints succeeded. Their content and the current official SDK independently agree on the OIDC configuration shape.

## Connect: independent from the daily driver, with a cache

Connect is an alternative private REST API hosted in the user's infrastructure. Its deployment uses sync and API containers plus a shared encrypted data volume. The server has a provisioned `1password-credentials.json` and scoped access tokens. This also operates independently from the user's workstation. [Connect concepts](https://www.1password.dev/connect/concepts)

The documented REST path `GET /v1/vaults/{vaultUUID}/items/{itemUUID}` returns item details under bearer-token authorization. No WebAuthn/passkey assertion operation appears in the published API reference. Use its separate Connect SDK or REST client; the main SDK README marks Connect authentication unsupported. [Connect API reference](https://www.1password.dev/connect/api-reference), [SDK support matrix](https://github.com/1Password/onepassword-sdk-js/blob/ec1e4625abca0a883ae31ceb3e17b71771b244bb/README.md)

Connect's documented cache permits unlimited re-requests after an initial fetch. That is useful for availability and higher request volume, at the cost of a credential-bearing server and cache lifecycle. Do not treat cache presence as proof of guaranteed cold-start availability or immediate cloud revocation while disconnected; test these failure modes and enforce ChromeSync revocation locally. Put Connect behind the trusted executor, not on the agent-facing relay API. [Connect overview](https://www.1password.dev/connect), [Connect access control](https://www.1password.dev/connect/security)

## Passkey findings from public SDK source and binary

Inspected official SDK Git tree: `ec1e4625abca0a883ae31ceb3e17b71771b244bb`.

1. The raw README has an **unchecked** Passkeys entry. HTML extraction renders checked and unchecked entries alike, so the raw source is the stronger evidence. [Raw README](https://raw.githubusercontent.com/1Password/onepassword-sdk-js/ec1e4625abca0a883ae31ceb3e17b71771b244bb/README.md)
2. Public `Item` has fourteen properties, including fields, files and websites, but no raw item, passkey, item-level details or extensible additional-properties member. `ItemFieldType` contains `Unsupported`; its field-details union has OTP, SSH and address data, no passkey. [Types](https://github.com/1Password/onepassword-sdk-js/blob/ec1e4625abca0a883ae31ceb3e17b71771b244bb/client/src/types.ts)
3. The JavaScript `ItemsGet` wrapper JSON-parses the core response and casts it as an Item. Its reviver handles dates/byte arrays; it does not strip unknown object fields. Any removal/translation of passkey data happens before that wrapper, not because TypeScript would discard runtime fields. [Item wrapper](https://github.com/1Password/onepassword-sdk-js/blob/ec1e4625abca0a883ae31ceb3e17b71771b244bb/client/src/items.ts)
4. Static string/symbol inspection of the distributed WASM found an internal `op_model_item::Passkey`, `load_passkey`, `save_passkey`, a passkey JSON schema including `privateKey`, `userHandle`, `alg` and `credWithUv`, plus `op_sdk_core::model::item::Item::from_internal`. A serialized “Item with 14 elements” agrees with the public type. The invocation-name list exposes ordinary item/secret operations; this inspection found no public raw-item or passkey-signing invocation. [Distributed core binary](https://github.com/1Password/onepassword-sdk-js/blob/ec1e4625abca0a883ae31ceb3e17b71771b244bb/wasm/nodejs/core_bg.wasm)

Binary reproducibility: 13,954,367 bytes; SHA-256 `97aa9140c5c923b39b41c059d5ab98e214b5fc78a80203d0026708cfbce8d6ab`. This is static evidence about code/schema capability, not evidence that a real passkey was obtained, that a service account receives it, or that the core can sign WebAuthn assertions.

**Working hypothesis:** passkeys share the encrypted item model already handled by the vault client, and the public SDK exposes a limited projection of it. A trusted integration may be able to retrieve/decrypt an enrolled passkey through a private protocol or a controlled provider export/provisioning path. Required proof: use a synthetic passkey in a dedicated test vault, authenticate with a read-only service account, establish whether complete encrypted passkey data and the necessary keys are available, and complete a real RP assertion using that provisioned credential. Maintain origin/challenge/verification semantics and versioned compatibility fixtures. The user's authorized extension-inspection workstream supplies complementary evidence; no existing personal passkey should be inspected merely to test the hypothesis.

The public SDK's lack of support should be described as an **integration/provisioning gap**. It is not correct to say all synced 1Password passkeys are inherently device-bound or can never be handled by an independently authorized trusted executor. It is equally incorrect to claim headless use of an existing passkey is already proven from schema strings alone.

## Executable evidence created

The isolated [offline credentials experiment](../../experiments/auth-broker/offline-credentials/README.md) contains an actual lazy SDK adapter and a synthetic provider contract/policy test. It returns only fixed outcomes; credential values enter a private injected browser sink. **15 tests pass** (11 top-level) with no dependency installation or real account access.

The tests verify offline “always” execution, pending ask-each-time and additional-factor requests, requester/account/expiry/purpose scoping, browser-derived origin validation, request mutation resistance, exact field references, passkey unsupported handling, and sanitized SDK/browser failures. They do not establish real provider connectivity, vault permissions, TOTP generation correctness, browser isolation, or real-site success. Those are explicit integration gates for the main implementation.
