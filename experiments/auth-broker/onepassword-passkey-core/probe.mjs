#!/usr/bin/env node
// Research probe only. Reads shipped code, never a browser profile or real vault.
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';

const extensionDir = process.argv[2];
if (!extensionDir) {
  console.error('Usage: node probe.mjs /absolute/path/to/1password/8.12.34.34_1');
  process.exit(2);
}

const pinned = {
  'manifest.json': '025d7d2273297891df48f9eaa8b28671b9ec00e01fbc72b9482de4a8820e91b4',
  'background/background.js': '4abb5b41a00df6e6a324bef5cddb8705548ca672a6a745a598a67e6ccc488117',
  'assets/wasm/op_wasm_b5x_bg-ATVVAPRM.wasm': '0c8b282aca90c72b9d5f966b96b84e3d302ea388dfa83fe13aee156b1efa3cad',
};

function readPinned(relativePath) {
  const bytes = fs.readFileSync(path.join(extensionDir, relativePath));
  const digest = crypto.createHash('sha256').update(bytes).digest('hex');
  assert.equal(digest, pinned[relativePath], `Unreviewed file version: ${relativePath}`);
  return bytes;
}

async function main() {
  assert.equal(JSON.parse(readPinned('manifest.json')).version, '8.12.34.34');
  const bundle = readPinned('background/background.js').toString('utf8');
  // Only the self-contained wasm-bindgen glue, not the extension startup/account code.
  const glueStart = bundle.indexOf('async function YTA(');
  const glueEnd = bundle.indexOf('var oCA,nCA=');
  assert.equal(glueStart, 1418500);
  assert.equal(glueEnd, 1453319);
  let blockedNetworkRequests = 0;
  let blockedRelatedOriginRequests = 0;
  const denyNetwork = () => {
    blockedNetworkRequests++;
    throw new Error('Network disabled in synthetic probe');
  };
  const denyRelatedOriginFetch = () => {
    blockedRelatedOriginRequests++;
    throw new Error('Related-origin lookup disabled in synthetic probe');
  };
  // Empty mocks: no access to the installed extension, Chrome session, or 1Password.
  const context = vm.createContext({
    console: { log() {}, info() {}, warn() {}, error() {}, debug() {} },
    chrome: { runtime: {} },
    browser: { storage: { session: { get: async () => ({}), set: async () => {} } } },
    performance, queueMicrotask, TextEncoder, TextDecoder, Uint8Array,
    ArrayBuffer, DataView, WebAssembly, FinalizationRegistry, WeakRef,
    URL, Request, Response, Headers, setTimeout, clearTimeout,
    crypto: crypto.webcrypto,
    fetch: denyNetwork,
    j: fn => {
      let initialized = false;
      return () => { if (!initialized) { initialized = true; fn(); } };
    },
    Cs: (object, definitions) => {
      for (const [key, get] of Object.entries(definitions)) {
        Object.defineProperty(object, key, { get });
      }
    },
  }, { name: 'synthetic-passkey-core-research' });
  vm.runInContext(
    bundle.slice(glueStart, glueEnd) + ';iCA();globalThis.probeAPI=An;',
    context,
    { timeout: 5000 },
  );
  context.wasmBytes = readPinned('assets/wasm/op_wasm_b5x_bg-ATVVAPRM.wasm');
  vm.runInContext('probeAPI.initSync({module:wasmBytes});', context, { timeout: 5000 });

  const origin = 'https://agent-auth.example';
  const rpId = 'agent-auth.example';
  const registrationInput = {
    url: origin,
    request: { publicKey: {
      rp: { id: rpId, name: 'Synthetic RP' },
      user: { id: [1, 2, 3, 4], name: 'synthetic', displayName: 'Synthetic' },
      challenge: Array.from(crypto.randomBytes(32)),
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
      authenticatorSelection: { userVerification: 'required' },
    } },
    isPrfEnabled: false,
    // Deliberately no claim of actual user verification. This is a pure core probe.
    didUnlock: false,
  };
  const callCore = async (method, input) => {
    const output = await context.probeAPI[method](JSON.stringify(input), denyRelatedOriginFetch);
    return JSON.parse(output);
  };
  const registrationResult = await callCore('webAuthnRegister', registrationInput);
  assert.equal(registrationResult.error, undefined);
  const registration = registrationResult.result;
  const privateJwk = JSON.parse(Buffer.from(registration.private_key.key).toString('utf8'));
  assert.equal(privateJwk.kty, 'EC');
  assert.equal(privateJwk.crv, 'P-256');
  assert.equal(privateJwk.alg, 'ES256');

  const publicKey = crypto.createPublicKey({
    key: Buffer.from(registration.public_key.response.publicKey),
    format: 'der',
    type: 'spki',
  });
  const request = { publicKey: {
    challenge: Array.from(crypto.randomBytes(32)),
    rpId,
    allowCredentials: [{ id: registration.public_key.rawId, type: 'public-key' }],
    userVerification: 'required',
  } };
  const loginInput = {
    url: origin, passkey: registration.private_key, request,
    isPrfEnabled: false, didUnlock: false,
  };
  const loginResult = await callCore('webAuthnLogin', loginInput);
  assert.equal(loginResult.error, undefined);
  const assertion = loginResult.result.credential;
  const authenticatorData = Buffer.from(assertion.response.authenticatorData);
  const clientDataBytes = Buffer.from(assertion.response.clientDataJSON);
  const clientData = JSON.parse(clientDataBytes);
  const signed = Buffer.concat([
    authenticatorData,
    crypto.createHash('sha256').update(clientDataBytes).digest(),
  ]);
  assert(crypto.verify('sha256', signed, publicKey, Buffer.from(assertion.response.signature)));
  assert.equal(clientData.origin, origin);
  assert.equal(clientData.type, 'webauthn.get');
  assert.equal(clientData.challenge, Buffer.from(request.publicKey.challenge).toString('base64url'));
  assert(authenticatorData.subarray(0, 32).equals(crypto.createHash('sha256').update(rpId).digest()));
  assert.deepEqual(assertion.rawId, registration.public_key.rawId);
  const changedMessage = Buffer.from(signed);
  changedMessage[changedMessage.length - 1] ^= 1;
  assert(!crypto.verify('sha256', changedMessage, publicKey, Buffer.from(assertion.response.signature)));
  assert.equal(blockedNetworkRequests, 0);
  assert.equal(blockedRelatedOriginRequests, 0);

  const rejected = [];
  for (const [label, url, requestedRpId, allowId] of [
    ['unrelated-origin', 'https://attacker.invalid', rpId, registration.public_key.rawId],
    ['unrelated-rp-id', origin, 'attacker.invalid', registration.public_key.rawId],
    ['wrong-credential-id', origin, rpId, [9, 9, 9]],
  ]) {
    const result = await callCore('webAuthnLogin', {
      ...loginInput, url,
      request: { publicKey: {
        ...request.publicKey, rpId: requestedRpId,
        allowCredentials: [{ id: allowId, type: 'public-key' }],
      } },
    });
    assert(result.error, `${label} unexpectedly succeeded`);
    assert.equal(result.result?.credential, undefined);
    rejected.push({ label, error: result.error });
  }

  // No key values, credentials, assertions, challenges, or tokens are printed or saved.
  console.log(JSON.stringify({
    extensionVersion: '8.12.34.34',
    generatedCredential: true,
    privateKeyEncoding: 'UTF-8 JSON JWK, EC/P-256/ES256 (synthetic only)',
    independentSignatureVerification: true,
    verifiedOriginRpIdChallengeCredentialId: true,
    modifiedMessageRejected: true,
    validFlowNetworkCalls: 0,
    authenticatorFlags: authenticatorData[32],
    didUnlockInput: false,
    consentConclusion: 'Core assumes caller consent; returned UV flag is not evidence of real verification.',
    negativeCases: rejected,
    blockedNetworkRequests,
    blockedRelatedOriginRequests,
  }, null, 2));
}

main().catch(error => {
  // Avoid dumping source bundles or incidental objects in stack traces.
  console.error(`Synthetic probe failed: ${error.message}`);
  process.exitCode = 1;
});
