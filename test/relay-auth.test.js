// Auth/room derivation: determinism, different-secret isolation, token ≠ roomId,
// client/server parity, encryption key path independent of the relay token.
// Synthetic pairing strings only — never real secrets.

import { test } from "node:test";
import assert from "node:assert/strict";
import { deriveRelayAuth, roomIdForToken as clientRoomId, clearRelayAuthCache } from "../companion/relay-auth.js";
import { roomIdForToken as serverRoomId, ROOM_ID_RE, verifyRoomAuth } from "../server/auth.js";
import { encryptCookies, decryptCookies, DropError } from "../companion/drop-crypto.js";
import { mapCookies } from "../src/cookies.js";
import { syntheticCookies } from "./fixtures.js";

const SECRET = "test-pairing-secret-not-real";
const OTHER = "different-pairing-secret-not-real";

test("same secret derives the same token and roomId (independent calls)", () => {
  clearRelayAuthCache();
  const a = deriveRelayAuth(SECRET);
  clearRelayAuthCache();
  const b = deriveRelayAuth(SECRET);
  assert.equal(a.token, b.token);
  assert.equal(a.roomId, b.roomId);
  assert.ok(ROOM_ID_RE.test(a.roomId));
  assert.equal(a.roomId.length, 22);
  assert.notEqual(a.token, a.roomId);
});

test("different secret derives a different room", () => {
  clearRelayAuthCache();
  const a = deriveRelayAuth(SECRET);
  const b = deriveRelayAuth(OTHER);
  assert.notEqual(a.token, b.token);
  assert.notEqual(a.roomId, b.roomId);
});

test("parity: companion/relay-auth.js and server/auth.js roomIdForToken match", () => {
  clearRelayAuthCache();
  const { token, roomId } = deriveRelayAuth(SECRET);
  assert.equal(clientRoomId(token), roomId);
  assert.equal(serverRoomId(token), roomId);
  assert.equal(clientRoomId(token), serverRoomId(token));
  const ok = verifyRoomAuth(roomId, token);
  assert.equal(ok.ok, true);
});

test("token is not a usable decryption key (encryption path is independent)", () => {
  const cookies = mapCookies(syntheticCookies).cookies;
  const { blob } = encryptCookies(cookies, SECRET, { counter: 1, createdAt: 1_700_000_000_000 });
  clearRelayAuthCache();
  const { token, relayMaster } = deriveRelayAuth(SECRET);
  assert.throws(() => decryptCookies(blob, token), (err) => err instanceof DropError);
  assert.throws(() => decryptCookies(blob, relayMaster.toString("hex")), (err) => err instanceof DropError);
  const out = decryptCookies(blob, SECRET);
  assert.deepEqual(out.cookies, cookies);
});
