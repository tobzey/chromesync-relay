// Worker auth: derivation parity with companion/relay-auth.js, bearer
// extraction, verifyRoomAuth status codes. Synthetic pairing strings only.

import { test } from "node:test";
import assert from "node:assert/strict";
import { deriveRelayAuth, roomIdForToken as companionRoomId, clearRelayAuthCache } from "../companion/relay-auth.js";
import {
  roomIdForToken,
  bearerToken,
  verifyRoomAuth,
  ROOM_ID_RE,
  TOKEN_RE,
} from "../worker/auth.js";

const SECRET = "test-pairing-secret-not-real";

test("parity: worker roomIdForToken matches companion for several tokens", async () => {
  clearRelayAuthCache();
  const derived = deriveRelayAuth(SECRET);
  const tokens = [derived.token, "token-alpha-test-01", "AAAAAAAAAAAAAAAA", `${"b".repeat(43)}`, "Zz-_0123456789ab"];
  for (const t of tokens) {
    assert.equal(await roomIdForToken(t), companionRoomId(t));
  }
  assert.equal(await roomIdForToken(derived.token), derived.roomId);
  assert.ok(ROOM_ID_RE.test(derived.roomId));
  assert.equal(derived.roomId.length, 22);
});

test("bearerToken extracts a well-formed Bearer value and rejects the rest", () => {
  assert.equal(bearerToken(""), "");
  assert.equal(bearerToken(null), "");
  assert.equal(bearerToken(undefined), "");
  assert.equal(bearerToken("Basic abc"), "");
  assert.equal(bearerToken("Bearer"), "");
  assert.equal(bearerToken("Bearer "), "");
  assert.equal(bearerToken("Bearer tok extra"), "");
  assert.equal(bearerToken("Bearer abcdefghijklmnop"), "abcdefghijklmnop");
  assert.equal(bearerToken("bearer abcdefghijklmnop"), "abcdefghijklmnop");
  assert.equal(bearerToken("BEARER abcdefghijklmnop"), "abcdefghijklmnop");
});

test("verifyRoomAuth: 400 / 401 / 403 / ok", async () => {
  clearRelayAuthCache();
  const { token, roomId } = deriveRelayAuth(SECRET);

  assert.deepEqual(await verifyRoomAuth("short", token), { ok: false, status: 400 });
  assert.deepEqual(await verifyRoomAuth("not valid room id!!!!", token), { ok: false, status: 400 });
  assert.deepEqual(await verifyRoomAuth(null, token), { ok: false, status: 400 });

  assert.deepEqual(await verifyRoomAuth(roomId, ""), { ok: false, status: 401 });
  assert.deepEqual(await verifyRoomAuth(roomId, "nope"), { ok: false, status: 401 });
  assert.deepEqual(await verifyRoomAuth(roomId, "spaces not ok!!!!"), { ok: false, status: 401 });
  assert.ok(TOKEN_RE.test(token));

  assert.deepEqual(await verifyRoomAuth(roomId, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"), {
    ok: false,
    status: 403,
  });
  assert.deepEqual(await verifyRoomAuth("bbbbbbbbbbbbbbbbbbbbbb", token), { ok: false, status: 403 });

  const ok = await verifyRoomAuth(roomId, token);
  assert.deepEqual(ok, { ok: true });
});
