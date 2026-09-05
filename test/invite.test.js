// Invite encode/decode. Dummy URLs only (relay.example.com / localhost).

import { test } from "node:test";
import assert from "node:assert/strict";
import { buildInvite, parseInvite, generatePairingCode } from "../src/invite.js";

test("buildInvite → parseInvite round-trip", () => {
  const secret = generatePairingCode();
  const invite = buildInvite({ relayUrl: "https://relay.example.com", secret });
  assert.match(invite, /^csync1\./);
  const parsed = parseInvite(invite);
  assert.equal(parsed.relayUrl, "https://relay.example.com");
  assert.equal(parsed.secret, secret);
});

test("localhost http invite is accepted", () => {
  const invite = buildInvite({ relayUrl: "http://127.0.0.1:8787", secret: "test-pairing-secret-not-real" });
  const parsed = parseInvite(invite);
  assert.equal(parsed.relayUrl, "http://127.0.0.1:8787");
});

test("malformed prefix is rejected", () => {
  assert.throws(() => parseInvite("nope.abc"), /invalid invite/);
  assert.throws(() => parseInvite("csync2.abc"), /invalid invite/);
});

test("bad base64 is rejected", () => {
  assert.throws(() => parseInvite("csync1.!!!not-base64!!!"), /invalid invite/);
});

test("bad scheme is rejected", () => {
  const payload = Buffer.from(JSON.stringify({ relayUrl: "http://example.com", secret: "abc" }), "utf8");
  const b64 = payload.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  assert.throws(() => parseInvite("csync1." + b64), /invalid invite/);
  assert.throws(() => buildInvite({ relayUrl: "ftp://relay.example.com", secret: "abc" }), /invalid invite/);
});

test("empty secret is rejected", () => {
  assert.throws(() => buildInvite({ relayUrl: "https://relay.example.com", secret: "" }), /invalid invite/);
  const payload = Buffer.from(JSON.stringify({ relayUrl: "https://relay.example.com", secret: "" }), "utf8");
  const b64 = payload.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  assert.throws(() => parseInvite("csync1." + b64), /invalid invite/);
});
