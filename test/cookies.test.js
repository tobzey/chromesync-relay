import { test } from "node:test";
import assert from "node:assert/strict";
import { toCdpCookie, filterByAllowlist, mapCookies } from "../src/cookies.js";
import { syntheticCookies } from "./fixtures.js";

test("sameSite mapping", () => {
  assert.equal(toCdpCookie({ name: "a", value: "1", domain: "example.com", sameSite: "lax" }).sameSite, "Lax");
  assert.equal(toCdpCookie({ name: "a", value: "1", domain: "example.com", sameSite: "no_restriction" }).sameSite, "None");
  assert.equal(toCdpCookie({ name: "a", value: "1", domain: "example.com", sameSite: "strict" }).sameSite, "Strict");
  // unspecified -> omitted
  assert.equal("sameSite" in toCdpCookie({ name: "a", value: "1", domain: "example.com", sameSite: "unspecified" }), false);
});

test("expiry: session cookie omits expires, persistent keeps it", () => {
  const session = toCdpCookie({ name: "a", value: "1", domain: "example.com", session: true, expirationDate: 4102444800 });
  assert.equal("expires" in session, false);
  const persistent = toCdpCookie({ name: "a", value: "1", domain: "example.com", session: false, expirationDate: 4102444800.9 });
  assert.equal(persistent.expires, 4102444800);
});

test("__Host- prefix rules", () => {
  const ok = toCdpCookie({ name: "__Host-x", value: "1", domain: "example.com", path: "/", secure: true });
  assert.ok(ok);
  assert.equal(ok.url, "https://example.com/");
  assert.equal("domain" in ok, false);
  // leading dot rejected
  assert.equal(toCdpCookie({ name: "__Host-x", value: "1", domain: ".example.com", path: "/", secure: true }), null);
  // non-root path rejected
  assert.equal(toCdpCookie({ name: "__Host-x", value: "1", domain: "example.com", path: "/app", secure: true }), null);
  // not secure rejected
  assert.equal(toCdpCookie({ name: "__Host-x", value: "1", domain: "example.com", path: "/", secure: false }), null);
});

test("__Secure- prefix requires secure", () => {
  assert.equal(toCdpCookie({ name: "__Secure-x", value: "1", domain: "example.com", secure: false }), null);
  assert.ok(toCdpCookie({ name: "__Secure-x", value: "1", domain: "example.com", secure: true }));
});

test("allowlist filtering matches domain + subdomains", () => {
  const cookies = [
    { name: "a", value: "1", domain: "example.com" },
    { name: "b", value: "1", domain: ".example.com" },
    { name: "c", value: "1", domain: "sub.example.com" },
    { name: "d", value: "1", domain: "notexample.com" },
    { name: "e", value: "1", domain: "example.org" },
  ];
  const out = filterByAllowlist(cookies, ["example.com"]);
  assert.deepEqual(out.map((c) => c.name).sort(), ["a", "b", "c"]);
  // empty allowlist passes all through
  assert.equal(filterByAllowlist(cookies, []).length, cookies.length);
});

test("mapCookies counts skipped prefix violations", () => {
  const { cookies, skipped } = mapCookies(syntheticCookies);
  // fixtures include two deliberate violations (__Host-bad, __Secure-bad)
  assert.equal(skipped, 2);
  assert.ok(cookies.every((c) => typeof c.value === "string"));
});
