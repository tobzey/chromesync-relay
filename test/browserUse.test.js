import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { BrowserUseSink } from "../src/sinks/browserUse.js";
import { mapCookies } from "../src/cookies.js";
import { syntheticCookies } from "./fixtures.js";
import { createMockBuServer } from "../mock/bu-api.js";

let mock;
let baseUrl;

before(async () => {
  mock = createMockBuServer();
  baseUrl = (await mock.listen()) + "";
});

after(async () => {
  await mock.close();
});

test("validate() hits GET /profiles against the mock", async () => {
  const sink = new BrowserUseSink();
  const res = await sink.validate({ apiKey: "dummy-key", baseUrl });
  assert.equal(res.ok, true);
});

test("validate() fails without api key (no network)", async () => {
  const sink = new BrowserUseSink();
  const res = await sink.validate({ baseUrl });
  assert.equal(res.ok, false);
});

test("writeCookies() runs session->push->stop flow against mock", async () => {
  const sink = new BrowserUseSink();
  const { cookies } = mapCookies(syntheticCookies);
  const res = await sink.writeCookies(cookies, { apiKey: "dummy-key", baseUrl, profileId: "test-profile" });
  assert.equal(res.errors.length, 0);
  assert.equal(res.written, cookies.length);

  // Mock recorded a stopped session with the cookies.
  const sessions = [...mock.state.sessions.values()];
  assert.equal(sessions.length, 1);
  assert.equal(sessions[0].stopped, true);
  assert.equal(sessions[0].cookies.length, cookies.length);
});

test("writeCookies() refuses without profileId", async () => {
  const sink = new BrowserUseSink();
  const res = await sink.writeCookies([], { apiKey: "dummy-key", baseUrl });
  assert.equal(res.written, 0);
  assert.ok(res.errors[0].includes("profileId"));
});
