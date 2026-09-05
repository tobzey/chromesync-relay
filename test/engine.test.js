import { test } from "node:test";
import assert from "node:assert/strict";
import { SyncEngine } from "../src/engine.js";
import { syntheticCookies } from "./fixtures.js";

function fakeSink(id, behavior) {
  return {
    id,
    label: id,
    async validate() {
      return behavior.validate || { ok: true };
    },
    async writeCookies(cookies) {
      if (behavior.throw) throw new Error("boom");
      return behavior.write || { written: cookies.length, skipped: 0, errors: [] };
    },
  };
}

function registryOf(...sinks) {
  const byId = new Map(sinks.map((s) => [s.id, s]));
  return { all: () => sinks, get: (id) => byId.get(id) };
}

test("sync fans out only to enabled sinks", async () => {
  const a = fakeSink("a", {});
  const b = fakeSink("b", {});
  const engine = new SyncEngine({ registry: registryOf(a, b), getAllCookies: async () => syntheticCookies });
  const summary = await engine.sync({
    allowlist: [],
    sinks: { a: { enabled: true }, b: { enabled: false } },
  });
  assert.ok(summary.sinks.a);
  assert.equal(summary.sinks.b, undefined);
  assert.equal(summary.sinks.a.ok, true);
});

test("one sink failing does not abort others", async () => {
  const good = fakeSink("good", {});
  const bad = fakeSink("bad", { throw: true });
  const engine = new SyncEngine({ registry: registryOf(bad, good), getAllCookies: async () => syntheticCookies });
  const summary = await engine.sync({
    allowlist: [],
    sinks: { good: { enabled: true }, bad: { enabled: true } },
  });
  assert.equal(summary.sinks.good.ok, true);
  assert.equal(summary.sinks.bad.ok, false);
  assert.ok(summary.sinks.bad.errors.length > 0);
});

test("invalid sink config is reported, not thrown", async () => {
  const s = fakeSink("s", { validate: { ok: false, error: "no config" } });
  const engine = new SyncEngine({ registry: registryOf(s), getAllCookies: async () => syntheticCookies });
  const summary = await engine.sync({ allowlist: [], sinks: { s: { enabled: true } } });
  assert.equal(summary.sinks.s.ok, false);
  assert.equal(summary.sinks.s.errors[0], "no config");
});

test("summary never contains cookie values", async () => {
  const s = fakeSink("s", {});
  const engine = new SyncEngine({ registry: registryOf(s), getAllCookies: async () => syntheticCookies });
  const summary = await engine.sync({ allowlist: [], sinks: { s: { enabled: true } } });
  const serialized = JSON.stringify(summary);
  for (const c of syntheticCookies) {
    assert.equal(serialized.includes(c.value), false, `value ${c.name} leaked`);
  }
});
