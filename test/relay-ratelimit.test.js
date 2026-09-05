// Token-bucket cap + eviction. Synthetic keys only; no network.

import { test } from "node:test";
import assert from "node:assert/strict";
import { TokenBucket, MAX_BUCKETS } from "../server/ratelimit.js";

test("TokenBucket buckets Map stays bounded under a flood of distinct keys", () => {
  const maxBuckets = 50;
  const limiter = new TokenBucket({ capacity: 5, refillPerSec: 1, maxBuckets });
  const t0 = 1_700_000_000_000;
  for (let i = 0; i < maxBuckets * 8; i++) {
    limiter.take(`k${i}`, t0);
  }
  assert.ok(
    limiter.buckets.size <= maxBuckets,
    `size ${limiter.buckets.size} exceeded cap ${maxBuckets}`,
  );

  const def = new TokenBucket({ capacity: 1, refillPerSec: 1 });
  for (let i = 0; i < MAX_BUCKETS + 250; i++) def.take(`d${i}`, t0);
  assert.ok(def.buckets.size <= MAX_BUCKETS, `default cap broken: ${def.buckets.size}`);
});

test("TokenBucket idle sweep drops fully-refilled keys losslessly", () => {
  const limiter = new TokenBucket({ capacity: 10, refillPerSec: 10, maxBuckets: 5 });
  const t0 = 1_700_000_000_000;
  for (let i = 0; i < 8; i++) limiter.take(`old${i}`, t0);
  assert.ok(limiter.buckets.size <= 5);

  // Full refill takes 1s; 2s idle means dropping them is lossless.
  limiter.take("new", t0 + 2000);
  assert.ok(limiter.buckets.size <= 5);
  assert.equal(limiter.buckets.has("new"), true);
  for (let i = 0; i < 8; i++) assert.equal(limiter.buckets.has(`old${i}`), false);
});

test("TokenBucket live-key allow/deny is unchanged when other keys are evicted", () => {
  const limiter = new TokenBucket({ capacity: 2, refillPerSec: 0, maxBuckets: 4 });
  const t0 = 1_700_000_000_000;
  assert.equal(limiter.take("live", t0), true);
  assert.equal(limiter.take("live", t0), true);
  assert.equal(limiter.take("live", t0), false);
  limiter.take("a", t0);
  limiter.take("b", t0);
  limiter.take("c", t0);
  // Refresh `last` so `live` is not the oldest entry when we overflow.
  assert.equal(limiter.take("live", t0 + 50), false);
  for (let i = 0; i < 20; i++) limiter.take(`x${i}`, t0 + 10);
  assert.ok(limiter.buckets.size <= 4);
  assert.equal(limiter.buckets.has("live"), true);
  assert.equal(limiter.take("live", t0 + 100), false);
});
