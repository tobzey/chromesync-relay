// Token-bucket rate limiter. Two instances are used: per IP and per room.
// Stock JS only. The buckets Map is capped so a flood of distinct keys
// cannot grow memory without bound.

export const MAX_BUCKETS = 10_000;

export class TokenBucket {
  constructor({ capacity, refillPerSec, maxBuckets } = {}) {
    this.capacity = Math.max(0, Number(capacity) || 0);
    this.refillPerSec = Math.max(0, Number(refillPerSec) || 0);
    const cap = Number(maxBuckets);
    this.maxBuckets = Number.isFinite(cap) && cap > 0 ? Math.trunc(cap) : MAX_BUCKETS;
    this.buckets = new Map();
  }

  take(key, now = Date.now()) {
    const id = String(key || "unknown");
    let b = this.buckets.get(id);
    if (!b) {
      b = { tokens: this.capacity, last: now };
      this.buckets.set(id, b);
      if (this.buckets.size > this.maxBuckets) this.evictOverflow(now);
    }
    const elapsed = Math.max(0, (now - b.last) / 1000);
    b.tokens = Math.min(this.capacity, b.tokens + elapsed * this.refillPerSec);
    b.last = now;
    if (b.tokens < 1) return false;
    b.tokens -= 1;
    return true;
  }

  // Drop keys whose idle time exceeds a full refill — lossless, they would
  // start full on the next take. If still over cap, evict oldest `last`.
  evictOverflow(now) {
    const refillMs =
      this.refillPerSec > 0 ? (this.capacity / this.refillPerSec) * 1000 : Infinity;
    if (Number.isFinite(refillMs)) {
      for (const [id, b] of this.buckets) {
        if (now - b.last > refillMs) this.buckets.delete(id);
      }
    }
    if (this.buckets.size <= this.maxBuckets) return;
    const overflow = this.buckets.size - this.maxBuckets;
    const ranked = [];
    for (const [id, b] of this.buckets) ranked.push([b.last, id]);
    ranked.sort((a, c) => a[0] - c[0] || (a[1] < c[1] ? -1 : a[1] > c[1] ? 1 : 0));
    for (let i = 0; i < overflow; i++) this.buckets.delete(ranked[i][1]);
  }
}
