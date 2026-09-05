// Pure coalesce/throttle decisions. Fake alarms/storage, no browser.

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  decideCookieChange,
  decideCoalesceFire,
  decideRelayPullSchedule,
  decideRelayPullFire,
  COALESCE_DELAY_MINUTES,
} from "../src/autosync.js";

test("a burst of cookie changes coalesces into one sync", () => {
  const t0 = 1_700_000_000_000;
  const first = decideCookieChange({
    syncOnChange: true,
    pendingSync: false,
    coalesceScheduled: false,
    lastSyncAt: 0,
    now: t0,
  });
  assert.equal(first.pendingSync, true);
  assert.equal(first.scheduleAlarm, true);
  assert.equal(first.alarmDelayMinutes, COALESCE_DELAY_MINUTES);

  const second = decideCookieChange({
    syncOnChange: true,
    pendingSync: true,
    coalesceScheduled: true,
    lastSyncAt: 0,
    now: t0 + 100,
  });
  assert.equal(second.pendingSync, true);
  assert.equal(second.scheduleAlarm, false);

  const third = decideCookieChange({
    syncOnChange: true,
    pendingSync: true,
    coalesceScheduled: true,
    lastSyncAt: 0,
    now: t0 + 200,
  });
  assert.equal(third.scheduleAlarm, false);

  const fire = decideCoalesceFire({
    pendingSync: true,
    lastSyncAt: 0,
    now: t0 + 30_000,
  });
  assert.equal(fire.shouldSync, true);
  assert.equal(fire.pendingSync, false);
  assert.equal(fire.reschedule, false);
});

test("throttle blocks a too-soon re-sync and asks to reschedule", () => {
  const t0 = 1_700_000_000_000;
  const throttleMs = 30_000;
  const change = decideCookieChange({
    syncOnChange: true,
    pendingSync: false,
    coalesceScheduled: false,
    lastSyncAt: t0,
    now: t0 + 5_000,
    throttleMs,
  });
  assert.equal(change.pendingSync, true);
  assert.equal(change.scheduleAlarm, true);

  const fire = decideCoalesceFire({
    pendingSync: true,
    lastSyncAt: t0,
    now: t0 + 10_000,
    throttleMs,
  });
  assert.equal(fire.shouldSync, false);
  assert.equal(fire.pendingSync, true);
  assert.equal(fire.reschedule, true);
  assert.ok(fire.alarmDelayMinutes > 0);

  const later = decideCoalesceFire({
    pendingSync: true,
    lastSyncAt: t0,
    now: t0 + 30_000,
    throttleMs,
  });
  assert.equal(later.shouldSync, true);
  assert.equal(later.pendingSync, false);
});

test("syncOnChange false ignores cookie changes", () => {
  const d = decideCookieChange({
    syncOnChange: false,
    pendingSync: false,
    coalesceScheduled: false,
    now: 1,
  });
  assert.equal(d.pendingSync, false);
  assert.equal(d.scheduleAlarm, false);
});

test("relay pull schedule only when enabled and mode includes pull", () => {
  assert.deepEqual(decideRelayPullSchedule({ enabled: false, mode: "pull", pollMinutes: 1 }), { schedule: false });
  assert.deepEqual(decideRelayPullSchedule({ enabled: true, mode: "push", pollMinutes: 1 }), { schedule: false });
  assert.deepEqual(decideRelayPullSchedule({ enabled: true, mode: "pull", pollMinutes: 2 }), {
    schedule: true,
    periodInMinutes: 2,
  });
  assert.equal(decideRelayPullFire({ enabled: true, mode: "both" }).shouldPull, true);
  assert.equal(decideRelayPullFire({ enabled: true, mode: "push" }).shouldPull, false);
});
