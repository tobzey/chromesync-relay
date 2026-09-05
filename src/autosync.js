// Pure coalesce / throttle decisions for MV3 auto-sync.
// The service worker can be evicted, so callers must persist flags in
// chrome.storage and schedule chrome.alarms — never setTimeout.

export const PERIODIC_ALARM = "sync";
export const COALESCE_ALARM = "sync-coalesce";
export const RELAY_PULL_ALARM = "relay-pull";

export const COALESCE_DELAY_MINUTES = 0.5;
export const DEFAULT_THROTTLE_MS = 30_000;

/**
 * A cookie change arrived. Set pendingSync and, if no coalesce alarm is
 * already scheduled, ask the caller to create one.
 */
export function decideCookieChange({
  syncOnChange,
  pendingSync,
  coalesceScheduled,
  lastSyncAt,
  now,
  throttleMs = DEFAULT_THROTTLE_MS,
  coalesceDelayMinutes = COALESCE_DELAY_MINUTES,
} = {}) {
  if (!syncOnChange) {
    return {
      pendingSync: !!pendingSync,
      scheduleAlarm: false,
      alarmDelayMinutes: coalesceDelayMinutes,
    };
  }
  return {
    pendingSync: true,
    scheduleAlarm: !coalesceScheduled,
    alarmDelayMinutes: coalesceDelayMinutes,
    lastSyncAt: lastSyncAt || 0,
    now,
    throttleMs,
  };
}

/**
 * The coalescing alarm fired. Either run one sync, or reschedule if we are
 * still inside the min-interval throttle window.
 */
export function decideCoalesceFire({
  pendingSync,
  lastSyncAt,
  now,
  throttleMs = DEFAULT_THROTTLE_MS,
  coalesceDelayMinutes = COALESCE_DELAY_MINUTES,
} = {}) {
  if (!pendingSync) {
    return { shouldSync: false, pendingSync: false, reschedule: false, coalesceScheduled: false };
  }
  const elapsed = now - (lastSyncAt || 0);
  if (lastSyncAt && elapsed < throttleMs) {
    const remainMs = throttleMs - elapsed;
    return {
      shouldSync: false,
      pendingSync: true,
      reschedule: true,
      coalesceScheduled: true,
      alarmDelayMinutes: Math.max(coalesceDelayMinutes, remainMs / 60_000),
    };
  }
  return {
    shouldSync: true,
    pendingSync: false,
    reschedule: false,
    coalesceScheduled: false,
    lastSyncAt: now,
  };
}

export function decideRelayPullSchedule({ enabled, mode, pollMinutes } = {}) {
  const pull = mode === "pull" || mode === "both";
  if (!enabled || !pull) return { schedule: false };
  const period = Math.max(1, Number(pollMinutes) || 1);
  return { schedule: true, periodInMinutes: period };
}

export function decideRelayPullFire({ enabled, mode } = {}) {
  const pull = mode === "pull" || mode === "both";
  return { shouldPull: Boolean(enabled && pull) };
}
