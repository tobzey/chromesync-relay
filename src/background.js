import { SyncEngine } from "./engine.js";
import { buildRegistry } from "./sinks/registry.js";
import { getConfig, setLastSync } from "./storage.js";
import { sendNative, syncTerminal } from "./terminal.js";
import {
  PERIODIC_ALARM,
  COALESCE_ALARM,
  RELAY_PULL_ALARM,
  decideCookieChange,
  decideCoalesceFire,
  decideRelayPullSchedule,
  decideRelayPullFire,
} from "./autosync.js";

function makeEngine() {
  return new SyncEngine({
    registry: buildRegistry(),
    getAllCookies: () => chrome.cookies.getAll({}),
  });
}

async function runSync(reason) {
  const { terminalBinding } = await chrome.storage.local.get('terminalBinding');
  if (terminalBinding) {
    const summary = await syncTerminal(terminalBinding);
    summary.reason = reason;
    await setLastSync(summary);
    await chrome.storage.local.set({ lastSyncAt: Date.now() });
    return summary;
  }
  const config = await getConfig();
  const engine = makeEngine();
  const summary = await engine.sync(config);
  summary.reason = reason;
  await setLastSync(summary);
  await chrome.storage.local.set({ lastSyncAt: Date.now() });
  return summary;
}

async function scheduleFromConfig() {
  const config = await getConfig();
  const { terminalBinding } = await chrome.storage.local.get('terminalBinding');
  const periodInMinutes = terminalBinding ? 1 : Math.max(1, Number(config.intervalMinutes) || 45);
  await chrome.alarms.create(PERIODIC_ALARM, { periodInMinutes });
  const relay = (config.sinks && config.sinks.relay) || {};
  const pull = decideRelayPullSchedule(relay);
  if (pull.schedule && !terminalBinding) {
    await chrome.alarms.create(RELAY_PULL_ALARM, { periodInMinutes: pull.periodInMinutes });
  } else {
    await chrome.alarms.clear(RELAY_PULL_ALARM);
  }
}

async function handleCoalesce() {
  const st = await chrome.storage.local.get(["pendingSync", "lastSyncAt"]);
  const decision = decideCoalesceFire({
    pendingSync: st.pendingSync,
    lastSyncAt: st.lastSyncAt,
    now: Date.now(),
  });
  if (decision.reschedule) {
    await chrome.alarms.create(COALESCE_ALARM, { delayInMinutes: decision.alarmDelayMinutes });
    await chrome.storage.local.set({ coalesceScheduled: true, pendingSync: true });
    return;
  }
  await chrome.storage.local.set({
    coalesceScheduled: false,
    pendingSync: false,
  });
  if (decision.shouldSync) {
    await runSync("cookie-change");
  }
}

async function handleRelayPull() {
  if ((await chrome.storage.local.get('terminalBinding')).terminalBinding) return;
  const config = await getConfig();
  const relay = (config.sinks && config.sinks.relay) || {};
  const d = decideRelayPullFire(relay);
  if (!d.shouldPull) return;
  if (!relay.relayUrl || !relay.pairingSecret) return;
  try {
    await sendNative({
      type: "relayPull",
      relayUrl: relay.relayUrl,
      pairingSecret: relay.pairingSecret,
      sourceHostId: relay.sourceHostId || "",
      statePath: relay.statePath || "",
      userDataDir: relay.userDataDir || "",
      port: relay.port || 0,
      maxAgeMs: relay.maxAgeMs || 0,
    });
  } catch {}
}

chrome.runtime.onInstalled.addListener(({ reason }) => {
  scheduleFromConfig();
  if (reason === 'install') chrome.runtime.openOptionsPage();
});

chrome.runtime.onStartup.addListener(() => {
  scheduleFromConfig();
  runSync("startup").catch(() => {});
});

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === PERIODIC_ALARM) runSync("alarm").catch(() => {});
  if (alarm.name === COALESCE_ALARM) handleCoalesce().catch(() => {});
  if (alarm.name === RELAY_PULL_ALARM) handleRelayPull().catch(() => {});
});

if (chrome.idle && chrome.idle.onStateChanged) {
  chrome.idle.onStateChanged.addListener((state) => {
    if (state === "idle") runSync("idle").catch(() => {});
  });
}

if (chrome.cookies && chrome.cookies.onChanged) {
  chrome.cookies.onChanged.addListener(() => {
    (async () => {
      const config = await getConfig();
      const st = await chrome.storage.local.get(["pendingSync", "lastSyncAt", "coalesceScheduled"]);
      const d = decideCookieChange({
        syncOnChange: config.syncOnChange !== false,
        pendingSync: st.pendingSync,
        coalesceScheduled: st.coalesceScheduled,
        lastSyncAt: st.lastSyncAt,
        now: Date.now(),
      });
      await chrome.storage.local.set({ pendingSync: d.pendingSync });
      if (d.scheduleAlarm) {
        await chrome.alarms.create(COALESCE_ALARM, { delayInMinutes: d.alarmDelayMinutes });
        await chrome.storage.local.set({ coalesceScheduled: true });
      }
    })().catch(() => {});
  });
}

// Messages from popup/options: { type: "syncNow" | "reschedule" }.
chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg?.type === 'terminalConnect') {
    (async () => {
      const { terminalInstanceId = Array.from(crypto.getRandomValues(new Uint8Array(16)), b => b.toString(16).padStart(2, '0')).join('') } = await chrome.storage.local.get('terminalInstanceId');
      await chrome.storage.local.set({ terminalInstanceId });
      await sendNative({ type: 'terminalBind', name: msg.name, instanceId: terminalInstanceId });
      await chrome.storage.local.set({ terminalBinding: { name: msg.name, instanceId: terminalInstanceId } });
      await scheduleFromConfig();
      return runSync('connected');
    })().then(sendResponse).catch(e => sendResponse({ error: e.message }));
    return true;
  }
  if (msg && msg.type === "syncNow") {
    (async () => {
      const summary = await runSync("manual");
      // Receive mode: Sync now must also pull (alarms alone are easy to miss).
      await handleRelayPull();
      return summary;
    })()
      .then(sendResponse)
      .catch((e) => sendResponse({ error: String(e && e.message || e) }));
    return true; // async
  }
  if (msg && msg.type === "reschedule") {
    scheduleFromConfig().then(() => sendResponse({ ok: true })).catch((e) => sendResponse({ error: String(e) }));
    return true;
  }
  return false;
});
