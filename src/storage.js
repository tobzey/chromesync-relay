// Config storage. Default backing store is chrome.storage.session so the API
// key never touches disk. Users may opt in to chrome.storage.local
// (persistLocal) at the documented cost that the key is then stored on disk
// under the browser profile.

export const DEFAULT_CONFIG = {
  intervalMinutes: 45,
  allowlist: [],
  persistLocal: false,
  syncOnChange: true,
  sinks: {
    "local-chrome": { enabled: false, userDataDir: "", port: 0 },
    "file-drop": {
      enabled: false,
      dropDir: "",
      pairingSecret: "",
      sourceHostId: "",
      statePath: "",
    },
    relay: {
      enabled: false,
      relayUrl: "",
      pairingSecret: "",
      mode: "push",
      sourceHostId: "",
      statePath: "",
      userDataDir: "",
      port: 0,
      pollMinutes: 1,
      maxAgeMs: 0,
    },
    "browser-use": {
      enabled: false,
      apiKey: "",
      baseUrl: "https://api.browser-use.com/api/v3",
      profileId: "",
      profileUseDir: "",
    },
  },
};

function area(persistLocal) {
  return persistLocal ? chrome.storage.local : chrome.storage.session;
}

export async function getConfig() {
  // persistLocal flag itself always lives in local storage so we know where to look.
  const { persistLocal = false } = await chrome.storage.local.get("persistLocal");
  const { config } = await area(persistLocal).get("config");
  const merged = deepMerge(structuredClone(DEFAULT_CONFIG), config || {}, { persistLocal });
  // Purge historical secret copies from both storage areas on first access.
  await chrome.storage.local.remove('relayPairing');
  for (const target of [chrome.storage.local, chrome.storage.session]) {
    const stored = await target.get('config');
    if (stored.config) { scrubLegacy(stored.config); await target.set({ config: stored.config }); }
  }
  scrubLegacy(merged);
  return merged;
}

export async function setConfig(config) {
  config = structuredClone(config);
  scrubLegacy(config);
  const persistLocal = !!config.persistLocal;
  await chrome.storage.local.set({ persistLocal });
  await area(persistLocal).set({ config });
  // Never leave a stale key in the other area after switching.
  await area(!persistLocal).remove("config");
  await chrome.storage.local.remove('relayPairing');
}

export async function getLastSync() {
  const { lastSync } = await chrome.storage.local.get("lastSync");
  return lastSync || null;
}

export async function setLastSync(summary) {
  // Counts and generic errors only — never cookie names/values.
  await chrome.storage.local.set({ lastSync: summary });
}

function deepMerge(base, override, extra) {
  const out = { ...base };
  for (const [k, v] of Object.entries(override)) {
    out[k] = v && typeof v === "object" && !Array.isArray(v) ? deepMerge(base[k] || {}, v) : v;
  }
  return { ...out, ...extra };
}

function scrubLegacy(config) {
  for (const name of ['relay', 'file-drop']) {
    if (config.sinks?.[name]) { config.sinks[name].pairingSecret = ''; config.sinks[name].enabled = false; }
  }
}
