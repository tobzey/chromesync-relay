export function sendNative(message) {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendNativeMessage('io.chromesync.host', message, response => {
      if (chrome.runtime.lastError) reject(new Error('Bridge unavailable; run chromesync extension install in your terminal'));
      else if (!response?.ok) reject(new Error(response?.error || 'Bridge request failed'));
      else resolve(response);
    });
  });
}

export async function collectTerminalCookies(api = chrome.cookies) {
  // Include partitioned jars as well as unpartitioned cookies. A failed read must
  // abort the snapshot; an incomplete snapshot would incorrectly remove sessions.
  const groups = await Promise.all([api.getAll({}), api.getAll({ partitionKey: {} })]);
  const cookies = new Map();
  for (const c of groups.flat()) {
    const key = JSON.stringify([c.storeId, c.name, c.domain, c.path, c.partitionKey?.topLevelSite, c.partitionKey?.hasCrossSiteAncestor]);
    cookies.set(key, c);
  }
  return [...cookies.values()];
}

export async function syncTerminal(binding, { collect = collectTerminalCookies, send = sendNative } = {}) {
  const cookies = await collect();
  const result = await send({ type: 'terminalPush', name: binding.name, instanceId: binding.instanceId, cookies });
  return { at: Date.now(), collected: cookies.length, mappingSkipped: 0,
    sinks: { [binding.name]: { ok: true, written: result.written || 0, skipped: 0, errors: [] } } };
}
