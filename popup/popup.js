const statusEl = document.getElementById("status");

function render(summary) {
  if (!summary) {
    statusEl.textContent = "No sync yet.";
    statusEl.className = "status muted";
    return;
  }
  const when = new Date(summary.at).toLocaleString();
  const lines = [`Last sync: ${when} (${summary.reason || "?"})`, `Collected: ${summary.collected} cookies`];
  for (const [id, r] of Object.entries(summary.sinks || {})) {
    const state = r.ok ? "ok" : "error";
    lines.push(`• ${id}: ${state} — wrote ${r.written}, skipped ${r.skipped}` + (r.errors.length ? ` (${r.errors.join("; ")})` : ""));
  }
  statusEl.textContent = lines.join("\n");
  statusEl.className = "status";
}

async function loadLast() {
  const { lastSync } = await chrome.storage.local.get("lastSync");
  render(lastSync);
}

document.getElementById("syncNow").addEventListener("click", async () => {
  statusEl.textContent = "Syncing…";
  statusEl.className = "status muted";
  chrome.runtime.sendMessage({ type: "syncNow" }, (summary) => {
    if (chrome.runtime.lastError) {
      statusEl.textContent = "Error: " + chrome.runtime.lastError.message;
      return;
    }
    if (summary && summary.error) {
      statusEl.textContent = "Error: " + summary.error;
      return;
    }
    render(summary);
  });
});

document.getElementById("openOptions").addEventListener("click", (e) => {
  e.preventDefault();
  chrome.runtime.openOptionsPage();
});

loadLast();
