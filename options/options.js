import { getConfig, setConfig } from "../src/storage.js";
import { buildInvite, parseInvite, generatePairingCode } from "../src/invite.js";
import { sendNative } from "../src/terminal.js";

const $ = (id) => document.getElementById(id);

function toForm(config) {
  $("intervalMinutes").value = config.intervalMinutes;
  $("syncOnChange").checked = config.syncOnChange !== false;
  $("allowlist").value = (config.allowlist || []).join("\n");
  $("persistLocal").checked = !!config.persistLocal;

  const lc = config.sinks["local-chrome"];
  $("lc_enabled").checked = !!lc.enabled;
  $("lc_userDataDir").value = lc.userDataDir || "";
  $("lc_port").value = lc.port || 0;

  const fd = config.sinks["file-drop"] || {};
  $("fd_enabled").checked = !!fd.enabled;
  $("fd_dropDir").value = fd.dropDir || "";
  $("fd_pairingSecret").value = fd.pairingSecret || "";
  $("fd_sourceHostId").value = fd.sourceHostId || "";
  $("fd_statePath").value = fd.statePath || "";

  const rel = config.sinks.relay || {};
  $("rel_enabled").checked = !!rel.enabled;
  $("rel_relayUrl").value = rel.relayUrl || "";
  $("rel_pairingSecret").value = rel.pairingSecret || "";
  $("rel_mode").value = rel.mode || "push";
  $("rel_userDataDir").value = rel.userDataDir || "";
  $("rel_port").value = rel.port || 0;

  const bu = config.sinks["browser-use"];
  $("bu_enabled").checked = !!bu.enabled;
  $("bu_baseUrl").value = bu.baseUrl || "";
  $("bu_apiKey").value = bu.apiKey || "";
  $("bu_profileId").value = bu.profileId || "";
  $("bu_profileUseDir").value = bu.profileUseDir || "";
}

function fromForm() {
  return {
    intervalMinutes: Math.max(1, Number($("intervalMinutes").value) || 45),
    syncOnChange: $("syncOnChange").checked,
    allowlist: $("allowlist").value.split("\n").map((s) => s.trim()).filter(Boolean),
    persistLocal: $("persistLocal").checked,
    sinks: {
      "local-chrome": {
        enabled: $("lc_enabled").checked,
        userDataDir: $("lc_userDataDir").value.trim(),
        port: Number($("lc_port").value) || 0,
      },
      "file-drop": {
        enabled: $("fd_enabled").checked,
        dropDir: $("fd_dropDir").value.trim(),
        pairingSecret: $("fd_pairingSecret").value,
        sourceHostId: $("fd_sourceHostId").value.trim(),
        statePath: $("fd_statePath").value.trim(),
      },
      relay: {
        enabled: $("rel_enabled").checked,
        relayUrl: $("rel_relayUrl").value.trim(),
        pairingSecret: $("rel_pairingSecret").value,
        mode: $("rel_mode").value || "push",
        userDataDir: $("rel_userDataDir").value.trim(),
        port: Number($("rel_port").value) || 0,
      },
      "browser-use": {
        enabled: $("bu_enabled").checked,
        baseUrl: $("bu_baseUrl").value.trim(),
        apiKey: $("bu_apiKey").value,
        profileId: $("bu_profileId").value.trim(),
        profileUseDir: $("bu_profileUseDir").value.trim(),
      },
    },
  };
}

function setInviteStatus(text) {
  const el = $("rel_inviteStatus");
  el.textContent = text;
}

$("rel_generate").addEventListener("click", () => {
  $("rel_pairingSecret").value = generatePairingCode();
  setInviteStatus("New pairing code filled in. Save, then copy the invite for your other device.");
});

$("rel_copyInvite").addEventListener("click", async () => {
  try {
    const invite = buildInvite({
      relayUrl: $("rel_relayUrl").value.trim(),
      secret: $("rel_pairingSecret").value,
    });
    await navigator.clipboard.writeText(invite);
    setInviteStatus("Invite copied. It contains the pairing code — share it privately.");
  } catch {
    setInviteStatus("Need a server address and a pairing code first.");
  }
});

$("rel_pasteInvite").addEventListener("click", () => {
  try {
    const parsed = parseInvite($("rel_invite").value);
    $("rel_relayUrl").value = parsed.relayUrl;
    $("rel_pairingSecret").value = parsed.secret;
    setInviteStatus("Invite applied. Save to keep it. Share invites only privately.");
  } catch {
    setInviteStatus("That invite isn’t valid.");
  }
});

$("save").addEventListener("click", async () => {
  await setConfig(fromForm());
  chrome.runtime.sendMessage({ type: "reschedule" });
  const saved = $("saved");
  saved.textContent = "Saved.";
  setTimeout(() => (saved.textContent = ""), 2000);
});

getConfig().then(toForm);

async function loadTerminalProfiles() {
  const status = $('terminal_status');
  try {
    const { profiles } = await sendNative({ type: 'terminalProfiles' });
    const { terminalBinding } = await chrome.storage.local.get('terminalBinding');
    $('terminal_profile').replaceChildren();
    for (const p of profiles) {
      const option = document.createElement('option');
      option.value = p.name;
      option.textContent = `${p.name} (${p.domains.length ? p.domains.join(', ') : 'all domains'})`;
      $('terminal_profile').append(option);
    }
    if (terminalBinding) $('terminal_profile').value = terminalBinding.name;
    $('terminal_connect').disabled = profiles.length === 0;
    status.textContent = terminalBinding ? `Connected to ${terminalBinding.name}. Cookies sync automatically while Chrome is open.`
      : profiles.length ? 'Choose a source, then connect this browser.' : 'Run chromesync setup and choose an existing Chrome profile.';
  } catch (error) {
    $('terminal_connect').disabled = true;
    status.textContent = error.message;
  }
}
$('terminal_connect').addEventListener('click', async () => {
  $('terminal_status').textContent = 'Connecting…';
  try {
    const result = await chrome.runtime.sendMessage({ type: 'terminalConnect', name: $('terminal_profile').value });
    if (result?.error) throw new Error(result.error);
    await loadTerminalProfiles();
  } catch (error) { $('terminal_status').textContent = error.message; }
});
$('terminal_refresh').addEventListener('click', loadTerminalProfiles);
$('terminal_disconnect').addEventListener('click', async () => {
  await chrome.storage.local.remove('terminalBinding');
  await chrome.runtime.sendMessage({ type: 'reschedule' });
  await loadTerminalProfiles();
});
loadTerminalProfiles();
