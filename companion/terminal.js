import path from 'node:path';
import { configHome, loadConfig, readJson, writePrivate, withProfileLock } from '../cli/config.js';
import { cookieParam, publishSnapshot } from '../cli/sync.js';
import { filterByAllowlist } from '../src/cookies.js';

const sameSite = { no_restriction: 'None', lax: 'Lax', strict: 'Strict' };

export async function terminalMessage(msg, { home = configHome(), ...deps } = {}) {
  const profiles = loadConfig(home).profiles.filter(p => p.protocol === 2 && !p.disabled && p.role === 'source' && p.sourceMode === 'extension');
  if (msg.type === 'terminalProfiles') return { ok: true, profiles: profiles.map(p => ({ name: p.name, domains: p.allowlist })) };
  const profile = profiles.find(p => p.name === msg.name);
  if (!profile) throw new Error('Run terminal setup with --source extension for this named profile');
  if (!/^[a-f0-9]{32}$/.test(msg.instanceId)) throw new Error('Invalid browser instance');
  return withProfileLock(home, profile.name, async paths => {
    const bindingPath = path.join(paths.dir, 'extension.json');
    const binding = readJson(bindingPath, null);
    if (binding && binding.instanceId !== msg.instanceId) throw new Error('Another Chrome profile is already connected to this source; choose a different source name');
    if (msg.type === 'terminalBind') {
      writePrivate(bindingPath, { instanceId: msg.instanceId });
      return { ok: true, name: profile.name };
    }
    if (msg.type !== 'terminalPush' || !binding) throw new Error('Connect this profile in ChromeSync extension settings first');
    if (!Array.isArray(msg.cookies)) throw new Error('Invalid cookie snapshot');
    const cookies = filterByAllowlist(msg.cookies, profile.allowlist).map(c => cookieParam({ ...c,
      expires: c.expirationDate, sameSite: sameSite[c.sameSite],
      domain: c.hostOnly ? c.domain.replace(/^\./, '') : c.domain,
    }));
    const state = readJson(paths.state, { counter: 0, accepted: 0, identities: [] });
    if (!Number.isSafeInteger(state.counter) || state.counter < 0) throw new Error('Invalid sync state');
    const result = await publishSnapshot(paths, state, profile, cookies, deps);
    return { ok: true, ...result };
  });
}
