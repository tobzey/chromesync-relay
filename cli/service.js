import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { privateDir } from './config.js';
import { resolveChromePath } from '../companion/host-core.js';

const xml = value => String(value).replace(/[<>&"']/g, c => ({ '<': '&lt;', '>': '&gt;', '&': '&amp;', '"': '&quot;', "'": '&apos;' })[c]);
const systemd = (value, command = false) => {
  let escaped = String(value).replace(/%/g, '%%').replace(/\\/g, '\\\\').replace(/"/g, '\\"');
  if (command) escaped = escaped.replace(/\$/g, () => '$$');
  return '"' + escaped + '"';
};

export function serviceDefinition({ platform, home, userHome, node, cli, chrome, launch = false }) {
  const argv = [node, cli, 'watch', ...(launch ? ['--launch'] : [])];
  if ([...argv, home, chrome || ''].some(v => /[\r\n\0]/.test(v))) throw new Error('Service paths must not contain control characters');
  if (platform === 'darwin') {
    const file = path.join(userHome, 'Library/LaunchAgents/io.chromesync.agent.plist');
    const env = { CHROMESYNC_HOME: home, ...(chrome ? { CHROMESYNC_CHROME: chrome } : {}) };
    return { file, body: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>io.chromesync.agent</string>
<key>ProgramArguments</key><array>${argv.map(v => `<string>${xml(v)}</string>`).join('')}</array>
<key>EnvironmentVariables</key><dict>${Object.entries(env).map(([k, v]) => `<key>${xml(k)}</key><string>${xml(v)}</string>`).join('')}</dict>
<key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
<key>ThrottleInterval</key><integer>30</integer>
<key>StandardOutPath</key><string>/dev/null</string>
<key>StandardErrorPath</key><string>/dev/null</string>
</dict></plist>\n` };
  }
  if (platform !== 'linux') throw new Error('Background service supports macOS and Linux; use watch in your process supervisor');
  return { file: path.join(userHome, '.config/systemd/user/chromesync.service'), body: `[Unit]
Description=ChromeSync cookie sync
After=network-online.target
[Service]
Type=simple
ExecStart=${argv.map(value => systemd(value, true)).join(' ')}
Environment=${systemd(`CHROMESYNC_HOME=${home}`)}
${chrome ? `Environment=${systemd(`CHROMESYNC_CHROME=${chrome}`)}\n` : ''}Restart=on-failure
RestartSec=30
UMask=0077
[Install]
WantedBy=default.target
` };
}

export function manageService(action, home, { launch = false } = {}) {
  if (!['install', 'uninstall'].includes(action)) throw new Error('Use service install or service uninstall');
  const def = serviceDefinition({ platform: process.platform, home, userHome: os.homedir(), node: process.env.CHROMESYNC_NODE_PATH || process.execPath,
    cli: process.env.CHROMESYNC_APP_ROOT ? path.join(process.env.CHROMESYNC_APP_ROOT, 'cli/index.js') : fileURLToPath(new URL('./index.js', import.meta.url)), chrome: resolveChromePath(), launch });
  const run = (bin, args, optional = false) => {
    const result = spawnSync(bin, args, { stdio: 'ignore' });
    if ((result.error || result.status !== 0) && !optional) throw new Error('Service manager failed; inspect the generated service file and your user service manager');
  };
  if (action === 'install') {
    // Do not chmod existing shared LaunchAgents/systemd directories.
    fs.mkdirSync(path.dirname(def.file), { recursive: true });
    privateDir(home);
    fs.writeFileSync(def.file, def.body, { mode: 0o600 });
  }
  if (process.platform === 'darwin') {
    const domain = `gui/${process.getuid()}`;
    run('launchctl', ['bootout', `${domain}/io.chromesync.agent`], true);
    if (action === 'install') run('launchctl', ['bootstrap', domain, def.file]);
  } else {
    if (action === 'install') {
      run('systemctl', ['--user', 'daemon-reload']);
      run('systemctl', ['--user', 'enable', 'chromesync.service']);
      run('systemctl', ['--user', 'restart', 'chromesync.service']);
    } else run('systemctl', ['--user', 'disable', '--now', 'chromesync.service']);
  }
  if (action === 'uninstall') {
    fs.rmSync(def.file, { force: true });
    if (process.platform === 'linux') run('systemctl', ['--user', 'daemon-reload']);
  }
  return { status: action === 'install' ? 'installed' : 'uninstalled', file: def.file };
}
