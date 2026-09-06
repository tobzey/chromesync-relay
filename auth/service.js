import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { privateDir } from '../cli/config.js';

const roles = Object.freeze({ executor: 'executor', approver: 'approvals' });
const xml = value => String(value).replace(/[<>&"']/g, c => ({ '<': '&lt;', '>': '&gt;', '&': '&amp;', '"': '&quot;', "'": '&apos;' })[c]);
const systemd = (value, command = false) => {
  let result = value.replace(/%/g, '%%').replace(/\\/g, '\\\\').replace(/"/g, '\\"');
  if (command) result = result.replace(/\$/g, () => '$$');
  return `"${result}"`;
};

export function authServiceDefinition({ platform, home, userHome, node, cli, role }) {
  if (!Object.hasOwn(roles, role)) throw new Error('Authentication service role must be executor or approver');
  for (const value of [home, userHome, node, cli]) {
    if (typeof value !== 'string' || /[\u0000-\u001f\u007f]/.test(value)) throw new Error('Service paths must not contain control characters');
    if (!path.isAbsolute(value)) throw new Error('Authentication service paths must be absolute');
  }
  const label = `io.chromesync.auth.${role}`;
  const unit = `chromesync-auth-${role}.service`;
  const argv = [node, cli, 'auth', roles[role]];
  // authHome() appends /authentication. Setting this to home itself would
  // accidentally select a second nested authentication directory.
  const configHome = path.dirname(path.resolve(home));
  if (platform === 'darwin') return {
    label, unit, file: path.join(userHome, 'Library', 'LaunchAgents', `${label}.plist`),
    body: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>${label}</string>
<key>ProgramArguments</key><array>${argv.map(value => `<string>${xml(value)}</string>`).join('')}</array>
<key>EnvironmentVariables</key><dict><key>CHROMESYNC_HOME</key><string>${xml(configHome)}</string></dict>
<key>RunAtLoad</key><true/>
<key>KeepAlive</key><true/>
<key>ThrottleInterval</key><integer>30</integer>
<key>Umask</key><integer>63</integer>
<key>StandardOutPath</key><string>/dev/null</string>
<key>StandardErrorPath</key><string>/dev/null</string>
</dict></plist>
`,
  };
  if (platform !== 'linux') throw new Error('Authentication background services support macOS and Linux');
  return {
    label, unit, file: path.join(userHome, '.config', 'systemd', 'user', unit),
    body: `[Unit]
Description=ChromeSync authentication ${role}
After=network-online.target
[Service]
Type=simple
ExecStart=${argv.map(value => systemd(value, true)).join(' ')}
Environment=${systemd(`CHROMESYNC_HOME=${configHome}`)}
Restart=on-failure
RestartSec=30
UMask=0077
StandardOutput=null
StandardError=null
[Install]
WantedBy=default.target
`,
  };
}

// This function is called only by an explicit user install/uninstall command.
// Optional process/path dependencies support tests without user service writes.
export function manageAuthService(action, home, {
  role,
  platform = process.platform,
  userHome = os.homedir(),
  node = process.env.CHROMESYNC_NODE_PATH || process.execPath,
  cli = process.env.CHROMESYNC_APP_ROOT ? path.join(process.env.CHROMESYNC_APP_ROOT, 'cli', 'index.js') : fileURLToPath(new URL('../cli/index.js', import.meta.url)),
  uid = process.getuid?.(),
  runner = spawnSync,
} = {}) {
  if (!['install', 'uninstall'].includes(action)) throw new Error('Use auth service install or auth service uninstall');
  const definition = authServiceDefinition({ platform, home, userHome, node, cli, role });
  if (platform === 'darwin' && (!Number.isSafeInteger(uid) || uid < 0)) throw new Error('A user login domain is required');
  const run = (binary, args, optional = false) => {
    const result = runner(binary, args, { stdio: 'ignore', timeout: 15000 });
    if ((result?.error || result?.status !== 0) && !optional) throw new Error('Authentication service manager failed; inspect your user service manager');
  };
  if (action === 'install') {
    // These are shared user directories. Do not change their permissions.
    fs.mkdirSync(path.dirname(definition.file), { recursive: true });
    privateDir(home);
    if (fs.existsSync(definition.file) && fs.lstatSync(definition.file).isSymbolicLink()) throw new Error('Authentication service file must not be a symlink');
    const temporary = `${definition.file}.${crypto.randomBytes(8).toString('hex')}.tmp`;
    try {
      fs.writeFileSync(temporary, definition.body, { mode: 0o600, flag: 'wx' });
      fs.renameSync(temporary, definition.file);
    } finally { fs.rmSync(temporary, { force: true }); }
  }
  if (platform === 'darwin') {
    const domain = `gui/${uid}`;
    run('launchctl', ['bootout', `${domain}/${definition.label}`], true);
    if (action === 'install') run('launchctl', ['bootstrap', domain, definition.file]);
  } else if (action === 'install') {
    run('systemctl', ['--user', 'daemon-reload']);
    run('systemctl', ['--user', 'enable', definition.unit]);
    run('systemctl', ['--user', 'restart', definition.unit]);
  } else run('systemctl', ['--user', 'disable', '--now', definition.unit]);
  if (action === 'uninstall') {
    fs.rmSync(definition.file, { force: true });
    if (platform === 'linux') run('systemctl', ['--user', 'daemon-reload']);
  }
  return { status: action === 'install' ? 'installed' : 'uninstalled', role, file: definition.file };
}
