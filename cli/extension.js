import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { privateDir, readJson, writePrivate } from './config.js';

const root = process.env.CHROMESYNC_APP_ROOT || fileURLToPath(new URL('../', import.meta.url));
export const shellQuote = value => "'" + String(value).replace(/'/g, "'\\''") + "'";

export function extensionId(manifest = readJson(path.join(root, 'manifest.json'))) {
  if (!manifest.key) throw new Error('The extension manifest has no public identity key');
  return crypto.createHash('sha256').update(Buffer.from(manifest.key, 'base64')).digest('hex')
    .slice(0, 32).replace(/[0-9a-f]/g, c => String.fromCharCode(97 + parseInt(c, 16)));
}

export function registerExtension(home, { userHome = os.homedir(), platform = process.platform, id = extensionId(), node = process.env.CHROMESYNC_NODE_PATH || process.execPath, appRoot = root } = {}) {
  if (!/^[a-p]{32}$/.test(id)) throw new Error('Invalid extension identity');
  let bases;
  if (platform === 'darwin') bases = ['Library/Application Support/Google/Chrome', 'Library/Application Support/Google/Chrome Beta',
    'Library/Application Support/Google/Chrome Canary', 'Library/Application Support/Chromium'];
  else if (platform === 'linux') bases = ['.config/google-chrome', '.config/google-chrome-beta', '.config/chromium'];
  else throw new Error('Native bridge registration supports macOS and Linux');
  const native = path.join(home, 'native');
  privateDir(home);
  privateDir(native);
  const launcher = path.join(native, 'launch.sh');
  fs.writeFileSync(launcher, `#!/bin/sh\nexport CHROMESYNC_HOME=${shellQuote(home)}\nexec ${shellQuote(node)} ${shellQuote(path.join(appRoot, 'companion/host.js'))} "$@"\n`, { mode: 0o700 });
  fs.chmodSync(launcher, 0o700);
  const manifest = { name: 'io.chromesync.host', description: 'ChromeSync local companion', path: launcher, type: 'stdio', allowed_origins: [`chrome-extension://${id}/`] };
  const directories = bases.map(base => path.join(userHome, base, 'NativeMessagingHosts'));
  if (process.env.CHROME_USER_DATA_DIR) directories.push(path.join(path.resolve(process.env.CHROME_USER_DATA_DIR), 'NativeMessagingHosts'));
  for (const dir of directories) {
    fs.mkdirSync(dir, { recursive: true });
    writePrivate(path.join(dir, 'io.chromesync.host.json'), manifest);
  }
  return { status: 'registered', extensionFolder: appRoot.replace(/\/$/, ''),
    next: 'In your source Chrome: chrome://extensions → Developer mode → Load unpacked → choose extensionFolder. Then open ChromeSync settings and connect your named profile.' };
}
