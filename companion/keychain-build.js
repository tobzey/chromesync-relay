import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
export function buildMacKeychain(root = path.join(os.homedir(), '.cache', 'chromesync-native')) {
  const source = fileURLToPath(new URL('./keychain-macos.c', import.meta.url));
  const hash = crypto.createHash('sha256').update(fs.readFileSync(source)).update(process.arch).digest('hex');
  fs.mkdirSync(root, { recursive: true, mode: 0o700 });
  if (fs.lstatSync(root).isSymbolicLink()) throw new Error('Native helper directory must not be a symlink');
  fs.chmodSync(root, 0o700);
  const target = path.join(root, `keychain-${hash}`);
  if (fs.existsSync(target)) {
    if (!fs.lstatSync(target).isFile()) throw new Error('Invalid native keychain helper');
    return target;
  }
  const temp = fs.mkdtempSync(path.join(root, '.build-'));
  try {
    const binary = path.join(temp, 'keychain');
    const result = spawnSync('/usr/bin/xcrun', ['clang', '-O2', '-Wno-deprecated-declarations', source, '-framework', 'Security', '-framework', 'CoreFoundation', '-o', binary], { encoding: 'utf8', timeout: 60000 });
    if (result.status !== 0) throw new Error('Install Apple Command Line Tools (xcode-select --install) to build the macOS Keychain bridge');
    fs.chmodSync(binary, 0o700); fs.renameSync(binary, target);
    return target;
  } finally { fs.rmSync(temp, { recursive: true, force: true }); }
}
