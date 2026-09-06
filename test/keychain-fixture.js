// Explicit test-only credential backend, never shipped or selected by production code.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { setKeychainExecutor } from '../companion/keychain.js';
const dir = process.env.CHROMESYNC_TEST_KEYCHAIN || fs.mkdtempSync(path.join(os.tmpdir(), 'csync-synthetic-keychain-'));
process.env.CHROMESYNC_TEST_KEYCHAIN = dir;
setKeychainExecutor((command, args, options) => {
  const id = args.at(-1), value = args.includes('store') ? options.input : undefined;
  const file = path.join(dir, id || 'invalid');
  if (value) fs.writeFileSync(file, value, { mode: 0o600 });
  return fs.existsSync(file) ? { status: 0, stdout: value ? '' : fs.readFileSync(file, 'utf8') } : { status: 1, stdout: '' };
});
