// Read shipped extension code only. Never opens a profile database or live account.
// Usage: node inspect-onepassword-extension.mjs /path/to/extension/version
import { readFile, realpath } from 'node:fs/promises';
import path from 'node:path';
import { createHash } from 'node:crypto';

const input = process.argv[2];
if (!input) throw new Error('Supply the installed extension version directory.');
const root = await realpath(input);
const files = [
  'manifest.json',
  'background/background.js',
  'inline/injected/secure-remote-autofill-start-pairing.js',
  'inline/injected/secure-remote-autofill-complete-pairing.js',
];
const content = new Map();
const artifacts = [];
for (const file of files) {
  const resolved = await realpath(path.join(root, file));
  if (!resolved.startsWith(root + path.sep)) throw new Error('Code path leaves the supplied directory.');
  const bytes = await readFile(resolved);
  if (bytes.length > 40 * 1024 * 1024) throw new Error('Unexpectedly large code file.');
  artifacts.push({ file, bytes: bytes.length, sha256: createHash('sha256').update(bytes).digest('hex') });
  content.set(file, bytes.toString('utf8'));
}
const manifest = JSON.parse(content.get('manifest.json'));
if (manifest.short_name !== '1Password' || manifest.manifest_version !== 3) {
  throw new Error('Expected a 1Password MV3 extension package.');
}
const background = content.get('background/background.js');
const symbols = [
  'enableAgenticMode', 'requestCredentialAccess', 'listGrantedCredentials',
  'autofillCredential', 'releaseCredentialAccess', 'agentic-autofill-item-cache',
  'NmSendSecureRemoteAutofillCredentialBundle', '/api/v2/mycelium/u/reconnect',
  'ChannelReconnectAuth', 'AGENTIC_AUTOFILL', 'agenticModeNotEnabled',
  'noExistingCredentials', 'autosubmitFailed',
];
const evidence = symbols.map(symbol => {
  const offsets = [];
  let index = 0;
  while ((index = background.indexOf(symbol, index)) !== -1) {
    offsets.push(Buffer.byteLength(background.slice(0, index)));
    index += symbol.length;
  }
  return { symbol, byteOffsets: offsets };
});
console.log(JSON.stringify({
  kind: 'static-code-inventory',
  version: manifest.version,
  artifacts,
  pairingScripts: manifest.content_scripts.filter(s => s.js?.some(p => p.includes('remote-autofill'))),
  evidence,
  note: 'Symbol presence is evidence for manual analysis, not proof of a supported API or successful authentication.',
}, null, 2));
