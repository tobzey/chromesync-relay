import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { shellQuote, registerExtension } from './extension.js';
import { configHome } from './config.js';

function stat(file) {
  try { return fs.lstatSync(file); } catch (error) { if (error.code === 'ENOENT') return null; throw error; }
}

function replaceLink(target, file) {
  if (stat(file) && !stat(file).isSymbolicLink()) throw new Error(`Refusing to replace an existing file or directory: ${file}`);
  const tmp = `${file}.next-${process.pid}`;
  fs.symlinkSync(target, tmp);
  try { fs.renameSync(tmp, file); } finally { fs.rmSync(tmp, { force: true }); }
}

export function activate(root, bin, commit, node = process.execPath) {
  if (!/^[a-f0-9]{40}$/.test(commit) || !path.isAbsolute(root) || !path.isAbsolute(bin)) throw new Error('Invalid installation paths or revision');
  const release = path.join(root, 'releases', commit);
  for (const file of ['cli/index.js', 'manifest.json', 'companion/host.js']) if (!fs.statSync(path.join(release, file)).isFile()) throw new Error('Incomplete ChromeSync release');
  const command = path.join(bin, 'chromesync');
  // Do not replace a command owned by another installation.
  if (stat(command) && (!stat(command).isSymbolicLink() || fs.readlinkSync(command) !== path.join(root, 'launcher'))) throw new Error('Another chromesync command already exists in the chosen bin directory');
  for (const file of ['current', 'node']) if (stat(path.join(root, file)) && !stat(path.join(root, file)).isSymbolicLink()) throw new Error(`Installation path ${file} is owned by an existing file or directory`);
  replaceLink(release, path.join(root, 'current'));
  replaceLink(node, path.join(root, 'node'));
  const appRoot = path.join(root, 'current');
  const body = `#!/bin/sh\nexport CHROMESYNC_APP_ROOT=${shellQuote(appRoot)}\nexport CHROMESYNC_NODE_PATH=${shellQuote(path.join(root, 'node'))}\nexec ${shellQuote(path.join(root, 'node'))} ${shellQuote(path.join(appRoot, 'cli/index.js'))} "$@"\n`;
  fs.writeFileSync(path.join(root, 'launcher'), body, { mode: 0o700 });
  fs.chmodSync(path.join(root, 'launcher'), 0o700);
  replaceLink(path.join(root, 'launcher'), command);
  if (fs.existsSync(path.join(configHome(), 'native/launch.sh'))) registerExtension(configHome(), { appRoot, node: path.join(root, 'node') });
}

export function addToPath(bin, { home = os.homedir(), shell = process.env.SHELL || '', platform = process.platform } = {}) {
  if (!path.isAbsolute(bin) || /[\r\n\0]/.test(bin)) throw new Error('Invalid command directory');
  const shellName = path.basename(shell);
  let file;
  if (shellName === 'zsh') file = path.join(home, '.zshrc');
  else if (shellName === 'bash') file = path.join(home, platform === 'darwin' ? '.bash_profile' : '.bashrc');
  else { console.log(`Add ${bin} to your shell's PATH to use the chromesync command.`); return; }
  const old = fs.existsSync(file) ? fs.readFileSync(file, 'utf8') : '';
  const block = `# ChromeSync PATH begin\nexport PATH=${shellQuote(bin)}:"$PATH"\n# ChromeSync PATH end`;
  const next = old.includes('# ChromeSync PATH begin') ? old.replace(/# ChromeSync PATH begin[\s\S]*?# ChromeSync PATH end/, () => block) : `${old}\n${block}\n`;
  fs.writeFileSync(file, next, { mode: 0o600 });
  console.log(`PATH configured in ${file}; open a new terminal after setup.`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(fs.realpathSync(process.argv[1])).href) {
  try {
    const [, , action, ...args] = process.argv;
    if (action === 'activate') activate(...args);
    else if (action === 'path') addToPath(args[0]);
    else throw new Error('Unknown installer action');
  } catch (error) { console.error(`ChromeSync installer: ${error.message}`); process.exitCode = 1; }
}
