#!/usr/bin/env python3
"""Deterministic stdlib archives: stable order, uid/gid, modes, timestamps; no compression variance."""
import gzip, hashlib, io, json, pathlib, sys, tarfile, zipfile
ROOT = pathlib.Path(__file__).resolve().parents[1]
out = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else ROOT / 'dist')
out.mkdir(parents=True, exist_ok=True)
# Select public source files without walking runtime/profile/deployment state.
# In particular, an ignored file is not automatically a safe release input.
source_groups = {
    'cli': {'.js'}, 'auth': {'.js', '.md'}, 'auth/browser': {'.js'},
    'auth/passkeys': {'.js', '.md'}, 'auth/passkeys/extension': {'.js'},
    'auth/ui': {'.js', '.html', '.css'},
    'companion': {'.js', '.sh', '.c', '.py'},
    'src': {'.js'}, 'src/sinks': {'.js'},
    'options': {'.js', '.html', '.css'}, 'popup': {'.js', '.html', '.css'},
    'server': {'.js'}, 'worker': {'.js'}, 'scripts': {'.js', '.mjs', '.py'},
}
files = [
    'auth/package.json', 'auth/package-lock.json', 'companion/io.chromesync.host.json',
    'server/README.md', 'server/Dockerfile', 'server/.dockerignore', 'worker/README.md',
    'deploy/alerts.wrangler.jsonc', 'deploy/r2-lifecycle.json', 'deploy/signed-commits.ruleset.json',
    'docs/agents.md', 'docs/install.md', 'docs/releasing.md', 'docs/relay-operations.md',
    'docs/authentication.md', 'docs/authentication-acceptance.md', 'docs/auth-browser.md',
    'manifest.json', 'package.json', 'package-lock.json', 'wrangler.jsonc',
    'LICENSE', 'SECURITY.md', 'CONTRIBUTING.md', 'README.md', 'install.sh',
]
for name, extensions in source_groups.items():
    directory = ROOT / name
    if directory.is_symlink(): raise ValueError('Symlinks are not allowed in release inputs')
    if not directory.is_dir(): continue
    for f in directory.iterdir():
        if f.name.startswith('.') or '.local.' in f.name or f.suffix not in extensions: continue
        files.append(f.relative_to(ROOT).as_posix())
selected = []
for name in files:
    f = ROOT / name
    if any(p.is_symlink() for p in (f, *f.parents) if p != ROOT and ROOT in p.parents):
        raise ValueError('Symlinks are not allowed in release inputs')
    if f.is_file(): selected.append(name)
files = selected
files = sorted(set(files))
tar_bytes = io.BytesIO()
with tarfile.open(fileobj=tar_bytes, mode='w', format=tarfile.USTAR_FORMAT) as tar:
    for name in files:
        data = (ROOT / name).read_bytes()
        info = tarfile.TarInfo('chromesync/' + name)
        info.size = len(data); info.mtime = 0; info.uid = info.gid = 0
        info.mode = 0o755 if name.endswith('.sh') or name == 'cli/index.js' else 0o644
        tar.addfile(info, io.BytesIO(data))
with (out / 'chromesync.tar.gz').open('wb') as dest:
    with gzip.GzipFile(fileobj=dest, filename='', mode='wb', compresslevel=0, mtime=0) as gz: gz.write(tar_bytes.getvalue())
with zipfile.ZipFile(out / 'chromesync-extension.zip', 'w', compression=zipfile.ZIP_STORED) as archive:
    for name in files:
        if name == 'manifest.json' or name.split('/')[0] in ['src', 'options', 'popup']:
            info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0)); info.create_system = 3
            info.external_attr = 0o100644 << 16
            archive.writestr(info, (ROOT / name).read_bytes())
(out / 'SHA256SUMS').write_text(''.join(hashlib.sha256((out / name).read_bytes()).hexdigest() + '  ' + name + '\n' for name in ['chromesync.tar.gz', 'chromesync-extension.zip']))
print(out)
