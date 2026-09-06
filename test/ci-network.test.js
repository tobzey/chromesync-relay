import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const script = fileURLToPath(new URL('../.github/scripts/isolate-test-network.sh', import.meta.url));

function fixture(t, platform) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'chromesync-ci-network-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const bin = path.join(directory, 'bin'), state = path.join(directory, 'state');
  fs.mkdirSync(bin); fs.mkdirSync(state);
  const log = path.join(directory, 'calls');
  const mocks = {
    uname: '#!/bin/sh\nprintf "%s\\n" "$CI_NETWORK_TEST_PLATFORM"\n',
    sudo: '#!/bin/sh\n[ "$1" = -n ] || exit 97\nshift\nexec "$@"\n',
    sysctl: `#!/bin/sh
printf '%s\\n' "$*" >> "$CI_NETWORK_TEST_LOG"
case "$1" in
  -w)
    shift
    for setting do
      key=\${setting%%=*}
      value=\${setting#*=}
      case "$key" in
        net.ipv4.ip_local_port_range|net.inet.ip.portrange.first|net.inet.ip.portrange.last|net.inet.ip.portrange.hifirst|net.inet.ip.portrange.hilast) ;;
        *) exit 98 ;;
      esac
      printf '%s\\n' "$value" > "$CI_NETWORK_TEST_STATE/$key"
    done
    ;;
  -n)
    if [ "$2" = "$CI_NETWORK_TEST_MISMATCH" ]; then printf '49152\\n'; else cat "$CI_NETWORK_TEST_STATE/$2"; fi
    ;;
  *) exit 99 ;;
esac
`,
  };
  for (const [name, body] of Object.entries(mocks)) fs.writeFileSync(path.join(bin, name), body, { mode: 0o700 });
  return {
    state,
    calls: () => fs.existsSync(log) ? fs.readFileSync(log, 'utf8').trim().split('\n') : [],
    run: (overrides = {}) => spawnSync('/bin/sh', [script], {
      env: { ...process.env, PATH: `${bin}:/usr/bin:/bin`, GITHUB_ACTIONS: 'true', RUNNER_ENVIRONMENT: 'github-hosted',
        CI_NETWORK_TEST_PLATFORM: platform, CI_NETWORK_TEST_LOG: log, CI_NETWORK_TEST_STATE: state,
        CI_NETWORK_TEST_MISMATCH: '', ...overrides }, encoding: 'utf8', timeout: 5000,
    }),
  };
}

test('CI network setup refuses local and self-hosted machines before invoking sysctl', t => {
  const f = fixture(t, 'Darwin');
  for (const environment of [{ GITHUB_ACTIONS: '' }, { RUNNER_ENVIRONMENT: 'self-hosted' }]) {
    const result = f.run(environment);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /only for temporary GitHub-hosted/);
  }
  assert.deepEqual(f.calls(), []);
});

test('Linux CI separates automatic ports without replacing reserved-port policies', t => {
  const f = fixture(t, 'Linux');
  const reserved = path.join(f.state, 'net.ipv4.ip_local_reserved_ports');
  fs.writeFileSync(reserved, '60100,62000-62100\n');
  const result = f.run();
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(f.calls(), ['-w net.ipv4.ip_local_port_range=60000 65535', '-n net.ipv4.ip_local_port_range']);
  assert.equal(fs.readFileSync(reserved, 'utf8'), '60100,62000-62100\n');
});

test('macOS CI sets and verifies both ordinary and high automatic port ranges', t => {
  const f = fixture(t, 'Darwin');
  const result = f.run();
  assert.equal(result.status, 0, result.stderr);
  for (const [key, value] of [['first', '60000'], ['last', '65535'], ['hifirst', '60000'], ['hilast', '65535']]) {
    assert.equal(fs.readFileSync(path.join(f.state, `net.inet.ip.portrange.${key}`), 'utf8').trim(), value);
    assert.ok(f.calls().includes(`-n net.inet.ip.portrange.${key}`));
  }
  assert.equal(f.calls().filter(call => call.startsWith('-w ')).length, 1);
});

test('CI network setup fails if either platform does not apply the required range', t => {
  for (const [platform, mismatch] of [['Linux', 'net.ipv4.ip_local_port_range'], ['Darwin', 'net.inet.ip.portrange.hifirst']]) {
    const f = fixture(t, platform);
    const result = f.run({ CI_NETWORK_TEST_MISMATCH: mismatch });
    assert.equal(result.status, 1);
    assert.match(result.stderr, /could not be verified/);
  }
});
