import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { runAuthCli } from '../auth/cli.js';
import { initializeAuth, authHome } from '../auth/config.js';

async function capture(work) {
  const lines = [], errors = [], log = console.log, error = console.error, exit = process.exitCode;
  console.log = value => lines.push(value); console.error = value => errors.push(value);
  try { await work(); return { lines, errors, exitCode: process.exitCode }; }
  finally { console.log = log; console.error = error; process.exitCode = exit; }
}

test('runAuthCli help and operator errors retain the top-level error boundary', async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'chromesync-cli-errors-'));
  const old = process.env.CHROMESYNC_HOME; process.env.CHROMESYNC_HOME = root;
  t.after(async () => { if (old === undefined) delete process.env.CHROMESYNC_HOME; else process.env.CHROMESYNC_HOME = old; await fs.rm(root, { recursive: true, force: true }); });
  const result = await capture(() => runAuthCli(['--help']));
  assert.match(result.lines[0], /--port PORT/);
  for (const [args, role, pattern] of [[['wait'], 'agent', /Provide --request/], [['wait', '--request', 'synthetic'], 'approver', /agent identity/], [['approvals', '--port', 'bad'], 'approver', /Invalid inbox port/], [['--not-an-option'], 'agent', /Unknown option/], [['init', '--role', 'bad'], 'agent', /role/i]]) {
    const output = await capture(async () => { await assert.rejects(runAuthCli(args, { remoteFactory: () => ({ role }) }), pattern); });
    assert.deepEqual(output.lines, []);
  }
});

test('runAuthCli wires wait, requests and decide to the injected remote', async () => {
  const calls = [];
  const remoteFactory = role => () => ({ role, async call(...args) { calls.push(args); return { status: 'succeeded' }; } });
  await capture(async () => {
    await runAuthCli(['wait', '--request', 'synthetic', '--timeout', '30'], { remoteFactory: remoteFactory('agent') });
    await runAuthCli(['requests', '--cursor', 'page-two'], { remoteFactory: remoteFactory('approver') });
    await runAuthCli(['decide', '--request', 'synthetic', '--decision', 'once', '--factors', 'password,totp'], { remoteFactory: remoteFactory('approver') });
  });
  assert.deepEqual(calls[0].slice(0, 2), ['auth.status', { requestId: 'synthetic' }]); assert.equal(calls[0][2].timeoutMs, 30000);
  assert.deepEqual(calls[1].slice(0, 2), ['requests', { cursor: 'page-two' }]);
  assert.deepEqual(calls[2].slice(0, 2), ['request.decide', { requestId: 'synthetic', decision: 'once', factors: ['password', 'totp'] }]);
});

test('runAuthCli emits only relay rejection codes and propagates unrelated codes', async () => {
  for (const code of ['SESSION_CLOSED', 'SECRET_SENTINEL']) {
    const result = await capture(() => runAuthCli(['status'], { remoteFactory: () => ({ role: 'agent', call() { throw Object.assign(new Error('private'), { code, operationRejected: true }); } }) }));
    assert.deepEqual(JSON.parse(result.lines[0]), { status: 'failed', reason: code === 'SESSION_CLOSED' ? code : 'OPERATION_REJECTED' }); assert.equal(result.exitCode, 1);
  }
  await capture(async () => { await assert.rejects(runAuthCli(['status'], { remoteFactory: () => { throw Object.assign(new Error('private'), { code: 'ENOENT' }); } }), { code: 'ENOENT' }); });
});

test('runAuthCli announces saved-port fallback and closes the inbox', async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'chromesync-cli-review-'));
  const old = process.env.CHROMESYNC_HOME; process.env.CHROMESYNC_HOME = root;
  t.after(async () => { if (old === undefined) delete process.env.CHROMESYNC_HOME; else process.env.CHROMESYNC_HOME = old; await fs.rm(root, { recursive: true, force: true }); });
  await initializeAuth(authHome(), 'approver'); let closed = false;
  const result = await capture(() => runAuthCli(['approvals'], { remoteFactory: () => ({ role: 'approver' }),
    inboxFactory: async () => ({ url: 'http://127.0.0.1:12345', portFallback: true, close: async () => { closed = true; } }),
    sleep: async () => { process.emit('SIGINT'); } }));
  assert.equal(JSON.parse(result.lines[0]).portFallback, true); assert.match(result.errors[0], /Saved inbox port is busy/); assert.equal(closed, true);
});
