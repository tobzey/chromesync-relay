#!/usr/bin/env node
import fs from 'node:fs';
import net from 'node:net';
import { frameMessage, MessageDecoder } from './framing.js';

// Invoked only by a generated trusted wrapper. Never emits logs to stdout.
function argument(name) { const i = process.argv.indexOf(name); return i >= 0 ? process.argv[i + 1] : undefined; }
const socketPath = argument('--socket');
const tokenFile = argument('--token-file');
const extensionId = argument('--extension-id');
const caller = process.argv.find(value => value.startsWith('chrome-extension://'));
if (!socketPath || !tokenFile || !/^[a-p]{32}$/.test(extensionId ?? '') || caller !== `chrome-extension://${extensionId}/`) process.exit(1);
const tokenFd = fs.openSync(tokenFile, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
const tokenStat = fs.fstatSync(tokenFd);
if (!tokenStat.isFile() || (tokenStat.mode & 0o077) !== 0) process.exit(1);
const token = fs.readFileSync(tokenFd, 'utf8').trim();
fs.closeSync(tokenFd);
if (!/^[A-Za-z0-9_-]{32,128}$/.test(token)) process.exit(1);
const socket = net.createConnection(socketPath);
const fromChrome = new MessageDecoder();
const fromDaemon = new MessageDecoder();
let connected = false;
let queued;
const close = () => { socket.destroy(); process.exit(0); };
fromChrome.on('error', close); fromDaemon.on('error', close);
fromChrome.on('message', message => {
  if (connected) socket.write(frameMessage(message));
  else if (!queued) queued = message;
  else close();
});
fromDaemon.on('message', message => {
  if (!process.stdout.write(frameMessage(message))) socket.pause();
});
process.stdout.on('drain', () => socket.resume());
socket.on('connect', () => {
  connected = true;
  socket.write(frameMessage({ v: 1, type: 'native-hello', extensionId, token }));
  if (queued) { socket.write(frameMessage(queued)); queued = undefined; }
});
socket.on('data', chunk => fromDaemon.push(chunk));
socket.on('error', close); socket.on('close', close);
process.stdin.on('data', chunk => fromChrome.push(chunk));
process.stdin.on('end', close); process.stdout.on('error', close);
