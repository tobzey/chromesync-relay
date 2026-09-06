import fs from 'node:fs/promises';
import path from 'node:path';
import net from 'node:net';
import crypto from 'node:crypto';
import { EventEmitter } from 'node:events';
import { frameMessage, MessageDecoder } from './framing.js';
import { identifier, normalizeOrigin, validateRequest, validateAssertion, safeError, boundedTimeout } from './protocol.js';

const extensionId = value => typeof value === 'string' && /^[a-p]{32}$/.test(value);
const abortError = () => Object.assign(new Error('Passkey authentication canceled'), { name: 'AbortError' });

export async function createPasskeyHub({ socketPath, tokenFile, allowedExtensionIds = [] }) {
  if (!path.isAbsolute(socketPath) || !path.isAbsolute(tokenFile)) throw new Error('Absolute protected paths required');
  for (const directory of new Set([path.dirname(socketPath), path.dirname(tokenFile)])) {
    await fs.mkdir(directory, { recursive: true, mode: 0o700 });
    const stat = await fs.lstat(directory);
    if (!stat.isDirectory() || stat.isSymbolicLink() || (stat.mode & 0o077)) throw new Error('Passkey transport directory must be private');
  }
  let token;
  try {
    token = crypto.randomBytes(32).toString('base64url');
    await fs.writeFile(tokenFile, token, { mode: 0o600, flag: 'wx' });
  } catch (error) {
    if (error.code !== 'EEXIST') throw error;
    const stat = await fs.lstat(tokenFile);
    if (!stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o077)) throw new Error('Passkey token file must be private');
    token = (await fs.readFile(tokenFile, 'utf8')).trim();
  }
  if (!/^[A-Za-z0-9_-]{32,128}$/.test(token)) throw new Error('Invalid passkey transport token');
  const allowed = new Set(allowedExtensionIds);
  if ([...allowed].some(id => !extensionId(id))) throw new Error('Invalid extension ID');
  const sessions = new Map();
  const connections = new Set();
  const events = new EventEmitter();
  const safeSend = (peer, message) => {
    if (!peer || peer.socket.destroyed) return false;
    peer.socket.write(frameMessage(message));
    return true;
  };
  const envelope = (session, type, fields = {}) => ({ v: 1, sessionId: session.sessionId, type, ...fields });
  const finish = (session, error, result) => {
    const authorization = session.authorization;
    if (!authorization) return;
    session.authorization = undefined;
    clearTimeout(authorization.timer);
    authorization.signal?.removeEventListener('abort', authorization.abort);
    error ? authorization.reject(error) : authorization.resolve(result);
  };
  const cancel = (session, error = abortError()) => {
    const request = session.pending;
    session.pending = undefined;
    if (request) {
      clearTimeout(request.timer);
      safeSend(session.receiver, envelope(session, 'cancel', { id: request.value.id }));
      safeSend(session.sender, envelope(session, 'result', { id: request.value.id, error: safeError(error) }));
    }
    finish(session, error);
  };
  const dispatch = async session => {
    const pending = session.pending;
    const authorization = session.authorization;
    if (!pending || !authorization || pending.dispatched || pending.validating || !session.receiver?.ready) return;
    pending.validating = true;
    try {
      if (Date.now() >= session.expiresAt || Date.now() >= pending.value.expiresAt) throw new Error('Expired ceremony');
      if (await authorization.validateSession(pending.value) !== true) throw new Error('Browser lease rejected passkey request');
      if (session.pending !== pending || session.authorization !== authorization || authorization.signal?.aborted) return;
      pending.dispatched = true;
      if (!safeSend(session.receiver, pending.value)) throw new Error('Passkey receiver disconnected');
      events.emit('dispatched', { sessionId: session.sessionId, requestId: pending.value.id });
    } catch (error) { if (session.pending === pending) cancel(session, error); }
    finally { pending.validating = false; }
  };
  const handle = async (peer, message) => {
    if (message?.v !== 1) throw new Error('Invalid protocol version');
    if (!peer.authenticated) {
      if (message.type !== 'native-hello' || !allowed.has(message.extensionId) || typeof message.token !== 'string') throw new Error('Invalid native peer');
      const offered = Buffer.from(message.token);
      const expected = Buffer.from(token);
      if (offered.length !== expected.length || !crypto.timingSafeEqual(offered, expected)) throw new Error('Invalid native peer');
      peer.authenticated = true; peer.extensionId = message.extensionId;
      return;
    }
    if (!peer.session) {
      if (message.type !== 'hello' || !['sender', 'receiver'].includes(message.role)) throw new Error('Invalid extension hello');
      const session = sessions.get(message.sessionId);
      if (!session || session.expiresAt <= Date.now() || message.origin !== session.origin || peer.extensionId !== session[`${message.role}ExtensionId`] || session[message.role]) throw new Error('Unregistered passkey session');
      peer.session = session; peer.role = message.role; session[peer.role] = peer;
      clearTimeout(peer.handshakeTimer);
      safeSend(peer, envelope(session, 'bind', { origin: session.origin, expiresAt: session.expiresAt }));
      return;
    }
    const session = peer.session;
    if (message.sessionId !== session.sessionId || sessions.get(session.sessionId) !== session || session.expiresAt <= Date.now()) throw new Error('Expired passkey session');
    if (message.type === 'ready' && message.role === peer.role) {
      peer.ready = true;
      events.emit('ready', { sessionId: session.sessionId, role: peer.role });
      await dispatch(session); return;
    }
    if (message.type === 'unavailable') { cancel(session, new Error('Browser passkey proxy unavailable')); return; }
    if (peer.role === 'sender') {
      if (message.type === 'capability') {
        identifier(message.id);
        if (session.receiver?.ready) safeSend(session.receiver, envelope(session, 'capability', { id: message.id }));
        else safeSend(peer, envelope(session, 'capability-result', { id: message.id, available: false }));
        return;
      }
      if (message.type === 'cancel') { if (session.pending?.value.id === message.id) cancel(session); return; }
      if (message.type !== 'get' || !peer.ready) throw new Error('Invalid sender message');
      const request = validateRequest(message, session);
      for (const [id, expiresAt] of session.seen) if (expiresAt <= Date.now()) session.seen.delete(id);
      if (request.expiresAt > session.expiresAt || session.pending || session.seen.has(request.id)) throw new Error('Conflicting passkey request');
      session.seen.set(request.id, request.expiresAt);
      if (session.seen.size > 64) throw new Error('Passkey session request limit reached');
      session.pending = { value: request, dispatched: false, timer: setTimeout(() => cancel(session, new Error('Passkey request expired')), request.expiresAt - Date.now()) };
      events.emit('request', { sessionId: session.sessionId, requestId: request.id, origin: request.origin, rpId: request.publicKey.rpId });
      await dispatch(session); return;
    }
    if (message.type === 'capability-result') {
      identifier(message.id);
      safeSend(session.sender, envelope(session, 'capability-result', { id: message.id, available: message.available === true })); return;
    }
    if (message.type !== 'result') throw new Error('Invalid receiver message');
    const pending = session.pending;
    const authorization = session.authorization;
    if (!pending || !pending.dispatched || pending.value.id !== message.id || !authorization) return;
    if (pending.completing) return;
    pending.completing = true;
    try {
      if (Date.now() >= pending.value.expiresAt) throw new Error('Expired ceremony');
      if (message.error) throw Object.assign(new Error('Passkey provider declined request'), safeError(message.error));
      const assertion = await validateAssertion(message.assertion, pending.value);
      if (await authorization.validateSession(pending.value) !== true) throw new Error('Browser lease changed');
      if (session.pending !== pending || session.authorization !== authorization || authorization.signal?.aborted) return;
      if (!safeSend(session.sender, envelope(session, 'result', { id: pending.value.id, assertion }))) throw new Error('Passkey sender disconnected');
      clearTimeout(pending.timer); session.pending = undefined;
      // Assertion completion is not proof that the RP accepted it. Caller checks its page.
      finish(session, undefined, { completed: true, method: 'passkey' });
    } catch (error) { if (session.pending === pending) cancel(session, error); }
  };
  const server = net.createServer(socket => {
    if (connections.size >= 128) { socket.destroy(); return; }
    const peer = { socket, authenticated: false };
    connections.add(peer);
    peer.handshakeTimer = setTimeout(() => socket.destroy(), 5000);
    const decoder = new MessageDecoder();
    let sequence = Promise.resolve();
    decoder.on('message', message => { sequence = sequence.then(() => handle(peer, message)).catch(() => socket.destroy()); });
    decoder.on('error', () => socket.destroy());
    socket.on('data', chunk => decoder.push(chunk));
    socket.on('error', () => socket.destroy());
    socket.on('close', () => {
      clearTimeout(peer.handshakeTimer); connections.delete(peer);
      const session = peer.session;
      if (session?.[peer.role] === peer) {
        session[peer.role] = undefined;
        cancel(session, new Error('Passkey browser disconnected'));
        events.emit('disconnected', { sessionId: session.sessionId, role: peer.role });
      }
    });
  });
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(socketPath, resolve); });
  await fs.chmod(socketPath, 0o600);
  return Object.assign(events, {
    registerSession(config) {
      identifier(config.sessionId); normalizeOrigin(config.origin);
      const lifetime = config.lifetime ?? 'deadline';
      // A trusted managed browser may remain alive across host sleeps. Its
      // native disconnect ends this binding; each ceremony still expires.
      const expiresAt = lifetime === 'connection' ? Number.MAX_SAFE_INTEGER : config.expiresAt;
      if (!['deadline', 'connection'].includes(lifetime) || sessions.has(config.sessionId) || sessions.size >= 64 || !Number.isSafeInteger(expiresAt) || expiresAt <= Date.now() || (lifetime === 'deadline' && expiresAt - Date.now() > 3600000) || !extensionId(config.senderExtensionId) || !extensionId(config.receiverExtensionId) || config.senderExtensionId === config.receiverExtensionId) throw new Error('Invalid passkey session registration');
      allowed.add(config.senderExtensionId); allowed.add(config.receiverExtensionId);
      const session = { sessionId: config.sessionId, origin: config.origin, senderExtensionId: config.senderExtensionId, receiverExtensionId: config.receiverExtensionId, expiresAt, lifetime, seen: new Map() };
      if (lifetime === 'deadline') session.timer = setTimeout(() => this.unregisterSession(config.sessionId), expiresAt - Date.now());
      sessions.set(config.sessionId, session);
    },
    status(sessionId) {
      const session = sessions.get(sessionId);
      return session ? { senderReady: !!session.sender?.ready, receiverReady: !!session.receiver?.ready, pending: !!session.pending,
        authenticating: !!session.pending?.dispatched && !!session.authorization } : null;
    },
    authenticate(sessionId, { signal, timeoutMs = 120000, validateSession } = {}) {
      const session = sessions.get(sessionId);
      if (!session || session.authorization || typeof validateSession !== 'function') return Promise.reject(new Error('A registered session and browser lease validator are required'));
      if (signal?.aborted) return Promise.reject(abortError());
      return new Promise((resolve, reject) => {
        const abort = () => cancel(session, abortError());
        session.authorization = { resolve, reject, signal, abort, validateSession, timer: setTimeout(() => cancel(session, new Error('Passkey authentication timed out')), boundedTimeout(timeoutMs, session.expiresAt - Date.now())) };
        signal?.addEventListener('abort', abort, { once: true });
        dispatch(session);
      });
    },
    cancel(sessionId) { const session = sessions.get(sessionId); if (session) cancel(session); },
    unregisterSession(sessionId) {
      const session = sessions.get(sessionId); if (!session) return;
      sessions.delete(sessionId); clearTimeout(session.timer); cancel(session);
      session.sender?.socket.destroy(); session.receiver?.socket.destroy();
    },
    async close() {
      for (const sessionId of [...sessions.keys()]) this.unregisterSession(sessionId);
      for (const peer of connections) peer.socket.destroy();
      await new Promise(resolve => server.close(resolve));
    },
  });
}
