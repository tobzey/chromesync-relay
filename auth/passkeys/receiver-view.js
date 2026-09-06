import crypto from 'node:crypto';

export const ONEPASSWORD_EXTENSION_ID = 'aeblfdkhhhdcdjpifhhbdiojplfjncoa';
const MAX_IMAGE_BYTES = 80 * 1024;
const keys = Object.freeze({ Enter: 13, Tab: 9, Backspace: 8, Delete: 46, Escape: 27, ArrowLeft: 37, ArrowUp: 38, ArrowRight: 39, ArrowDown: 40, Home: 36, End: 35, PageUp: 33, PageDown: 34 });
const failure = code => Object.assign(new Error(code), { code });

function eligible(target, origin, extensionId) {
  if (target.type !== 'page') return undefined;
  try {
    const url = new URL(target.url);
    if (url.protocol === 'chrome-extension:' && url.host === extensionId && !url.username && !url.password) return 'provider';
    if (['https:', 'http:'].includes(url.protocol) && url.origin === origin && !url.username && !url.password) return 'service';
  } catch {}
  return undefined;
}

export function jpegDimensions(bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length < 4 || bytes[0] !== 255 || bytes[1] !== 216) throw failure('RECEIVER_IMAGE_INVALID');
  let offset = 2;
  while (offset + 4 <= bytes.length) {
    if (bytes[offset++] !== 255) throw failure('RECEIVER_IMAGE_INVALID');
    while (bytes[offset] === 255) offset++;
    const marker = bytes[offset++];
    if (marker === 217 || marker === 218) break;
    if (marker === 1 || (marker >= 208 && marker <= 215)) continue;
    if (offset + 2 > bytes.length) break;
    const size = bytes.readUInt16BE(offset);
    if (size < 2 || offset + size > bytes.length) break;
    if ([192, 193, 194, 195, 197, 198, 199, 201, 202, 203, 205, 206, 207].includes(marker)) {
      if (size < 8) break;
      const height = bytes.readUInt16BE(offset + 3), width = bytes.readUInt16BE(offset + 5);
      if (width < 1 || height < 1 || width > 4096 || height > 4096) break;
      return { width, height };
    }
    offset += size;
  }
  throw failure('RECEIVER_IMAGE_INVALID');
}

// getCeremony is supplied only by the trusted provider facade. The alternate
// provider ID is a test/infrastructure dependency; the facade always uses the
// fixed official 1Password ID and never accepts an ID from an owner or agent.
export function createReceiverView({ getCeremony, providerExtensionId = ONEPASSWORD_EXTENSION_ID }) {
  if (typeof getCeremony !== 'function' || !/^[a-p]{32}$/.test(providerExtensionId)) throw new Error('Invalid receiver view configuration');
  let busy = false;
  let lease;
  const handles = new Map();
  const detach = entry => {
    if (entry.onEvent) entry.connection.off?.('event', entry.onEvent);
    entry.connection.send('Target.detachFromTarget', { sessionId: entry.targetSession }).catch(() => {});
  };
  const reset = () => { for (const entry of handles.values()) detach(entry); lease = undefined; handles.clear(); };
  const guard = async (sessionId, expected) => {
    const current = await getCeremony(sessionId);
    if (!current || current.signal?.aborted || !current.connection || current.connection.closed || !current.id ||
        (expected && (current.id !== expected.id || current.connection !== expected.connection || current.origin !== expected.origin))) throw failure('RECEIVER_CEREMONY_INACTIVE');
    await current.assertCurrent();
    const again = await getCeremony(sessionId);
    if (!again || again.id !== current.id || again.connection !== current.connection || again.signal?.aborted) throw failure('RECEIVER_CEREMONY_INACTIVE');
    return current;
  };
  const operation = async (sessionId, fn) => {
    if (busy) throw failure('RECEIVER_BUSY');
    busy = true;
    try {
      const ceremony = await guard(sessionId);
      if (lease?.id !== ceremony.id || lease?.connection !== ceremony.connection) { reset(); lease = ceremony; }
      const timeout = AbortSignal.timeout(10000);
      const signal = ceremony.signal ? AbortSignal.any([ceremony.signal, timeout]) : timeout;
      const send = (method, params = {}, targetSession) => ceremony.connection.send(method, params, targetSession, { signal, timeoutMs: 3000 });
      return await fn({ ceremony, send, check: () => guard(sessionId, ceremony) });
    } finally { busy = false; }
  };
  const targets = async context => {
    const { targetInfos } = await context.send('Target.getTargets');
    const allowed = targetInfos.flatMap(info => {
      const kind = eligible(info, context.ceremony.origin, providerExtensionId);
      return kind ? [{ ...info, kind }] : [];
    });
    if (allowed.length > 8) throw failure('RECEIVER_TARGET_LIMIT');
    return allowed;
  };
  const frame = async (context, entry) => {
    const current = (await targets(context)).find(target => target.targetId === entry.targetId);
    if (!current || current.kind !== entry.kind) throw failure('RECEIVER_TARGET_CHANGED');
    const { frameTree } = await context.send('Page.getFrameTree', {}, entry.targetSession);
    const top = frameTree?.frame;
    if (!top?.loaderId || eligible({ type: 'page', url: top.url }, context.ceremony.origin, providerExtensionId) !== entry.kind) throw failure('RECEIVER_TARGET_CHANGED');
    return top;
  };
  const selected = async (context, targetHandle) => {
    const entry = handles.get(targetHandle);
    if (!entry || !entry.viewport || Date.now() - entry.observedAt > 30000) throw failure('RECEIVER_VIEW_STALE');
    const current = await frame(context, entry);
    if (current.id !== entry.frameId || current.loaderId !== entry.loaderId) throw failure('RECEIVER_TARGET_CHANGED');
    await context.check();
    return entry;
  };
  return Object.freeze({
    reset,
    receiverObserve(sessionId, { targetHandle } = {}) {
      return operation(sessionId, async context => {
        const allowed = await targets(context);
        for (const [handle, entry] of handles) if (!allowed.some(target => target.targetId === entry.targetId)) { detach(entry); handles.delete(handle); }
        for (const target of allowed) {
          if ([...handles.values()].some(entry => entry.targetId === target.targetId)) continue;
          const { sessionId: targetSession } = await context.send('Target.attachToTarget', { targetId: target.targetId, flatten: true });
          const entry = { targetId: target.targetId, targetSession, kind: target.kind, connection: context.ceremony.connection };
          const handle = crypto.randomUUID();
          try {
          await context.send('Page.enable', {}, targetSession);
          const initial = await frame(context, entry);
          entry.onEvent = event => {
            if (event.sessionId !== targetSession || event.method !== 'Fetch.requestPaused') return;
            // Block a target's top-level navigation outside its original
            // eligible origin while owner input is enabled. This closes the
            // check/input navigation race without reading page content.
            const params = event.params;
            const allowedNavigation = params.frameId !== initial.id || eligible({ type: 'page', url: params.request.url }, context.ceremony.origin, providerExtensionId) === entry.kind;
            context.ceremony.connection.send(allowedNavigation ? 'Fetch.continueRequest' : 'Fetch.failRequest', {
              requestId: params.requestId, ...(!allowedNavigation ? { errorReason: 'BlockedByClient' } : {}),
            }, targetSession, { timeoutMs: 3000 }).catch(() => {});
          };
          context.ceremony.connection.on?.('event', entry.onEvent);
          handles.set(handle, entry);
          await context.send('Fetch.enable', { patterns: [{ resourceType: 'Document', requestStage: 'Request' }] }, targetSession);
          } catch (error) { handles.delete(handle); detach(entry); throw error; }
        }
        const list = [...handles].map(([handle, entry]) => ({ handle, kind: entry.kind, label: entry.kind === 'provider' ? '1Password prompt' : 'Service page' }));
        const chosen = targetHandle ? list.find(target => target.handle === targetHandle) : list.find(target => target.kind === 'provider') ?? list[0];
        if (!chosen) throw failure(targetHandle ? 'RECEIVER_TARGET_NOT_FOUND' : 'RECEIVER_NO_PAGE_PROMPT');
        const entry = handles.get(chosen.handle);
        const before = await frame(context, entry);
        const metrics = await context.send('Page.getLayoutMetrics', {}, entry.targetSession);
        const viewport = metrics.cssVisualViewport ?? metrics.visualViewport;
        const width = viewport?.clientWidth, height = viewport?.clientHeight;
        if (!Number.isFinite(width) || !Number.isFinite(height) || width < 1 || height < 1 || width > 8192 || height > 8192) throw failure('RECEIVER_IMAGE_UNAVAILABLE');
        const initialScale = Math.min(1, 1024 / width, 768 / height);
        let image, dimensions;
        for (const scale of [initialScale, initialScale / 2]) {
          for (const quality of [45, 25, 10]) {
            await context.check();
            const captured = await context.send('Page.captureScreenshot', {
              format: 'jpeg', quality, fromSurface: true, captureBeyondViewport: false,
              clip: { x: viewport.pageX, y: viewport.pageY, width, height, scale },
            }, entry.targetSession);
            if (typeof captured.data !== 'string' || captured.data.length > 512 * 1024) continue;
            const bytes = Buffer.from(captured.data, 'base64');
            if (bytes.length > MAX_IMAGE_BYTES) continue;
            dimensions = jpegDimensions(bytes); image = captured.data; break;
          }
          if (image) break;
        }
        if (!image) throw failure('RECEIVER_IMAGE_TOO_LARGE');
        const after = await frame(context, entry);
        if (before.id !== after.id || before.loaderId !== after.loaderId) throw failure('RECEIVER_TARGET_CHANGED');
        await context.check();
        entry.viewport = { cssWidth: width, cssHeight: height, ...dimensions };
        entry.frameId = after.id; entry.loaderId = after.loaderId; entry.observedAt = Date.now();
        return { sessionId, targets: list, targetHandle: chosen.handle, ...dimensions, format: 'jpeg', image };
      });
    },
    receiverClick(sessionId, { targetHandle, x, y } = {}) {
      return operation(sessionId, async context => {
        const entry = await selected(context, targetHandle);
        if (!Number.isFinite(x) || !Number.isFinite(y) || x < 0 || y < 0 || x >= entry.viewport.width || y >= entry.viewport.height) throw failure('RECEIVER_COORDINATES_INVALID');
        const position = { x: x * entry.viewport.cssWidth / entry.viewport.width, y: y * entry.viewport.cssHeight / entry.viewport.height };
        await context.send('Input.dispatchMouseEvent', { type: 'mousePressed', ...position, button: 'left', clickCount: 1 }, entry.targetSession);
        await context.check();
        await context.send('Input.dispatchMouseEvent', { type: 'mouseReleased', ...position, button: 'left', clickCount: 1 }, entry.targetSession);
        return { status: 'ok' };
      });
    },
    receiverType(sessionId, { targetHandle, text } = {}) {
      return operation(sessionId, async context => {
        if (typeof text !== 'string' || text.length > 16384 || /[\u0000]/.test(text)) throw failure('RECEIVER_TEXT_INVALID');
        const entry = await selected(context, targetHandle);
        try { await context.send('Input.insertText', { text }, entry.targetSession); }
        finally { text = undefined; }
        return { status: 'ok' };
      });
    },
    receiverKey(sessionId, { targetHandle, key } = {}) {
      return operation(sessionId, async context => {
        if (!Object.hasOwn(keys, key)) throw failure('RECEIVER_KEY_INVALID');
        const entry = await selected(context, targetHandle);
        const event = { key, code: key, windowsVirtualKeyCode: keys[key] };
        await context.send('Input.dispatchKeyEvent', { type: 'keyDown', ...event, ...(key === 'Enter' ? { text: '\r' } : {}) }, entry.targetSession);
        await context.check();
        await context.send('Input.dispatchKeyEvent', { type: 'keyUp', ...event }, entry.targetSession);
        return { status: 'ok' };
      });
    },
  });
}
