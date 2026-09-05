import { test } from 'node:test';
import assert from 'node:assert/strict';
import { CdpClient } from '../companion/cdp.js';

class FakeSocket extends EventTarget {
  sent = [];
  send(value) { this.sent.push(JSON.parse(value)); }
  close() { this.dispatchEvent(new Event('close')); }
}

test('CDP requests time out and connection closure rejects pending requests', async () => {
  const ws = new FakeSocket(), client = new CdpClient(ws);
  await assert.rejects(client.send('Storage.getCookies', {}, { timeoutMs: 10 }), /timed out/);
  const pending = client.send('Storage.getCookies');
  ws.close();
  await assert.rejects(pending, /closed/);
  await assert.rejects(client.send('Storage.getCookies'), /closed/);
});

test('CDP supports target sessions and never exposes response error payloads', async () => {
  const ws = new FakeSocket(), client = new CdpClient(ws);
  const pending = client.send('Network.deleteCookies', { name: 'test' }, { sessionId: 'session' });
  assert.equal(ws.sent[0].sessionId, 'session');
  const event = new Event('message');
  event.data = JSON.stringify({ id: 1, error: { message: 'synthetic-secret-must-not-leak' } });
  ws.dispatchEvent(event);
  await assert.rejects(pending, error => error.message === 'Chrome rejected the CDP operation');
  client.close();
});
