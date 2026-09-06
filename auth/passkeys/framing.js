import { EventEmitter } from 'node:events';
import { endianness } from 'node:os';
import { MAX_MESSAGE_BYTES } from './protocol.js';

const littleEndian = endianness() === 'LE';
export function frameMessage(message) {
  const body = Buffer.from(JSON.stringify(message), 'utf8');
  if (!body.length || body.length > MAX_MESSAGE_BYTES) throw new Error('Native message exceeds limit');
  const length = Buffer.alloc(4);
  littleEndian ? length.writeUInt32LE(body.length) : length.writeUInt32BE(body.length);
  return Buffer.concat([length, body]);
}

export class MessageDecoder extends EventEmitter {
  #buffer = Buffer.alloc(0);
  #closed = false;
  push(chunk) {
    if (this.#closed) return;
    this.#buffer = Buffer.concat([this.#buffer, chunk]);
    try {
      while (this.#buffer.length >= 4) {
        const length = littleEndian ? this.#buffer.readUInt32LE() : this.#buffer.readUInt32BE();
        if (!length || length > MAX_MESSAGE_BYTES) throw new Error('Invalid native frame length');
        if (this.#buffer.length < length + 4) return;
        const text = new TextDecoder('utf-8', { fatal: true }).decode(this.#buffer.subarray(4, 4 + length));
        const message = JSON.parse(text);
        this.#buffer = this.#buffer.subarray(length + 4);
        if (!message || typeof message !== 'object' || Array.isArray(message)) throw new Error('Invalid native message');
        this.emit('message', message);
      }
    } catch (error) { this.#closed = true; this.#buffer = Buffer.alloc(0); this.emit('error', error); }
  }
}
