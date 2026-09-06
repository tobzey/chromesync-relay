import { createHmac, randomBytes } from 'node:crypto';

// Keep salted fingerprints, not plaintext credentials, after the fill finishes.
// This catches exact credential echoes, not arbitrary encodings by a hostile site.
export function createCredentialRedactor() {
  const salt = randomBytes(32);
  const entries = new Map();
  const digest = value => createHmac('sha256',salt).update(value).digest('hex');
  function remember(value) {
    if (typeof value !== 'string' || !value.length) return;
    let set = entries.get(value.length);
    if (!set) entries.set(value.length,set = new Set());
    set.add(digest(value));
  }
  function redactText(value) {
    const ranges = [];
    for (const [length,digests] of entries) {
      for (let i=0; i<=value.length-length; i++) if (digests.has(digest(value.slice(i,i+length)))) ranges.push([i,i+length]);
    }
    if (!ranges.length) return value;
    ranges.sort((a,b) => a[0]-b[0]);
    const merged = [];
    for (const range of ranges) {
      const last = merged.at(-1);
      if (last && range[0] <= last[1]) last[1] = Math.max(last[1],range[1]);
      else merged.push(range);
    }
    let text = '',cursor = 0;
    for (const [start,end] of merged) { text += value.slice(cursor,start)+'[redacted]'; cursor=end; }
    return text+value.slice(cursor);
  }
  function redact(value) {
    if (typeof value === 'string') return redactText(value);
    if (Array.isArray(value)) return value.map(redact);
    if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([key,item]) => [key,redact(item)]));
    return value;
  }
  return {remember,redact,clear(){entries.clear();salt.fill(0);}};
}
