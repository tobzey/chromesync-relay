// In-memory R2Bucket subset used by worker/store.js. Named so the
// test/*.test.js glob does not pick this file up as a test.

function toBytes(value) {
  if (value instanceof Uint8Array) return new Uint8Array(value);
  if (value instanceof ArrayBuffer) return new Uint8Array(value.slice(0));
  if (ArrayBuffer.isView(value)) {
    return new Uint8Array(value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength));
  }
  if (typeof value === "string") return new TextEncoder().encode(value);
  throw new TypeError("unsupported R2 put value");
}

function viewOf(obj) {
  return {
    size: obj.bytes.byteLength,
    uploaded: obj.uploaded,
    customMetadata: { ...obj.customMetadata },
  };
}

export class MemoryR2Bucket {
  constructor() {
    /** @type {Map<string, { bytes: Uint8Array, uploaded: Date, customMetadata: Record<string, string> }>} */
    this.objects = new Map();
  }

  async put(key, value, opts = {}) {
    const bytes = toBytes(value);
    const customMetadata = opts.customMetadata ? { ...opts.customMetadata } : {};
    this.objects.set(key, { bytes, uploaded: new Date(), customMetadata });
    return { key, ...viewOf(this.objects.get(key)) };
  }

  async get(key) {
    const obj = this.objects.get(key);
    if (!obj) return null;
    const copy = new Uint8Array(obj.bytes);
    return {
      key,
      ...viewOf(obj),
      arrayBuffer: async () => copy.buffer.slice(copy.byteOffset, copy.byteOffset + copy.byteLength),
    };
  }

  async head(key) {
    const obj = this.objects.get(key);
    if (!obj) return null;
    return { key, ...viewOf(obj) };
  }

  async delete(key) {
    this.objects.delete(key);
  }

  async list({ prefix = "", limit = 1000, cursor, include } = {}) {
    const keys = [...this.objects.keys()].filter((k) => k.startsWith(prefix)).sort();
    const start = cursor ? Number(cursor) || 0 : 0;
    const pageLimit = Number(limit);
    const size = Number.isFinite(pageLimit) && pageLimit > 0 ? Math.trunc(pageLimit) : 1000;
    const sliced = keys.slice(start, start + size);
    const truncated = start + sliced.length < keys.length;
    const withMeta = Array.isArray(include) && include.includes("customMetadata");
    return {
      objects: sliced.map((k) => {
        const obj = this.objects.get(k);
        const { size: objSize, uploaded, customMetadata } = viewOf(obj);
        const listed = { key: k, size: objSize, uploaded };
        if (withMeta) listed.customMetadata = customMetadata;
        return listed;
      }),
      truncated,
      cursor: truncated ? String(start + sliced.length) : undefined,
    };
  }
}
