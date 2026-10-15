/**
 * Minimal schema-less protobuf encode/decode used by the gemini-web executor.
 *
 * Encoding takes a list of [fieldNumber, value] pairs:
 *   number            → varint
 *   string            → length-delimited UTF-8
 *   Uint8Array/Buffer → length-delimited bytes
 *   array of pairs    → nested message
 *   null/undefined    → skipped
 *
 * Decoding returns a tree of { fields: Map<number, Array<value>> } where a
 * length-delimited value is kept as { bytes, text, msg } so callers can pick
 * whichever interpretation applies.
 */

function varint(n) {
  const out = [];
  let v = BigInt(n);
  while (true) {
    const b = Number(v & 0x7fn);
    v >>= 7n;
    if (v > 0n) out.push(b | 0x80);
    else { out.push(b); break; }
  }
  return out;
}

export function encodeMessage(pairs) {
  const chunks = [];
  for (const [num, val] of pairs) {
    if (val === null || val === undefined) continue;
    if (typeof val === "number" || typeof val === "bigint" || typeof val === "boolean") {
      chunks.push(Uint8Array.from([...varint((num << 3) | 0), ...varint(Number(val))]));
      continue;
    }
    let payload;
    if (typeof val === "string") payload = new TextEncoder().encode(val);
    else if (val instanceof Uint8Array) payload = val;
    else if (Array.isArray(val)) payload = encodeMessage(val);
    else throw new TypeError(`Unsupported protobuf value for field ${num}`);
    chunks.push(Uint8Array.from([...varint((num << 3) | 2), ...varint(payload.length)]));
    chunks.push(payload);
  }
  const total = chunks.reduce((n, c) => n + c.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) { out.set(c, off); off += c.length; }
  return out;
}

const utf8 = new TextDecoder("utf-8", { fatal: true });

export function decodeMessage(bytes, depth = 0) {
  const fields = new Map();
  let i = 0;
  const readVarint = () => {
    let r = 0n; let s = 0n;
    while (true) {
      if (i >= bytes.length) throw new RangeError("truncated varint");
      const c = bytes[i++];
      r |= BigInt(c & 0x7f) << s; s += 7n;
      if (c < 0x80) return r;
    }
  };
  const push = (num, v) => { if (!fields.has(num)) fields.set(num, []); fields.get(num).push(v); };
  while (i < bytes.length) {
    const key = Number(readVarint());
    const num = key >>> 3; const wt = key & 7;
    if (wt === 0) push(num, Number(readVarint()));
    else if (wt === 2) {
      const len = Number(readVarint());
      if (i + len > bytes.length) throw new RangeError("truncated bytes");
      const sub = bytes.subarray(i, i + len); i += len;
      let text = null; let msg = null;
      try { text = utf8.decode(sub); } catch { text = null; }
      if (depth < 12 && sub.length > 0) {
        try { msg = decodeMessage(sub, depth + 1); } catch { msg = null; }
      }
      push(num, { bytes: sub, text, msg });
    } else if (wt === 1) { i += 8; push(num, null); }
    else if (wt === 5) { i += 4; push(num, null); }
    else throw new RangeError(`unsupported wire type ${wt}`);
  }
  return { fields };
}

/** Follow a path of field numbers through nested messages; returns the first match (value node) or undefined. */
export function pick(node, path) {
  let cur = node;
  for (let k = 0; k < path.length; k++) {
    if (!cur?.fields?.has(path[k])) return undefined;
    const v = cur.fields.get(path[k])[0];
    if (k === path.length - 1) return v;
    cur = v?.msg;
    if (!cur) return undefined;
  }
  return cur;
}

export function pickText(node, path) {
  const v = pick(node, path);
  return v && typeof v === "object" && typeof v.text === "string" ? v.text : null;
}

export function pickNumber(node, path) {
  const v = pick(node, path);
  return typeof v === "number" ? v : null;
}

export function toBase64(bytes) {
  return Buffer.from(bytes).toString("base64");
}

export function fromBase64(str) {
  return new Uint8Array(Buffer.from(str, "base64"));
}
