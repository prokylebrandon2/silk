// Reads and writes Kiln's `.skln` container, the vault file the app writes (core/src/skln.rs, Kiln's
// docs/FORMAT.md "The .skln container"), for a bundle (kind 1) under a raw 32-byte key. Writing
// follows Kiln's `seal_with` and `bundle::pack` exactly, so the app opens what the extension saves.
//
//   header  magic[8] "\x89SKLN\r\n\x1a" | version u8 (1) | flags u8 | kind u8 | chunk_log2 u8 |
//           revision u64 | salt[16]                                     (36 bytes, little-endian)
//           flags bit 0 adds a 26-byte password block after the salt; Silk never sets it
//   body    records: len u32 | ChaCha20-Poly1305(ciphertext + tag[16]); every record but the last
//           holds exactly 2^chunk_log2 bytes of plaintext
//   key     HKDF-SHA256(ikm = the VEK, salt = header salt, info = "kiln skln v1 file key") -> 32 bytes
//   nonce   4 zero bytes | record index u64 (little-endian)
//   aad     the whole header, then one byte: 1 for the last record, else 0
//   bundle  count u32 | { name_len u16 | name | data_len u32 | data }*    (little-endian)
//
// Every length is checked against what is left of the file before it is used.
import { chacha20Poly1305Open, chacha20Poly1305Seal } from './chacha.js';

export const MAGIC_SKLN = [0x89, 0x53, 0x4b, 0x4c, 0x4e, 0x0d, 0x0a, 0x1a];
export const KIND_BUNDLE = 1;

const HEADER_LEN = 36;
const PASSWORD_BLOCK_LEN = 26;
const TAG_LEN = 16;
const MIN_CHUNK_LOG2 = 12;
const MAX_CHUNK_LOG2 = 24;
const MAX_MEMBERS = 1024;
const MAX_NAME_LEN = 255;
const MAX_BUNDLE_LEN = 64 * 1024 * 1024;
const DEFAULT_CHUNK_LOG2 = 20; // Kiln's default: records of 1 MiB
const FILE_KEY_INFO = new TextEncoder().encode('kiln skln v1 file key');

export class SklnError extends Error {
  constructor(code) {
    super(
      code === 'not-skln' ? 'This is not a .skln file.' : code === 'too-large' ? 'This vault is too large to save from the extension.' : 'The vault file is damaged.',
    );
    this.code = code; // 'not-skln' | 'corrupt' | 'too-large'
  }
}

export const isSkln = (f) => f.length >= MAGIC_SKLN.length && MAGIC_SKLN.every((b, i) => f[i] === b);

/** Reads the plain header. Nothing here is trusted until a record decrypts, which authenticates it. */
export function parseSkln(f) {
  if (!isSkln(f) || f.length < HEADER_LEN) throw new SklnError('not-skln');
  if (f[8] !== 1) throw new SklnError('not-skln');
  const flags = f[9];
  const chunkLog2 = f[11];
  if ((flags & ~1) !== 0 || chunkLog2 < MIN_CHUNK_LOG2 || chunkLog2 > MAX_CHUNK_LOG2) throw new SklnError('corrupt');
  const headerLen = HEADER_LEN + (flags & 1 ? PASSWORD_BLOCK_LEN : 0);
  if (f.length < headerLen) throw new SklnError('corrupt');
  const dv = new DataView(f.buffer, f.byteOffset, f.byteLength);
  return {
    kind: f[10],
    chunkLog2,
    revision: dv.getBigUint64(12, true),
    salt: f.subarray(20, 36),
    headerLen,
  };
}

async function fileKey(vek, salt) {
  const ikm = await crypto.subtle.importKey('raw', vek, 'HKDF', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info: FILE_KEY_INFO }, ikm, 256));
}

/** Decrypts every record. Returns { kind, revision (BigInt), plaintext }. Throws SklnError. */
export async function openSkln(vek, f) {
  const h = parseSkln(f);
  const key = await fileKey(vek, h.salt);
  const header = f.subarray(0, h.headerLen);
  const full = 2 ** h.chunkLog2 + TAG_LEN;
  const dv = new DataView(f.buffer, f.byteOffset, f.byteLength);
  const parts = [];
  let total = 0;
  let pos = h.headerLen;
  try {
    for (let index = 0; ; index++) {
      if (f.length - pos < 4) throw new SklnError('corrupt');
      const n = dv.getUint32(pos, true);
      const end = pos + 4 + n;
      if (end > f.length) throw new SklnError('corrupt');
      const last = end === f.length;
      if (last ? n < TAG_LEN || n > full : n !== full) throw new SklnError('corrupt');
      total += n - TAG_LEN;
      if (total > MAX_BUNDLE_LEN) throw new SklnError('corrupt');
      const nonce = new Uint8Array(12);
      new DataView(nonce.buffer).setBigUint64(4, BigInt(index), true);
      const aad = new Uint8Array(header.length + 1);
      aad.set(header, 0);
      aad[header.length] = last ? 1 : 0;
      parts.push(chacha20Poly1305Open(key, nonce, aad, f.subarray(pos + 4, end)));
      if (last) break;
      pos = end;
    }
  } catch (e) {
    for (const p of parts) p.fill(0);
    throw e instanceof SklnError ? e : new SklnError('corrupt'); // a tag mismatch
  } finally {
    key.fill(0);
  }
  const plaintext = new Uint8Array(total);
  let at = 0;
  for (const p of parts) {
    plaintext.set(p, at);
    at += p.length;
    p.fill(0);
  }
  return { kind: h.kind, revision: h.revision, plaintext };
}

const nameOk = (name) =>
  name.length > 0 && name !== '.' && name !== '..' && !/[/\\\u0000-\u001f\u007f-\u009f]/u.test(name);

/** Reads the little-endian member bundle (kind 1) into a Map of name -> bytes. */
export function unpackBundle(buf) {
  const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const bad = () => new SklnError('corrupt');
  let pos = 0;
  const need = (n) => {
    if (n > buf.length - pos) throw bad();
  };
  need(4);
  const count = dv.getUint32(pos, true);
  pos += 4;
  if (count > MAX_MEMBERS) throw bad();
  const members = new Map();
  for (let i = 0; i < count; i++) {
    need(2);
    const nameLen = dv.getUint16(pos, true);
    pos += 2;
    if (nameLen > MAX_NAME_LEN) throw bad();
    need(nameLen);
    let name;
    try {
      name = new TextDecoder('utf-8', { fatal: true }).decode(buf.subarray(pos, pos + nameLen));
    } catch {
      throw bad();
    }
    pos += nameLen;
    if (!nameOk(name) || members.has(name)) throw bad();
    need(4);
    const dataLen = dv.getUint32(pos, true);
    pos += 4;
    need(dataLen);
    members.set(name, buf.subarray(pos, pos + dataLen));
    pos += dataLen;
  }
  if (pos !== buf.length) throw bad();
  return members;
}

/** Encodes a Map of name -> bytes as the little-endian member bundle (kind 1), the inverse of unpackBundle. */
export function packBundle(members) {
  if (members.size > MAX_MEMBERS) throw new SklnError('too-large');
  const enc = new TextEncoder();
  const named = [];
  let total = 4;
  for (const [name, data] of members) {
    const bytes = enc.encode(name);
    if (!nameOk(name) || bytes.length > MAX_NAME_LEN) throw new SklnError('corrupt');
    named.push([bytes, data]);
    total += 2 + bytes.length + 4 + data.length;
  }
  if (total > MAX_BUNDLE_LEN) throw new SklnError('too-large');
  const out = new Uint8Array(total);
  const dv = new DataView(out.buffer);
  dv.setUint32(0, named.length, true);
  let pos = 4;
  for (const [bytes, data] of named) {
    dv.setUint16(pos, bytes.length, true);
    pos += 2;
    out.set(bytes, pos);
    pos += bytes.length;
    dv.setUint32(pos, data.length, true);
    pos += 4;
    out.set(data, pos);
    pos += data.length;
  }
  return out;
}

/**
 * Seals a bundle payload as a kind-1 `.skln` under the VEK, with `revision` in the plain header.
 * Every call draws a new file salt, so a key and nonce pair never repeats across saves.
 */
export async function sealSkln(vek, revision, plaintext, chunkLog2 = DEFAULT_CHUNK_LOG2) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const header = new Uint8Array(HEADER_LEN);
  header.set(MAGIC_SKLN, 0);
  header[8] = 1; // version
  header[9] = 0; // flags: no password block
  header[10] = KIND_BUNDLE;
  header[11] = chunkLog2;
  new DataView(header.buffer).setBigUint64(12, BigInt(revision), true);
  header.set(salt, 20);
  const key = await fileKey(vek, salt);
  const chunk = 2 ** chunkLog2;
  const count = Math.max(1, Math.ceil(plaintext.length / chunk)); // an empty payload still has a last record
  const records = [];
  let size = header.length;
  try {
    for (let index = 0; index < count; index++) {
      const nonce = new Uint8Array(12);
      new DataView(nonce.buffer).setBigUint64(4, BigInt(index), true);
      const aad = new Uint8Array(header.length + 1);
      aad.set(header, 0);
      aad[header.length] = index === count - 1 ? 1 : 0;
      const sealed = chacha20Poly1305Seal(key, nonce, aad, plaintext.subarray(index * chunk, (index + 1) * chunk));
      records.push(sealed);
      size += 4 + sealed.length;
    }
  } finally {
    key.fill(0);
  }
  const out = new Uint8Array(size);
  out.set(header, 0);
  const dv = new DataView(out.buffer);
  let pos = header.length;
  for (const record of records) {
    dv.setUint32(pos, record.length, true);
    pos += 4;
    out.set(record, pos);
    pos += record.length;
  }
  return out;
}

