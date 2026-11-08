// Reads Kiln's `.skln` container, the vault file the app now writes (core/src/skln.rs, Kiln's
// docs/FORMAT.md "The .skln container"), for a bundle (kind 1) under a raw 32-byte key. Opening only:
// the extension never writes a vault.
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
import { chacha20Poly1305Open } from './chacha.js';

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
const FILE_KEY_INFO = new TextEncoder().encode('kiln skln v1 file key');

export class SklnError extends Error {
  constructor(code) {
    super(code === 'not-skln' ? 'This is not a .skln file.' : 'The vault file is damaged.');
    this.code = code; // 'not-skln' | 'corrupt'
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
