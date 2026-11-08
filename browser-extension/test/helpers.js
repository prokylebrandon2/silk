// Builds backups exactly the way the app does (core/src/backup.rs + keyslot.rs + skln.rs), so the
// extension can be tested without the app. The .skln sealing here uses node:crypto, not
// src/chacha.js, so the two are independent of each other.
import { createCipheriv, hkdfSync } from 'node:crypto';
import { argon2, TYPES } from '../src/argon2.js';

/**
 * A `.skln` bundle file (kind 1) with one member per [name, bytes] pair, sealed under `vek`.
 * `chunkLog2` is small in tests so that a vault spans several records.
 */
export function sealSkln(vek, members, revision = 1, chunkLog2 = 20) {
  const le = (bytes, n, size) => {
    const b = Buffer.alloc(size);
    if (size === 2) b.writeUInt16LE(n);
    else b.writeUInt32LE(n);
    return bytes ? Buffer.concat([b, bytes]) : b;
  };
  const archive = Buffer.concat([
    le(null, members.length, 4),
    ...members.flatMap(([name, data]) => {
      const nameBytes = Buffer.from(name);
      return [le(nameBytes, nameBytes.length, 2), le(Buffer.from(data), data.length, 4)];
    }),
  ]);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const header = Buffer.alloc(36);
  Buffer.from([0x89, 0x53, 0x4b, 0x4c, 0x4e, 0x0d, 0x0a, 0x1a, 1, 0, 1, chunkLog2]).copy(header, 0);
  header.writeBigUInt64LE(BigInt(revision), 12);
  Buffer.from(salt).copy(header, 20);
  const key = Buffer.from(hkdfSync('sha256', vek, salt, 'kiln skln v1 file key', 32));
  const chunk = 2 ** chunkLog2;
  const pieces = [];
  for (let at = 0; at < archive.length; at += chunk) pieces.push(archive.subarray(at, at + chunk));
  if (pieces.length === 0) pieces.push(Buffer.alloc(0));
  const out = [header];
  pieces.forEach((piece, i) => {
    const nonce = Buffer.alloc(12);
    nonce.writeBigUInt64LE(BigInt(i), 4);
    const cipher = createCipheriv('chacha20-poly1305', key, nonce, { authTagLength: 16 });
    cipher.setAAD(Buffer.concat([header, Buffer.from([i === pieces.length - 1 ? 1 : 0])]));
    const sealed = Buffer.concat([cipher.update(piece), cipher.final(), cipher.getAuthTag()]);
    out.push(le(sealed, sealed.length, 4).subarray(0, 4), sealed);
  });
  return new Uint8Array(Buffer.concat(out));
}

/**
 * A Silk backup: "SKBK" | 1 | key slot[91] | vault file. The VEK is random; the Argon2id key only wraps it.
 */
export async function sealBundle(entries, password, keyFile, kdf = { t: 1, m: 64, p: 1 }, revision = 1, chunkLog2 = 20) {
  const sha = async (b) => new Uint8Array(await crypto.subtle.digest('SHA-256', b));
  const gcm = async (key, iv, aad, data) => {
    const k = await crypto.subtle.importKey('raw', key, 'AES-GCM', false, ['encrypt']);
    return new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 }, k, data));
  };
  const concat = (...parts) => {
    const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
    let at = 0;
    for (const p of parts) {
      out.set(p, at);
      at += p.length;
    }
    return out;
  };

  // key slot
  const vek = crypto.getRandomValues(new Uint8Array(32));
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const slotHeader = new Uint8Array(31);
  slotHeader.set([0x53, 0x4b, 0x56, 0x4b, 1, keyFile ? 1 : 0]);
  const sdv = new DataView(slotHeader.buffer);
  sdv.setUint32(6, kdf.t);
  sdv.setUint32(10, kdf.m);
  slotHeader[14] = kdf.p;
  slotHeader.set(salt, 15);
  let ikm = await sha(new TextEncoder().encode(password));
  if (keyFile) ikm = await sha(concat(ikm, await sha(keyFile)));
  const kek = argon2(ikm, salt, { ...kdf, len: 32, type: TYPES.argon2id });
  const slotNonce = crypto.getRandomValues(new Uint8Array(12));
  const slot = concat(slotHeader, slotNonce, await gcm(kek, slotNonce, slotHeader, vek));

  const body = new TextEncoder().encode(JSON.stringify({ entries }));
  const vault = sealSkln(vek, [['vault.json', body]], revision, chunkLog2);
  return concat(new Uint8Array([0x53, 0x4b, 0x42, 0x4b, 1]), slot, vault);
}
