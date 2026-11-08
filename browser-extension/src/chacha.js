// ChaCha20-Poly1305 (RFC 8439), decrypting only.
//
// A `.skln` vault file (core/src/skln.rs, Kiln's format) is sealed with it, and WebCrypto has no
// ChaCha20, so the extension carries its own, as it does for Argon2id. Poly1305 uses BigInt: that is
// slower than limbs but short and easy to check, and a vault is a few hundred KB. The tag is compared
// without stopping at the first difference.

const SIGMA = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];
const rotl = (v, n) => (v << n) | (v >>> (32 - n));

/** XORs `data` with the keystream that starts at block `counter`. Returns a new array. */
function xorStream(key, nonce, counter, data) {
  const kv = new DataView(key.buffer, key.byteOffset, key.byteLength);
  const nv = new DataView(nonce.buffer, nonce.byteOffset, nonce.byteLength);
  const state = new Uint32Array(16);
  state.set(SIGMA, 0);
  for (let i = 0; i < 8; i++) state[4 + i] = kv.getUint32(i * 4, true);
  for (let i = 0; i < 3; i++) state[13 + i] = nv.getUint32(i * 4, true);
  const out = new Uint8Array(data.length);
  const x = new Uint32Array(16);
  const ks = new DataView(new ArrayBuffer(64));
  const qr = (a, b, c, d) => {
    x[a] += x[b];
    x[d] = rotl(x[d] ^ x[a], 16);
    x[c] += x[d];
    x[b] = rotl(x[b] ^ x[c], 12);
    x[a] += x[b];
    x[d] = rotl(x[d] ^ x[a], 8);
    x[c] += x[d];
    x[b] = rotl(x[b] ^ x[c], 7);
  };
  for (let off = 0; off < data.length; off += 64, counter++) {
    state[12] = counter;
    x.set(state);
    for (let r = 0; r < 10; r++) {
      qr(0, 4, 8, 12);
      qr(1, 5, 9, 13);
      qr(2, 6, 10, 14);
      qr(3, 7, 11, 15);
      qr(0, 5, 10, 15);
      qr(1, 6, 11, 12);
      qr(2, 7, 8, 13);
      qr(3, 4, 9, 14);
    }
    for (let i = 0; i < 16; i++) ks.setUint32(i * 4, (x[i] + state[i]) >>> 0, true);
    const n = Math.min(64, data.length - off);
    for (let i = 0; i < n; i++) out[off + i] = data[off + i] ^ ks.getUint8(i);
  }
  return out;
}

const P = (1n << 130n) - 5n;
const MASK128 = (1n << 128n) - 1n;
const CLAMP = 0x0ffffffc0ffffffc0ffffffc0fffffffn;

function leToBig(bytes) {
  let n = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(bytes[i]);
  return n;
}

function poly1305(key, msg) {
  const r = leToBig(key.subarray(0, 16)) & CLAMP;
  const s = leToBig(key.subarray(16, 32));
  let acc = 0n;
  for (let i = 0; i < msg.length; i += 16) {
    const block = msg.subarray(i, i + 16);
    acc = ((acc + (leToBig(block) | (1n << BigInt(8 * block.length)))) * r) % P;
  }
  acc = (acc + s) & MASK128;
  const tag = new Uint8Array(16);
  for (let i = 0; i < 16; i++) {
    tag[i] = Number(acc & 0xffn);
    acc >>= 8n;
  }
  return tag;
}

/**
 * Decrypts `sealed` (ciphertext followed by its 16-byte tag) with a 32-byte key and 12-byte nonce.
 * Throws if the tag does not match.
 */
export function chacha20Poly1305Open(key, nonce, aad, sealed) {
  if (key.length !== 32 || nonce.length !== 12 || sealed.length < 16) throw new Error('bad ChaCha20-Poly1305 input');
  const ct = sealed.subarray(0, sealed.length - 16);
  const tag = sealed.subarray(sealed.length - 16);
  const otk = xorStream(key, nonce, 0, new Uint8Array(32));
  const pad = (n) => (16 - (n % 16)) % 16;
  const mac = new Uint8Array(aad.length + pad(aad.length) + ct.length + pad(ct.length) + 16);
  mac.set(aad, 0);
  mac.set(ct, aad.length + pad(aad.length));
  const dv = new DataView(mac.buffer);
  dv.setBigUint64(mac.length - 16, BigInt(aad.length), true);
  dv.setBigUint64(mac.length - 8, BigInt(ct.length), true);
  const expect = poly1305(otk, mac);
  otk.fill(0);
  let diff = 0;
  for (let i = 0; i < 16; i++) diff |= expect[i] ^ tag[i];
  if (diff !== 0) throw new Error('ChaCha20-Poly1305 tag mismatch');
  return xorStream(key, nonce, 1, ct);
}
