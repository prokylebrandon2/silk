// Opens the two file kinds the Android app produces.
//
// 1. A Silk backup (core/src/backup.rs, the current kind): "SKBK" | version | key slot[91] | vault file.
//    The key slot (core/src/keyslot.rs) is the random VEK encrypted with the Argon2id key; the vault
//    file is the entries encrypted with the VEK. So: Argon2id key -> unwrap VEK -> decrypt the vault
//    file -> read the archive. The vault file is one of two kinds:
//      key slot   "SKVK" | version | flags | t u32 | memKiB u32 | p u8 | salt[16] | nonce[12] | AES-GCM(VEK) + tag
//                 (the first 31 bytes are the associated data)
//      .skln      Kiln's container (src/skln.js, core/src/skln.rs): the kind the app writes now.
//      "SKIM"     the stand-in that came before (core/src/interim.rs), read so older backups still open:
//                 "SKIM" | version | flags | revision u64 | nonce[12] | AES-GCM(archive) + tag
//                 (the first 14 bytes are the associated data)
//      archive    count u32 | { name_len u16 | name | data_len u32 | data }*, entries in "vault.json"
//                 (big-endian in "SKIM", little-endian in .skln)
//
// 2. An old vault file (core/src/vault.rs, kept so old backups still open): "PVLT" | version | flags |
//    t | memKiB | p | salt[16], then nonce[12] and AES-256-GCM(ciphertext + tag). Here the Argon2id
//    key encrypts the entries directly.
//
// In both, the key is Argon2id( SHA-256(password) [then SHA-256(that || SHA-256(key file))] ) with the salt.
import { argon2, TYPES } from './argon2.js';
import { isSkln, openSkln, unpackBundle, KIND_BUNDLE } from './skln.js';

const HEADER_LEN = 31;
const NONCE_LEN = 12;
const TAG_LEN = 16;

const BUNDLE_HEADER = 5; // "SKBK" + version
const SLOT_LEN = 91;
const SLOT_AAD = 31;
const VAULT_AAD = 14;
const MAX_MEMBERS = 1024;

const MAGIC_BUNDLE = [0x53, 0x4b, 0x42, 0x4b]; // SKBK
const MAGIC_SLOT = [0x53, 0x4b, 0x56, 0x4b]; // SKVK
const MAGIC_VAULT = [0x53, 0x4b, 0x49, 0x4d]; // SKIM
const MAGIC_LEGACY = [0x50, 0x56, 0x4c, 0x54]; // PVLT

const hasMagic = (f, magic) => f.length >= 4 && magic.every((b, i) => f[i] === b);

export class VaultError extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
  }
}

// Same limits as the app: a crafted file must not be able to exhaust memory.
function checkCost(t, m, p) {
  if (t < 1 || t > 32 || m < 8 || m > 1 << 18 || p < 1 || p > 16) {
    throw new VaultError('corrupt', 'The vault file is damaged.');
  }
}

/** Reads the plain header of either file kind. `kind` is 'silk' (backup) or 'legacy' (old vault file). */
export function parseHeader(f) {
  if (hasMagic(f, MAGIC_BUNDLE)) return parseBundle(f);
  if (f.length < HEADER_LEN + NONCE_LEN + TAG_LEN || !hasMagic(f, MAGIC_LEGACY) || f[4] !== 1) {
    throw new VaultError('not-a-vault', "This isn't a Silk file.");
  }
  const dv = new DataView(f.buffer, f.byteOffset, f.byteLength);
  const t = dv.getUint32(6);
  const m = dv.getUint32(10);
  const p = f[14];
  checkCost(t, m, p);
  return { kind: 'legacy', keyFile: (f[5] & 1) === 1, t, m, p, salt: f.slice(15, 31) };
}

export function parseBundle(f) {
  if (f.length < BUNDLE_HEADER + SLOT_LEN + VAULT_AAD + NONCE_LEN + TAG_LEN || !hasMagic(f, MAGIC_BUNDLE) || f[4] !== 1) {
    throw new VaultError('not-a-vault', "This isn't a Silk file.");
  }
  const slot = f.subarray(BUNDLE_HEADER, BUNDLE_HEADER + SLOT_LEN);
  const vault = f.subarray(BUNDLE_HEADER + SLOT_LEN);
  const vaultOk = isSkln(vault) ? vault[8] === 1 : hasMagic(vault, MAGIC_VAULT) && vault[4] === 1;
  if (!hasMagic(slot, MAGIC_SLOT) || slot[4] !== 1 || !vaultOk) {
    throw new VaultError('not-a-vault', "This isn't a Silk file.");
  }
  const dv = new DataView(slot.buffer, slot.byteOffset, slot.byteLength);
  const t = dv.getUint32(6);
  const m = dv.getUint32(10);
  const p = slot[14];
  checkCost(t, m, p);
  return { kind: 'silk', keyFile: (slot[5] & 1) === 1, t, m, p, salt: slot.slice(15, 31), slot, vault };
}

async function sha256(bytes) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
}

export async function deriveKey(password, keyFile, header, onProgress) {
  let ikm = await sha256(new TextEncoder().encode(password));
  if (keyFile) {
    const kf = await sha256(keyFile);
    const both = new Uint8Array(64);
    both.set(ikm, 0);
    both.set(kf, 32);
    ikm = await sha256(both);
  }
  return argon2(ikm, header.salt, { t: header.t, m: header.m, p: header.p, len: 32, type: TYPES.argon2id }, onProgress);
}

const decryptGcm = async (rawKey, iv, aad, data) => {
  const k = await crypto.subtle.importKey('raw', rawKey, 'AES-GCM', false, ['decrypt']);
  return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 }, k, data));
};

const damaged = () => new VaultError('corrupt', 'The vault file is damaged.');

/** Reads the archive layout (core/src/interim.rs) into a Map of name -> bytes. Every length is checked. */
function unpack(buf) {
  const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  let pos = 0;
  const need = (n) => {
    if (n > buf.length - pos) throw damaged();
  };
  need(4);
  const count = dv.getUint32(pos);
  pos += 4;
  if (count > MAX_MEMBERS) throw damaged();
  const members = new Map();
  for (let i = 0; i < count; i++) {
    need(2);
    const nameLen = dv.getUint16(pos);
    pos += 2;
    need(nameLen);
    let name;
    try {
      name = new TextDecoder('utf-8', { fatal: true }).decode(buf.subarray(pos, pos + nameLen));
    } catch {
      throw damaged();
    }
    pos += nameLen;
    need(4);
    const dataLen = dv.getUint32(pos);
    pos += 4;
    need(dataLen);
    if (members.has(name)) throw damaged();
    members.set(name, buf.subarray(pos, pos + dataLen));
    pos += dataLen;
  }
  if (pos !== buf.length) throw damaged();
  return members;
}

const toEntries = (doc) =>
  (doc.entries || []).map((e) => ({
    id: String(e.id ?? ''),
    title: String(e.title ?? ''),
    username: String(e.username ?? ''),
    password: String(e.password ?? ''),
    url: String(e.url ?? ''),
    otp: String(e.otp ?? ''),
    notes: String(e.notes ?? ''),
  }));

function parseDoc(bytes) {
  try {
    return JSON.parse(new TextDecoder().decode(bytes));
  } catch {
    throw damaged();
  }
}

async function openBundle(file, password, keyFile, onProgress) {
  const header = parseBundle(file);
  if (header.keyFile && !keyFile) throw new VaultError('key-file-required', 'This vault needs its key file. Choose it and try again.');
  if (!header.keyFile && keyFile) throw new VaultError('key-file-not-used', "This vault doesn't use a key file. Clear the key file and try again.");
  const kek = await deriveKey(password, keyFile, header, onProgress);
  const { slot, vault } = header;
  // The key slot: only the right password (and key file) unwraps the VEK.
  let vek;
  try {
    vek = await decryptGcm(kek, slot.subarray(SLOT_AAD, SLOT_AAD + NONCE_LEN), slot.subarray(0, SLOT_AAD), slot.subarray(SLOT_AAD + NONCE_LEN));
  } catch {
    throw new VaultError('wrong-credentials', 'Wrong password or key file. Check both and try again.');
  }
  if (vek.length !== 32) throw damaged();
  // The vault file: with the right VEK this only fails if the file was changed.
  let plain;
  let members;
  try {
    if (isSkln(vault)) {
      const opened = await openSkln(vek, vault);
      plain = opened.plaintext;
      if (opened.kind !== KIND_BUNDLE) throw damaged();
      members = unpackBundle(plain);
    } else {
      plain = await decryptGcm(vek, vault.subarray(VAULT_AAD, VAULT_AAD + NONCE_LEN), vault.subarray(0, VAULT_AAD), vault.subarray(VAULT_AAD + NONCE_LEN));
      members = unpack(plain);
    }
  } catch (e) {
    throw e instanceof VaultError ? e : damaged();
  } finally {
    vek.fill(0);
  }
  const member = members.get('vault.json');
  if (!member) throw damaged();
  const doc = parseDoc(member);
  plain.fill(0);
  return toEntries(doc);
}

/** Decrypts the file and returns the list of logins. Throws VaultError with a code the UI can act on. */
export async function openVault(file, password, keyFile, onProgress) {
  if (hasMagic(file, MAGIC_BUNDLE)) return openBundle(file, password, keyFile, onProgress);
  const header = parseHeader(file);
  if (header.keyFile && !keyFile) throw new VaultError('key-file-required', 'This vault needs its key file. Choose it and try again.');
  if (!header.keyFile && keyFile) throw new VaultError('key-file-not-used', "This vault doesn't use a key file. Clear the key file and try again.");
  const key = await deriveKey(password, keyFile, header, onProgress);
  const aad = file.subarray(0, HEADER_LEN);
  const nonce = file.subarray(HEADER_LEN, HEADER_LEN + NONCE_LEN);
  const body = file.subarray(HEADER_LEN + NONCE_LEN);
  let plain;
  try {
    const k = await crypto.subtle.importKey('raw', key, 'AES-GCM', false, ['decrypt']);
    plain = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce, additionalData: aad, tagLength: 128 }, k, body));
  } catch {
    throw new VaultError('wrong-credentials', 'Wrong password or key file. Check both and try again.');
  }
  const doc = parseDoc(plain);
  plain.fill(0);
  return toEntries(doc);
}

export function toBase64(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(s);
}

export const fromBase64 = (b64) => Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
