// Opens the file the Android app produces for the extension: a Silk backup (core/src/backup.rs),
// "SKBK" | version | key slot[91] | vault file.
//
//   key slot   core/src/keyslot.rs: the random VEK encrypted with the Argon2id key.
//              "SKVK" | version | flags | t u32 | memKiB u32 | p u8 | salt[16] | nonce[12] | AES-GCM(VEK) + tag
//              (the first 31 bytes are the associated data)
//   vault file Kiln's `.skln` container (src/skln.js, core/src/skln.rs): the entries, encrypted with
//              the VEK, as a bundle with one member, "vault.json".
//
// So: Argon2id key -> unwrap VEK -> decrypt the vault file -> read the bundle. The key is
// Argon2id( SHA-256(password) [then SHA-256(that || SHA-256(key file))] ) with the key slot's salt.
import { argon2, TYPES } from './argon2.js';
import { isSkln, openSkln, unpackBundle, KIND_BUNDLE } from './skln.js';

const NONCE_LEN = 12;
const BUNDLE_HEADER = 5; // "SKBK" + version
const SLOT_LEN = 91;
const SLOT_AAD = 31;
const SKLN_HEADER = 36;

const MAGIC_BUNDLE = [0x53, 0x4b, 0x42, 0x4b]; // SKBK
const MAGIC_SLOT = [0x53, 0x4b, 0x56, 0x4b]; // SKVK

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

/** Reads the plain header of a Silk backup: whether it needs a key file, the Argon2id cost and salt, and the two parts. */
export function parseHeader(f) {
  const notSilk = () => new VaultError('not-a-vault', "This isn't a Silk file.");
  if (f.length < BUNDLE_HEADER + SLOT_LEN + SKLN_HEADER || !hasMagic(f, MAGIC_BUNDLE) || f[4] !== 1) throw notSilk();
  const slot = f.subarray(BUNDLE_HEADER, BUNDLE_HEADER + SLOT_LEN);
  const vault = f.subarray(BUNDLE_HEADER + SLOT_LEN);
  if (!hasMagic(slot, MAGIC_SLOT) || slot[4] !== 1 || !isSkln(vault) || vault[8] !== 1) throw notSilk();
  const dv = new DataView(slot.buffer, slot.byteOffset, slot.byteLength);
  const t = dv.getUint32(6);
  const m = dv.getUint32(10);
  const p = slot[14];
  checkCost(t, m, p);
  return { keyFile: (slot[5] & 1) === 1, t, m, p, salt: slot.slice(15, 31), slot, vault };
}

async function sha256(bytes) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
}

async function deriveKey(password, keyFile, header, onProgress) {
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

/** Decrypts the backup and returns the list of logins. Throws VaultError with a code the UI can act on. */
export async function openVault(file, password, keyFile, onProgress) {
  const header = parseHeader(file);
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
    const opened = await openSkln(vek, vault);
    plain = opened.plaintext;
    if (opened.kind !== KIND_BUNDLE) throw damaged();
    members = unpackBundle(plain);
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

export function toBase64(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(s);
}

export const fromBase64 = (b64) => Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
