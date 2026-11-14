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
import { isSkln, openSkln, parseSkln, unpackBundle, packBundle, sealSkln, KIND_BUNDLE } from './skln.js';

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

// Every field of an entry is kept (kind, folder, labelled fields), because saving writes the whole
// entry back and the app must find its cards, notes and folders as it left them.
const toEntries = (doc) =>
  (doc.entries || []).map((e) => ({
    ...e,
    id: String(e.id ?? ''),
    title: String(e.title ?? ''),
    username: String(e.username ?? ''),
    password: String(e.password ?? ''),
    url: String(e.url ?? ''),
    otp: String(e.otp ?? ''),
    notes: String(e.notes ?? ''),
    kind: String(e.kind ?? ''),
    folder: String(e.folder ?? ''),
    fields: (Array.isArray(e.fields) ? e.fields : []).map((f) => ({ label: String(f.label ?? ''), value: String(f.value ?? ''), secret: f.secret === true })),
  }));

function parseDoc(bytes) {
  try {
    return JSON.parse(new TextDecoder().decode(bytes));
  } catch {
    throw damaged();
  }
}

/** The key slot: only the right password (and key file) unwraps the VEK. */
async function unwrapVek(header, password, keyFile, onProgress) {
  if (header.keyFile && !keyFile) throw new VaultError('key-file-required', 'This vault needs its key file. Choose it and try again.');
  if (!header.keyFile && keyFile) throw new VaultError('key-file-not-used', "This vault doesn't use a key file. Clear the key file and try again.");
  const kek = await deriveKey(password, keyFile, header, onProgress);
  const { slot } = header;
  let vek;
  try {
    vek = await decryptGcm(kek, slot.subarray(SLOT_AAD, SLOT_AAD + NONCE_LEN), slot.subarray(0, SLOT_AAD), slot.subarray(SLOT_AAD + NONCE_LEN));
  } catch {
    throw new VaultError('wrong-credentials', 'Wrong password or key file. Check both and try again.');
  }
  if (vek.length !== 32) throw damaged();
  return vek;
}

/** The revision in the plain header of a parsed backup (a BigInt). It is authenticated once the vault file opens. */
export const revisionOf = (header) => parseSkln(header.vault).revision;

/**
 * Opens the vault file of a backup with the VEK: no password, no Argon2id.
 * Returns { entries, revision (BigInt), extras }, where extras holds any bundle member besides
 * vault.json so that saving can carry it along. With the right VEK this only fails if the file was changed.
 */
export async function openWithVek(file, vek) {
  const { vault } = parseHeader(file);
  let plain;
  let members;
  let revision;
  try {
    const opened = await openSkln(vek, vault);
    plain = opened.plaintext;
    revision = opened.revision;
    if (opened.kind !== KIND_BUNDLE) throw damaged();
    members = unpackBundle(plain);
  } catch (e) {
    throw e instanceof VaultError ? e : damaged();
  }
  const member = members.get('vault.json');
  if (!member) {
    plain.fill(0);
    throw damaged();
  }
  const doc = parseDoc(member);
  const extras = new Map();
  for (const [name, data] of members) if (name !== 'vault.json') extras.set(name, data.slice());
  plain.fill(0);
  return { entries: toEntries(doc), revision, extras };
}

/**
 * Decrypts the backup with the master password (and key file) and returns the entries together with
 * the VEK, which the caller must wipe or keep on purpose. Throws VaultError with a code the UI can act on.
 */
export async function unlockVault(file, password, keyFile, onProgress) {
  const vek = await unwrapVek(parseHeader(file), password, keyFile, onProgress);
  try {
    return { ...(await openWithVek(file, vek)), vek };
  } catch (e) {
    vek.fill(0);
    throw e;
  }
}

/** Decrypts the backup and returns the list of logins. Throws VaultError with a code the UI can act on. */
export async function openVault(file, password, keyFile, onProgress) {
  const opened = await unlockVault(file, password, keyFile, onProgress);
  opened.vek.fill(0);
  return opened.entries;
}

/**
 * The backup with `entries` sealed under the VEK as revision + 1 (what the app's save does). The key
 * slot is the same bytes, so the master password and key file keep working. `extras` and `revision`
 * come from openWithVek on the backup being replaced. Returns { file, revision }.
 */
export async function sealVault(file, vek, entries, extras, revision) {
  const { slot } = parseHeader(file);
  const body = new TextEncoder().encode(JSON.stringify({ entries }));
  const packed = packBundle(new Map([['vault.json', body], ...extras]));
  const next = revision + 1n;
  try {
    return { file: joinBackup(slot, await sealSkln(vek, next, packed)), revision: next };
  } finally {
    packed.fill(0);
    body.fill(0);
  }
}

export function toBase64(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(s);
}

export const fromBase64 = (b64) => Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));

/** Joins the two files kept in the cloud (key slot, vault file) into a backup: the bytes the app's Back up vault writes. */
export function joinBackup(slot, vault) {
  if (slot.length !== SLOT_LEN) throw new VaultError('not-a-vault', "This isn't a Silk file.");
  const out = new Uint8Array(BUNDLE_HEADER + SLOT_LEN + vault.length);
  out.set([...MAGIC_BUNDLE, 1], 0);
  out.set(slot, BUNDLE_HEADER);
  out.set(vault, BUNDLE_HEADER + SLOT_LEN);
  parseHeader(out); // throws if either part is not what it should be
  return out;
}

