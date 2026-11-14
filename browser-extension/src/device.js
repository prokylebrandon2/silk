// A key that belongs to this browser profile, used to seal small secrets so the extension can open
// without asking again (the vault key after unlocking, the cloud refresh token after signing in).
//
// Each key is a non-extractable AES-GCM CryptoKey kept in IndexedDB: page and extension code can use
// it, but nothing can read its bytes out through the API. That keeps a sealed blob in
// chrome.storage useless on its own, and deleting the key (forget) makes every blob sealed with it
// unreadable at once. It does NOT protect against someone who can run code as you in this browser
// profile, or who copies the whole profile folder; that is the price of opening without a password.
import { toBase64, fromBase64 } from './vault.js';

const DB = 'silk-device';
const STORE = 'keys';

const request = (r) =>
  new Promise((resolve, reject) => {
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => reject(r.error);
  });

async function withStore(mode, fn) {
  const opening = indexedDB.open(DB, 1);
  opening.onupgradeneeded = () => opening.result.createObjectStore(STORE);
  const db = await request(opening);
  try {
    return await fn(db.transaction(STORE, mode).objectStore(STORE));
  } finally {
    db.close();
  }
}

/** The key called `name`; with `create` a missing one is made. The popup and the service worker may both ask at once. */
const keyFor = (name, create) =>
  navigator.locks.request(`silk-key-${name}`, async () => {
    let key = await withStore('readonly', (s) => request(s.get(name)));
    if (!key && create) {
      key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
      await withStore('readwrite', (s) => request(s.put(key, name)));
    }
    return key || null;
  });

const context = (name) => new TextEncoder().encode(`silk:${name}`);

/** Seals bytes under the key `name` (made on first use). Returns text that is safe to keep in chrome.storage. */
export async function seal(name, bytes) {
  const key = await keyFor(name, true);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const sealed = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: context(name) }, key, bytes));
  return `${toBase64(iv)}.${toBase64(sealed)}`;
}

/** The bytes inside a blob from `seal`, or null when the key is gone or the blob is not ours. */
export async function unseal(name, blob) {
  const key = await keyFor(name, false);
  const [iv, sealed] = String(blob).split('.');
  if (!key || !iv || !sealed) return null;
  try {
    return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: fromBase64(iv), additionalData: context(name) }, key, fromBase64(sealed)));
  } catch {
    return null;
  }
}

/** Deletes the key `name`, which makes everything sealed with it unreadable. */
export const forget = (name) => navigator.locks.request(`silk-key-${name}`, () => withStore('readwrite', (s) => request(s.delete(name))));
