// Supabase for the extension: the same steps as the app (core/src/auth.rs, core/src/supabase.rs,
// core/src/sync.rs). This is the only file in the extension that talks to the network. Supabase Auth
// signs the user in with email and password; the two encrypted files then live in the user's folder of
// the private bucket. The content security policy lets extension pages talk to *.supabase.co and nothing else.
//
// "Sign in once": after the first sign-in only the refresh token is kept, sealed by the device key
// (src/device.js), and each use trades it for a new access token. The account password is never stored.
import { VaultError, fromBase64, joinBackup } from './vault.js';
import { parseSkln } from './skln.js';
import { exclusive, loadVault, storeVault } from './state.js';
import * as device from './device.js';
import { SUPABASE_URL, SUPABASE_PUBLISHABLE_KEY } from './config.js';

const MAX_FILE = 8 * 1024 * 1024; // chrome.storage.local allows 10 MB
const SYNC_MINUTES = 30;
const local = chrome.storage.local;

// ------------------------------------------------------------------ configuration

const clean = (s) => String(s).replace(/[\x00-\x1f\x7f]/g, '').slice(0, 160);

function jwtClaims(token) {
  const parts = String(token).split('.');
  if (parts.length !== 3) return null;
  try {
    const b64 = parts[1].replace(/-/g, '+').replace(/_/g, '/');
    return JSON.parse(new TextDecoder().decode(fromBase64(b64 + '='.repeat((4 - (b64.length % 4)) % 4))));
  } catch {
    return null;
  }
}

/** Same rules as the app's Config::new: a Supabase project URL and a publishable key, never a secret one. */
function cloudConfig(url, key) {
  let base = String(url || '').trim().replace(/\/+$/, '');
  for (const api of ['/rest/v1', '/auth/v1', '/storage/v1']) {
    if (base.endsWith(api)) {
      base = base.slice(0, -api.length);
      break;
    }
  }
  const k = String(key || '').trim();
  if (!/^https:\/\/[a-z0-9]+\.supabase\.co$/.test(base)) return null;
  if (!k || k.startsWith('YOUR_') || k.startsWith('sb_secret_') || !/^[A-Za-z0-9._-]+$/.test(k)) return null;
  if (k.includes('.')) {
    const claims = jwtClaims(k);
    if (!claims || claims.role !== 'anon') return null;
  }
  return { url: base, key: k };
}

/** The project values, or null in a build without them (cloud sign-in is then switched off). */
export const CLOUD = cloudConfig(SUPABASE_URL, SUPABASE_PUBLISHABLE_KEY);

// ------------------------------------------------------------------ requests

async function cloudCall(path, init, token) {
  const headers = { apikey: CLOUD.key, ...(init.headers || {}) };
  if (token) headers.Authorization = `Bearer ${token}`;
  try {
    return await fetch(CLOUD.url + path, { ...init, headers, credentials: 'omit', cache: 'no-store', signal: AbortSignal.timeout(30000) });
  } catch {
    throw new VaultError('network', 'Couldn’t reach Supabase. Check your connection and the project URL.');
  }
}

function authError(status, body) {
  const code = String(body.error_code || '');
  const msg = String(body.msg || body.message || body.error_description || body.error || '');
  const lower = msg.toLowerCase();
  if (code === 'invalid_credentials' || body.error === 'invalid_grant' || lower.includes('invalid login credentials')) return 'Wrong email or password.';
  if (code === 'email_not_confirmed' || lower.includes('email not confirmed')) return 'Confirm your email first: open the link Supabase sent to that address, then sign in.';
  if (code === 'email_provider_disabled') return 'Email sign-in is turned off in the Supabase project.';
  if (code === 'user_banned') return 'This account has been disabled.';
  if (status === 429 || code.startsWith('over_')) return 'Too many attempts. Wait a few minutes and try again.';
  if (lower.includes('api key') || lower.includes('apikey')) return 'Supabase doesn’t accept that key. Check the publishable key.';
  return msg ? clean(msg) : `Supabase Auth answered ${status}`;
}

/** A refresh token Supabase no longer accepts: the saved sign-in is no good any more. */
function deadRefresh(body) {
  const code = String(body.error_code || '');
  const msg = String(body.msg || body.message || body.error_description || '').toLowerCase();
  return ['refresh_token_not_found', 'refresh_token_already_used', 'session_expired', 'session_not_found', 'user_not_found', 'bad_jwt'].includes(code) || body.error === 'invalid_grant' || msg.includes('refresh token');
}

/** Signs in with a password or a refresh token. Returns { uid, email, access, refresh }. */
async function authCall(grant, body) {
  const res = await cloudCall(`/auth/v1/token?grant_type=${grant}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  const reply = await res.json().catch(() => ({}));
  if (!res.ok) {
    if (grant === 'refresh_token' && deadRefresh(reply)) throw new VaultError('signed-out', 'Your Silk sign-in expired. Sign in again.');
    throw new VaultError('account', authError(res.status, reply));
  }
  const uid = reply.user && reply.user.id;
  const claims = jwtClaims(reply.access_token);
  // Same check as the app: the token must belong to the account whose folder is read.
  if (!uid || !claims || claims.sub !== uid || !reply.refresh_token) throw new VaultError('account', 'Supabase gave an unexpected sign-in answer.');
  return { uid, email: String((reply.user && reply.user.email) || ''), access: reply.access_token, refresh: reply.refresh_token };
}

const objectPath = (uid, name) => `/storage/v1/object/silk-vaults/vaults/${encodeURIComponent(uid)}/${name}`;

/** One file from the user's folder. `null` means it isn't there; every other problem throws. */
async function getObject(session, name) {
  const res = await cloudCall(objectPath(session.uid, name).replace('/object/', '/object/authenticated/'), {}, session.access);
  if (res.ok) {
    if (Number(res.headers.get('content-length') || 0) > MAX_FILE) throw new VaultError('too-large', 'That vault is too large for this extension.');
    const bytes = new Uint8Array(await res.arrayBuffer());
    if (bytes.length > MAX_FILE) throw new VaultError('too-large', 'That vault is too large for this extension.');
    return bytes;
  }
  const { code, msg } = await storageError(res);
  if (code === 401 || /jwt/i.test(msg)) throw new VaultError('account', 'Supabase didn’t accept the sign-in. Try again.');
  if (/bucket/i.test(msg)) throw new VaultError('cloud', `Supabase Storage: ${clean(msg)}`);
  if (code === 404) return null;
  throw storageFailure(code, msg);
}

/** Storage sometimes answers 400 with the real status in the body. */
async function storageError(res) {
  const err = await res.json().catch(() => ({}));
  const msg = String(err.message || '');
  return { code: err.error === 'not_found' ? 404 : Number(err.statusCode || res.status), msg, duplicate: err.error === 'Duplicate' };
}

function storageFailure(code, msg) {
  if (code === 403 || /row-level security/i.test(msg)) return new VaultError('cloud', 'Supabase refused the request. Check that supabase/storage-policies.sql has been run on the project.');
  if (code === 413 || /maximum allowed size/i.test(msg)) return new VaultError('cloud', 'The vault is larger than the cloud storage allows.');
  return new VaultError('cloud', `Supabase Storage answered ${code}${msg ? `: ${clean(msg)}` : ''}`);
}

/**
 * Writes one file. `exists` is what the read just before it found: a file that was there is replaced
 * (PUT); one that was not is created (POST, which refuses to replace anything), so a file that appeared
 * in between, or that the policies hide, is never overwritten blindly.
 */
async function putObject(session, name, bytes, exists) {
  const res = await cloudCall(objectPath(session.uid, name), { method: exists ? 'PUT' : 'POST', headers: { 'Content-Type': 'application/octet-stream', 'cache-control': 'max-age=0' }, body: bytes }, session.access);
  if (res.ok) return;
  const { code, msg, duplicate } = await storageError(res);
  if (code === 401 || /jwt/i.test(msg)) throw new VaultError('account', 'Supabase didn’t accept the sign-in. Try again.');
  if (code === 409 || duplicate) throw new VaultError('cloud', 'The cloud copy changed while syncing, so nothing was replaced. Sync again.');
  throw storageFailure(code, msg);
}

// ------------------------------------------------------------------ the saved sign-in

/** The saved sign-in ({ email, uid, token }), or null. The token is the refresh token, sealed by the device key. */
export const cloudSession = async () => (await local.get('cloud')).cloud || null;

async function saveSignIn(s) {
  await local.set({ cloud: { email: s.email, uid: s.uid, token: await device.seal('cloud', new TextEncoder().encode(s.refresh)) } });
  chrome.alarms.create('silk-sync', { periodInMinutes: SYNC_MINUTES });
}

/** Forgets the saved sign-in (the vault in this browser stays). */
export async function signOut() {
  await local.remove(['cloud', 'lastSync']);
  await device.forget('cloud');
  chrome.alarms.clear('silk-sync');
}

/** A session with a fresh access token, from the saved refresh token. Supabase rotates it, so the new one is saved at once. */
function freshSession() {
  return navigator.locks.request('silk-cloud', async () => {
    const saved = await cloudSession();
    if (!saved) throw new VaultError('signed-out', 'Sign in to your Silk account first.');
    const sealed = await device.unseal('cloud', saved.token);
    if (!sealed) {
      await signOut();
      throw new VaultError('signed-out', 'Your Silk sign-in expired. Sign in again.');
    }
    let session;
    try {
      session = await authCall('refresh_token', { refresh_token: new TextDecoder().decode(sealed) });
    } catch (e) {
      if (e.code === 'signed-out') await signOut();
      throw e;
    }
    if (session.uid !== saved.uid) throw new VaultError('account', 'Supabase gave an unexpected sign-in answer.');
    await saveSignIn({ ...session, email: session.email || saved.email });
    return session;
  });
}

/**
 * First sign-in: email and password, then the two encrypted files joined into a backup. The sign-in is
 * saved (refresh token only) so later opens and syncs need no password. Returns { bytes, uid }.
 */
export async function signInAndDownload(email, password) {
  const session = await authCall('password', { email, password });
  const slot = await getObject(session, 'keyslot.skvk');
  if (!slot) throw new VaultError('no-vault', 'This account has no vault in the cloud yet. Open Silk on your phone and sync first.');
  const vault = await getObject(session, 'vault.skln');
  if (!vault) throw new VaultError('no-vault', 'The cloud vault isn’t complete yet. Sync once more in the app, then try again.');
  const bytes = joinBackup(slot, vault);
  await saveSignIn({ ...session, email: session.email || email });
  return { bytes, uid: session.uid };
}

// ------------------------------------------------------------------ sync

const same = (a, b) => !!a && !!b && a.length === b.length && a.every((v, i) => v === b[i]);

function revisionOfFile(file) {
  try {
    return parseSkln(file).revision;
  } catch {
    throw new VaultError('corrupt', 'The cloud vault file is damaged.');
  }
}

/**
 * The app's sync rule (core/src/sync.rs) for this browser's vault and the cloud's: the higher authenticated
 * revision wins. `mode` is 'sync' (may download a newer cloud copy) or 'push' (after a save: upload only).
 * Returns { report }: 'off', 'signed-out', 'upToDate', 'uploaded', 'downloaded' (the stored vault was
 * replaced: reopen it), 'cloudNewer' (a push found the cloud ahead), 'conflict' (same revision, different
 * files: nothing is copied, the next save here gets the next revision and wins) or 'unlinked' (this vault
 * came from a file, not from the account: nothing is copied, signing in again replaces it with the cloud's).
 */
export function syncNow(mode = 'sync') {
  return exclusive(async () => {
    if (!CLOUD) return { report: 'off' };
    if (!(await cloudSession())) return { report: 'signed-out' };
    const stored = await loadVault();
    if (!stored) return { report: 'upToDate' };
    const session = await freshSession();
    const cloudSlot = await getObject(session, 'keyslot.skvk');
    const cloudFile = await getObject(session, 'vault.skln');
    // A vault file without a key slot can't be opened by anyone. Never build on it.
    if (!cloudSlot && cloudFile) throw new VaultError('corrupt', 'The cloud copy has a vault file but no key slot.');
    const { slot, vault } = stored.header;
    const upload = async () => {
      // Key slot first (and only if it differs), then the vault file.
      if (!same(cloudSlot, slot)) await putObject(session, 'keyslot.skvk', slot, !!cloudSlot);
      await putObject(session, 'vault.skln', vault, !!cloudFile);
    };
    const link = () => local.set({ linkedUid: session.uid });
    const finish = async (report) => {
      await local.set({ lastSync: Date.now() });
      return { report };
    };

    if (!cloudSlot) {
      await upload();
      await link();
      return finish('uploaded');
    }
    const identical = same(cloudSlot, slot) && same(cloudFile, vault);
    if ((await local.get('linkedUid')).linkedUid !== session.uid) {
      if (!identical) return finish('unlinked');
      await link();
      return finish('upToDate');
    }
    const ours = revisionOfFile(vault);
    const theirs = cloudFile ? revisionOfFile(cloudFile) : 0n;
    if (theirs > ours) {
      if (mode === 'push') return finish('cloudNewer');
      await storeVault(joinBackup(cloudSlot, cloudFile), undefined, { deliberate: false });
      return finish('downloaded');
    }
    if (theirs < ours) {
      await upload();
      return finish('uploaded');
    }
    return finish(identical ? 'upToDate' : 'conflict');
  });
}
