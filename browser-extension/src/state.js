// What the extension keeps, shared by the popup and the service worker (either may be awake).
//
// chrome.storage.local (on disk)
//   vault, vaultName   the encrypted backup (key slot + vault file), as base64
//   seen               the highest vault revision this browser has opened (rollback guard, see below)
//   linkedUid          the cloud account this vault was downloaded from or synced with ('' = none)
//   kept               the VEK sealed by the device key (src/device.js): present while "keep me unlocked" is on
//   cloud, lastSync    the cloud sign-in and when it last synced (src/cloud.js)
//   prefs              generator options and the unlock preference; nothing secret
// chrome.storage.session (memory only, gone when the browser closes)
//   unlocked           the decrypted entries and the VEK while the vault is open; `until` is the idle
//                      deadline, or 0 when the vault stays open until Lock
//
// Everything that changes the stored vault runs inside `exclusive`, so the popup and the worker
// never write over each other.
import { parseHeader, revisionOf, openWithVek, sealVault, toBase64, fromBase64, VaultError } from './vault.js';
import { DEFAULTS as GENERATOR_DEFAULTS, normalize } from './generator.js';
import * as device from './device.js';

const IDLE_MS = 5 * 60 * 1000; // same idle limit as the app, used when the vault is not kept open
const local = chrome.storage.local;
const session = chrome.storage.session;

export const exclusive = (fn) => navigator.locks.request('silk-vault', fn);

// ------------------------------------------------------------------ the stored vault

/** The stored backup as { bytes, header, name }, or null when there is none or it can't be read. */
export async function loadVault() {
  const { vault, vaultName } = await local.get(['vault', 'vaultName']);
  if (!vault) return null;
  try {
    const bytes = fromBase64(vault);
    return { bytes, header: parseHeader(bytes), name: vaultName || 'vault' };
  } catch {
    return null;
  }
}

async function seenRevision() {
  const { seen } = await local.get('seen');
  try {
    return BigInt(seen ?? 0);
  } catch {
    return 0n;
  }
}

/** Same rule as the app (Error::Rollback): a vault older than one already opened is refused. */
async function checkRevision(revision) {
  if (revision < (await seenRevision())) {
    throw new VaultError('rollback', 'This vault is older than one this browser has already opened. If you restored an older backup on purpose, choose that backup file again.');
  }
}

async function noteRevision(revision) {
  if (revision > (await seenRevision())) await local.set({ seen: revision.toString() });
}

/**
 * Replaces the stored vault. `deliberate` is the user choosing it (a backup file, a fresh sign-in): that is
 * the one way back to an older vault, so it clears the rollback mark, the kept key and the open session,
 * and sets the cloud link to `uid` ('' for a file). Otherwise (a sync download) the rollback guard applies.
 */
export async function storeVault(bytes, name, { deliberate = false, uid = '' } = {}) {
  const header = parseHeader(bytes);
  const revision = revisionOf(header);
  if (deliberate) {
    await local.remove(['seen']);
    await forgetKept();
    await session.remove('unlocked');
    chrome.alarms.clear('silk-lock');
    await local.set({ linkedUid: uid });
  } else {
    await checkRevision(revision);
  }
  await local.set({ vault: toBase64(bytes), ...(name ? { vaultName: name } : {}) });
  await noteRevision(revision);
  return header;
}

// ------------------------------------------------------------------ the open vault

async function forgetKept() {
  await local.remove('kept');
  await device.forget('vault');
}

/** The open vault as { entries, vek, until }, or null. A session past its idle deadline is dropped. */
async function loadSession() {
  const { unlocked } = await session.get('unlocked');
  if (!unlocked) return null;
  if (unlocked.until && unlocked.until <= Date.now()) {
    await session.remove('unlocked');
    return null;
  }
  return { entries: unlocked.entries, vek: fromBase64(unlocked.vek), until: unlocked.until || 0 };
}

function setIdle(keep) {
  if (keep) {
    chrome.alarms.clear('silk-lock');
    return 0;
  }
  const until = Date.now() + IDLE_MS;
  chrome.alarms.create('silk-lock', { when: until });
  return until;
}

/**
 * Opens the vault for use after an unlock with the master password. With `keep` the VEK is also sealed
 * by the device key, so the next open (even after a browser restart) needs no password; without it
 * the vault locks itself after five idle minutes, as before.
 */
export async function startSession(entries, vek, keep, revision) {
  await checkRevision(revision);
  await noteRevision(revision);
  if (keep) await local.set({ kept: await device.seal('vault', vek) });
  else await forgetKept();
  await session.set({ unlocked: { entries, vek: toBase64(vek), until: setIdle(keep) } });
}

/** Opens the vault from the sealed VEK, if there is one. A VEK that no longer fits the vault is forgotten. */
async function openKept() {
  const [{ kept }, vault] = await Promise.all([local.get('kept'), loadVault()]);
  if (!kept || !vault) return null;
  const vek = await device.unseal('vault', kept);
  if (!vek) {
    await forgetKept();
    return null;
  }
  try {
    const opened = await openWithVek(vault.bytes, vek);
    await checkRevision(opened.revision);
    await noteRevision(opened.revision);
    await session.set({ unlocked: { entries: opened.entries, vek: toBase64(vek), until: 0 } });
    return { entries: opened.entries, vek, until: 0 };
  } catch {
    await forgetKept();
    return null;
  }
}

/** The open vault, opening it from the sealed VEK when the session is empty (a new browser run). Null means the master password is needed. */
export async function ensureUnlocked() {
  return (await loadSession()) || openKept();
}

/** Counts as use: pushes the idle deadline back. Does nothing while the vault is kept open. */
export async function touchSession() {
  const { unlocked } = await session.get('unlocked');
  if (!unlocked || !unlocked.until) return;
  await session.set({ unlocked: { ...unlocked, until: setIdle(false) } });
}

/** Locks: wipes the open vault and forgets the sealed VEK, so the master password is needed next time. The cloud sign-in stays. */
export async function lockAll() {
  await session.remove('unlocked');
  chrome.alarms.clear('silk-lock');
  await forgetKept();
}

/** Switches between "kept open until Lock" and the five-minute idle lock, for the vault that is open now. */
export async function setKeep(keep) {
  const open = await loadSession();
  if (!open) return;
  if (keep) await local.set({ kept: await device.seal('vault', open.vek) });
  else await forgetKept();
  const { unlocked } = await session.get('unlocked');
  await session.set({ unlocked: { ...unlocked, until: setIdle(keep) } });
}

/** Saves `entries` as the next revision: the backup in storage and the open session. Returns the new revision. Call inside `exclusive`. */
export async function saveEntries(entries) {
  const [vault, open] = await Promise.all([loadVault(), loadSession()]);
  if (!vault || !open) throw new VaultError('locked', 'Unlock the vault first.');
  const current = await openWithVek(vault.bytes, open.vek); // the revision to build on, and any other bundle members
  const sealed = await sealVault(vault.bytes, open.vek, entries, current.extras, current.revision);
  await local.set({ vault: toBase64(sealed.file) });
  await noteRevision(sealed.revision);
  const { unlocked } = await session.get('unlocked');
  await session.set({ unlocked: { ...unlocked, entries } });
  return sealed.revision;
}

/** After the stored vault was replaced by a newer copy: reads the entries again with the VEK that is in use. Null (and locked) if it no longer fits. */
export async function reopenSession() {
  const [vault, open] = await Promise.all([loadVault(), loadSession()]);
  if (!vault || !open) return null;
  try {
    const opened = await openWithVek(vault.bytes, open.vek);
    const { unlocked } = await session.get('unlocked');
    await session.set({ unlocked: { ...unlocked, entries: opened.entries } });
    return opened.entries;
  } catch {
    await lockAll();
    return null;
  }
}

// ------------------------------------------------------------------ preferences

/** Settings that hold nothing secret: generator options, whether to keep the vault open, a dismissed tip. */
export async function loadPrefs() {
  const { prefs } = await local.get('prefs');
  const p = prefs || {};
  return { keep: p.keep !== false, tipDismissed: p.tipDismissed === true, gen: normalize({ ...GENERATOR_DEFAULTS, ...p.gen }) };
}

export async function savePrefs(change) {
  await local.set({ prefs: { ...(await loadPrefs()), ...change } });
}
