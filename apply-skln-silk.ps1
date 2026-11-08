$ErrorActionPreference = 'Stop'
$root = (Get-Location).Path
if (-not (Test-Path -LiteralPath (Join-Path $root 'core\Cargo.toml'))) { throw 'Run this from the silk-rust project root (the folder that contains core/Cargo.toml).' }
$utf8 = New-Object System.Text.UTF8Encoding($false)
$writes = New-Object System.Collections.Generic.List[object]
$uni = [System.Text.RegularExpressions.MatchEvaluator]{ param($m) [string][char][Convert]::ToInt32($m.Groups[1].Value, 16) }
function Lf([string]$t) { [regex]::Replace(($t -replace "`r`n", "`n"), '\{\{U\+([0-9A-F]{4})\}\}', $uni) }
function Edit-File([string]$rel, [object[]]$pairs) {
  $path = Join-Path $root $rel
  if (-not (Test-Path -LiteralPath $path)) { throw "$rel is missing" }
  $raw = [IO.File]::ReadAllText($path)
  $crlf = $raw.Contains("`r`n")
  $s = Lf $raw
  for ($i = 0; $i -lt $pairs.Count; $i += 2) {
    $old = Lf $pairs[$i]; $new = Lf $pairs[$i + 1]
    $n = ([regex]::Matches($s, [regex]::Escape($old))).Count
    if ($n -ne 1) { throw "$rel : an anchor matched $n times (expected 1): $($old.Substring(0, [Math]::Min(70, $old.Length)))" }
    $s = $s.Replace($old, $new)
  }
  if ($crlf) { $s = $s -replace "`n", "`r`n" }
  $writes.Add(@{ Path = $path; Text = $s; Bytes = $null })
}
function New-TextFile([string]$rel, [string]$text) {
  $path = Join-Path $root $rel
  if (Test-Path -LiteralPath $path) { throw "$rel already exists" }
  $writes.Add(@{ Path = $path; Text = ((Lf $text) + "`n"); Bytes = $null })
}
function New-BinFile([string]$rel, [string]$b64) {
  $path = Join-Path $root $rel
  if (Test-Path -LiteralPath $path) { throw "$rel already exists" }
  $writes.Add(@{ Path = $path; Text = $null; Bytes = [Convert]::FromBase64String(($b64 -replace '\s', '')) })
}
Edit-File 'CLAUDE.md' @(
@'
  Storage keeps the two encrypted files. `SUPABASE_URL` and `SUPABASE_PUBLISHABLE_KEY` come from the
  environment or `android/local.properties`. See `docs/ARCHITECTURE.md`, "Setting up the cloud".
- The `.skln` container (Kiln's encryption engine) comes after Kiln's security update; `core/src/interim.rs`
  stands in behind the `Archiver` trait until then.

'@
@'
  Storage keeps the two encrypted files. `SUPABASE_URL` and `SUPABASE_PUBLISHABLE_KEY` come from the
  environment or `android/local.properties`. See `docs/ARCHITECTURE.md`, "Setting up the cloud".
- The vault file is Kiln's `.skln` (the `kiln-skln` crate, `core/src/skln.rs`). `core/src/interim.rs` is the
  older stand-in format, kept read-only so existing vaults convert on unlock. Encrypting the `.key` file
  inside a `.skln` still waits for Kiln's security update.

'@
)
Edit-File 'README.md' @(
@'
The master password derives a key that protects the VEK. The VEK then encrypts the vault archive.

In the planned final architecture, the archive will use Kiln's `.skln` format. Kiln is a separate project, and `.skln` support is not implemented in Kiln yet.

For now, `core/src/interim.rs` provides the temporary archive implementation behind the `Archiver` trait. This allows Silk to use the future archive interface without depending on the unfinished `.skln` format.

The architecture diagram, file formats, key file layout, `.skln` requirements, and remaining implementation tasks are documented in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

### Building Silk
'@
@'
The master password derives a key that protects the VEK. The VEK then encrypts the vault archive.

The vault archive uses Kiln's `.skln` format, through the `kiln-skln` crate from the separate Kiln project. `core/src/skln.rs` connects it to the `Archiver` trait. Vault files of the older stand-in format (`core/src/interim.rs`) are still opened and are rewritten as `.skln` the first time they are unlocked.

The architecture diagram, file formats, key file layout, `.skln` details, and remaining implementation tasks are documented in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

### Building Silk
'@
)
Edit-File 'docs/ARCHITECTURE.md' @(
@'
| **Silk** | This app: the password manager, formerly called PassVault. Master-password entry, unlock/save, the unlocked state in memory. | this repository |
| **Kiln** | A separate project: a multicore archiver (Rust engine + Android app) with its own container format. Today it writes `.kiln` v2 archives (you call them `.kln`; in Kiln's own docs `.kln` is the original Python app's format). | `kiln-rust` repository |
| **`.skln`** | A new Kiln archive type, **not written yet**: the encrypted archive that holds Silk's entries, keyed by the VEK. | to be added to Kiln |
| **VEK** | Vault Encryption Key: 256 random bits, generated once at first-time setup. Encrypts the `.skln`. | in memory only; stored wrapped |
| **Key** | The Argon2id output (the diagram's "key"; KEK in code comments). Only ever wraps the VEK. | derived on demand, never stored |
| **Key slot** | The VEK encrypted by the key, plus the Argon2id settings and salt needed to re-derive it. 91 bytes. | `core/src/keyslot.rs` |
| **`Archiver`** | The seam between Silk and Kiln: a small trait for "seal entries with the VEK / open them again". | `core/src/archive.rs` |
| **Interim archiver** | A stand-in implementation of `Archiver` so the cloud flow can be built and tested before `.skln` exists. **Not the `.skln` format**: different magic (`SKIM`) and object name (`vault.interim`). | `core/src/interim.rs` |
| **Local store** | The on-device copy of the key slot and vault file in the app's private folder. It implements `RemoteStore`, so unlocking from the local copy runs the same flow as unlocking from the cloud does. Also holds the rollback mark. | `core/src/local.rs` |
| **Session** | The unlocked state the app holds (VEK + entries), idle lock, saves to the local store, backup and restore. | `core/src/session.rs` |
'@
@'
| **Silk** | This app: the password manager, formerly called PassVault. Master-password entry, unlock/save, the unlocked state in memory. | this repository |
| **Kiln** | A separate project: a multicore archiver (Rust engine + Android app) with its own container format. Today it writes `.kiln` v2 archives (you call them `.kln`; in Kiln's own docs `.kln` is the original Python app's format). | `kiln-rust` repository |
| **`.skln`** | Kiln's container for encrypted data (the `kiln-skln` crate, format in Kiln's `docs/FORMAT.md`). Silk stores its entries in one, keyed by the VEK, as `vault.skln`. | Kiln: `skln/`; Silk: `core/src/skln.rs` |
| **VEK** | Vault Encryption Key: 256 random bits, generated once at first-time setup. Encrypts the `.skln`. | in memory only; stored wrapped |
| **Key** | The Argon2id output (the diagram's "key"; KEK in code comments). Only ever wraps the VEK. | derived on demand, never stored |
| **Key slot** | The VEK encrypted by the key, plus the Argon2id settings and salt needed to re-derive it. 91 bytes. | `core/src/keyslot.rs` |
| **`Archiver`** | The seam between Silk and Kiln: a small trait for "seal entries with the VEK / open them again". | `core/src/archive.rs` |
| **Interim archive** | The stand-in that was used before `.skln` existed. **Not the `.skln` format**: different magic (`SKIM`) and object name (`vault.interim`). Read-only now: such a file still opens and is rewritten as `.skln` on unlock. | `core/src/interim.rs` |
| **Local store** | The on-device copy of the key slot and vault file in the app's private folder. It implements `RemoteStore`, so unlocking from the local copy runs the same flow as unlocking from the cloud does. Also holds the rollback mark. | `core/src/local.rs` |
| **Session** | The unlocked state the app holds (VEK + entries), idle lock, saves to the local store, backup and restore. | `core/src/session.rs` |
'@
@'
7. **The browser extension reads the vault in JavaScript today.** If it should open `.skln`, the format needs a JS reader too (Kiln has none), so a simple, well-specified container is worth it.

Once `.skln` exists: write `impl Archiver for <Kiln adapter>` and change `archive::Current`. Nothing in `cloud.rs`, `keyslot.rs` or `remote.rs` should need to change. Keep `interim.rs` as a read-only source: devices will by then hold real vaults in the interim format (see Known limits), and they need converting to `.skln` on unlock.

## Formats

All integers are big-endian.

```
'@
@'
7. **The browser extension reads the vault in JavaScript today.** If it should open `.skln`, the format needs a JS reader too (Kiln has none), so a simple, well-specified container is worth it.

**Status: built.** Kiln has a separate crate, `kiln-skln` (`skln/` in the Kiln repository, edition 2021, depending on `chacha20poly1305`, `hkdf`, `sha2`, `getrandom` and `zeroize`), with the raw-key seal and open, the authenticated revision in the plain header and the member bundle Silk keeps its entries in. Points 1 to 4 and 7 are met by it and by `browser-extension/src/skln.js`. Point 5 did not arise: the crate is edition 2021 and Silk's CI uses the stable toolchain. Point 6: the vault file is ChaCha20-Poly1305 and the key slot stays AES-256-GCM. `core/src/skln.rs` is the `Archiver` for it and `archive::Current` points at it; nothing in `cloud.rs`, `keyslot.rs` or `remote.rs` changed. `interim.rs` stays as a read-only source: a device that holds a vault in the interim format opens it and rewrites it as `.skln` on the first unlock (see Known limits).

## Formats

All integers are big-endian, except inside a `.skln`, which is little-endian like the rest of Kiln's formats.

```
'@
@'
          first 31 bytes are the associated data; total 91 bytes

interim   "SKIM" | version u8 | flags u8 | revision u64 | nonce[12] | AES-256-GCM(archive) + tag[16]       (stand-in, see above)
archive   count u32 | { name_len u16 | name | data_len u32 | data }*
          one member today: "vault.json" = {"entries":[...]}  (same entry shape as the old vault)

backup    "SKBK" | version u8 | key slot[91] | vault file (the rest)
'@
@'
          first 31 bytes are the associated data; total 91 bytes

skln      "\x89SKLN\r\n\x1a" | version u8 (1) | flags u8 | kind u8 (1 = bundle) | chunk_log2 u8 | revision u64 | salt[16]   (36 bytes)
          then records: len u32 | ChaCha20-Poly1305(chunk) + tag[16]. The file key is HKDF-SHA256(VEK, salt); the header is
          authenticated, so the revision cannot be changed unnoticed. Full layout: Kiln's docs/FORMAT.md
bundle    (the payload of a .skln, little-endian) count u32 | { name_len u16 | name | data_len u32 | data }*
          one member: "vault.json" = {"entries":[...]}  (same entry shape as the old vault)

interim   "SKIM" | version u8 | flags u8 | revision u64 | nonce[12] | AES-256-GCM(archive) + tag[16]       (read-only, see above)
archive   (inside a SKIM file, big-endian) count u32 | { name_len u16 | name | data_len u32 | data }*

backup    "SKBK" | version u8 | key slot[91] | vault file (the rest)
'@
@'
```

The browser extension reads the backup (`browser-extension/src/vault.js`) and, as before, old `.pvlt` files. Its vault-file part follows the interim format, so it changes together with `interim.rs`.

Key derivation is unchanged from the old vault: `SHA-256(password)`, mixed with `SHA-256(key file material)` when a key file is used, then Argon2id (t=3, 64 MiB, p=4 by default) to 32 bytes. The material of a Silk key file is its 64-byte secret; the material of any other file is the whole file. Existing key files keep working.
'@
@'
```

The browser extension reads the backup (`browser-extension/src/vault.js`) and, as before, old `.pvlt` files. It opens both kinds of vault file inside a backup: `.skln` (`src/skln.js`; `src/chacha.js` carries its own ChaCha20-Poly1305 because WebCrypto has none) and the interim `SKIM` kind of older backups.

Key derivation is unchanged from the old vault: `SHA-256(password)`, mixed with `SHA-256(key file material)` when a key file is used, then Argon2id (t=3, 64 MiB, p=4 by default) to 32 bytes. The material of a Silk key file is its 64-byte secret; the material of any other file is the whole file. Existing key files keep working.
'@
@'
```
keyslot.skvk     the key slot
vault.interim    the vault file (vault.skln later)
vault.pvlt       an old vault, only until the first unlock converts it
seen.rev         highest vault revision this device has seen
'@
@'
```
keyslot.skvk     the key slot
vault.skln       the vault file (Kiln's .skln)
vault.interim    a vault file from before .skln: read when there is no vault.skln, removed when the next save writes one
vault.pvlt       an old vault, only until the first unlock converts it
seen.rev         highest vault revision this device has seen
'@
@'
```
silk-vaults/vaults/<user id>/keyslot.skvk
silk-vaults/vaults/<user id>/vault.skln        (vault.interim while the stand-in is in use)
```

'@
@'
```
silk-vaults/vaults/<user id>/keyslot.skvk
silk-vaults/vaults/<user id>/vault.skln
```

'@
@'
- **Cloud sync is optional.** Without the Supabase values (`android/local.properties`) the app stays fully offline (it still declares `INTERNET`, but `Net.java` only accepts HTTPS to the one configured Supabase host, and nothing else).
- **The sign-in in the key file is not encrypted yet** (see "The key file").
- **Real vaults are now written in the interim format** (`vault.interim`, magic `SKIM`). When `.skln` arrives, `interim.rs` cannot simply be deleted: it has to stay as a read-only source so existing vaults can be converted to `.skln` on unlock (the two have different file names, so telling them apart is easy). The same goes for the backup bundle, which embeds whichever vault file is current.

## The PassVault to Silk rename
'@
@'
- **Cloud sync is optional.** Without the Supabase values (`android/local.properties`) the app stays fully offline (it still declares `INTERNET`, but `Net.java` only accepts HTTPS to the one configured Supabase host, and nothing else).
- **The sign-in in the key file is not encrypted yet** (see "The key file").
- **Vaults written before `.skln` are converted on unlock.** A device that holds `vault.interim` (magic `SKIM`) opens it through `interim.rs`, which is now read-only, and the first unlock saves it again as `vault.skln` with the next revision, so the rollback mark stays valid, then removes `vault.interim`. A backup that embeds an interim vault file still restores and still opens in the extension. The cloud only accepts `vault.skln` now (the Storage policies no longer list `vault.interim`), so an interim copy left in a bucket is not read; sync has not been run against the live project yet (task 17).

## The PassVault to Silk rename
'@
@'
| 4 | `CloudVault` flow: setup, unlock, save, change password, legacy `.pvlt` migration, VEK export for biometrics, `RemoteStore` trait (`cloud.rs`, `remote.rs`) | done |
| 5 | Cloud layout and access policies (`supabase/storage-policies.sql`) | done on paper; policies not yet run against the live project |
| 6 | **Kiln repo (yours):** add `.skln` with the contract above | todo |
| 7 | Add a Kiln-backed `Archiver`, switch `archive::Current`, convert interim vaults to `.skln` on unlock (keep `interim.rs` as the reader); move Silk's CI toolchain if needed | todo, after 6 |
| 8 | Session uses `CloudVault`: local copy of key slot + vault file in private storage (offline unlock), migrate `vault.pvlt` on first unlock (`local.rs`, `session.rs`, `backup.rs`) | done, untested on a device |
| 9 | Cloud transport: Supabase Auth (`auth.rs`) and Supabase Storage (`supabase.rs`, a `RemoteStore`) over an `Http` trait, carried by the Java glue (`Net.java`); `INTERNET` permission; project config (`local.properties`) | done with mocked tests; **not yet run against the live project** (do task 17), untested on a device |
'@
@'
| 4 | `CloudVault` flow: setup, unlock, save, change password, legacy `.pvlt` migration, VEK export for biometrics, `RemoteStore` trait (`cloud.rs`, `remote.rs`) | done |
| 5 | Cloud layout and access policies (`supabase/storage-policies.sql`) | done on paper; policies not yet run against the live project |
| 6 | **Kiln repo (yours):** add `.skln` with the contract above | done: the `kiln-skln` crate (raw-key seal/open, member bundle, golden files written by an independent Python implementation) |
| 7 | Add a Kiln-backed `Archiver`, switch `archive::Current`, convert interim vaults to `.skln` on unlock (keep `interim.rs` as the reader) | done (`skln.rs`, `session.rs`, `local.rs`); not compiled by the author: run `cargo test -p silk-core` |
| 8 | Session uses `CloudVault`: local copy of key slot + vault file in private storage (offline unlock), migrate `vault.pvlt` on first unlock (`local.rs`, `session.rs`, `backup.rs`) | done, untested on a device |
| 9 | Cloud transport: Supabase Auth (`auth.rs`) and Supabase Storage (`supabase.rs`, a `RemoteStore`) over an `Http` trait, carried by the Java glue (`Net.java`); `INTERNET` permission; project config (`local.properties`) | done with mocked tests; **not yet run against the live project** (do task 17), untested on a device |
'@
@'
| 11 | Sync safety: rollback detection from the revision, conflict handling (`sync.rs`: unrelated vaults and same-revision saves are never overwritten silently), VEK rotation with an atomic commit | partly: rollback guard and conflict handling done; rotation todo |
| 12 | UI: first-time setup vs unlock, sync status, change password, migration prompt | partly: setup/unlock, a migration notice and the Cloud sync screens (sign in, sync status, Sync now, keep-or-use choice) exist; change password todo |
| 13 | Browser extension reads key slot + vault file | done for the interim format and old `.pvlt`; `.skln` reader todo, after 6 |
| 14 | The deeper PassVault to Silk rename (package, crates, library) | done, see above |
| 15 | Silk key file (`SKEY`) and automatic saving of the cloud sign-in in it (`keyfile.rs`, `ui.rs`, `SilkActivity.saveKeyFile`) | done, untested on a device |
'@
@'
| 11 | Sync safety: rollback detection from the revision, conflict handling (`sync.rs`: unrelated vaults and same-revision saves are never overwritten silently), VEK rotation with an atomic commit | partly: rollback guard and conflict handling done; rotation todo |
| 12 | UI: first-time setup vs unlock, sync status, change password, migration prompt | partly: setup/unlock, a migration notice and the Cloud sync screens (sign in, sync status, Sync now, keep-or-use choice) exist; change password todo |
| 13 | Browser extension reads key slot + vault file | done: `.skln`, the interim format and old `.pvlt` (`node --test` in `browser-extension/`) |
| 14 | The deeper PassVault to Silk rename (package, crates, library) | done, see above |
| 15 | Silk key file (`SKEY`) and automatic saving of the cloud sign-in in it (`keyfile.rs`, `ui.rs`, `SilkActivity.saveKeyFile`) | done, untested on a device |
'@
)
Edit-File 'browser-extension/src/vault.js' @(
@'
// 1. A Silk backup (core/src/backup.rs, the current kind): "SKBK" | version | key slot[91] | vault file.
//    The key slot (core/src/keyslot.rs) is the random VEK encrypted with the Argon2id key; the vault
//    file (core/src/interim.rs, a stand-in until Kiln's .skln exists) is the entries encrypted with
//    the VEK. So: Argon2id key -> unwrap VEK -> decrypt the vault file -> read the archive.
//      key slot   "SKVK" | version | flags | t u32 | memKiB u32 | p u8 | salt[16] | nonce[12] | AES-GCM(VEK) + tag
//                 (the first 31 bytes are the associated data)
//      vault file "SKIM" | version | flags | revision u64 | nonce[12] | AES-GCM(archive) + tag
//                 (the first 14 bytes are the associated data)
//      archive    count u32 | { name_len u16 | name | data_len u32 | data }*, entries in "vault.json"
//    When .skln replaces the stand-in, only the vault-file part of this changes.
//
// 2. An old vault file (core/src/vault.rs, kept so old backups still open): "PVLT" | version | flags |
'@
@'
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
'@
@'
// In both, the key is Argon2id( SHA-256(password) [then SHA-256(that || SHA-256(key file))] ) with the salt.
import { argon2, TYPES } from './argon2.js';

const HEADER_LEN = 31;
'@
@'
// In both, the key is Argon2id( SHA-256(password) [then SHA-256(that || SHA-256(key file))] ) with the salt.
import { argon2, TYPES } from './argon2.js';
import { isSkln, openSkln, unpackBundle, KIND_BUNDLE } from './skln.js';

const HEADER_LEN = 31;
'@
@'
  const slot = f.subarray(BUNDLE_HEADER, BUNDLE_HEADER + SLOT_LEN);
  const vault = f.subarray(BUNDLE_HEADER + SLOT_LEN);
  if (!hasMagic(slot, MAGIC_SLOT) || slot[4] !== 1 || !hasMagic(vault, MAGIC_VAULT) || vault[4] !== 1) {
    throw new VaultError('not-a-vault', "This isn't a Silk file.");
  }
'@
@'
  const slot = f.subarray(BUNDLE_HEADER, BUNDLE_HEADER + SLOT_LEN);
  const vault = f.subarray(BUNDLE_HEADER + SLOT_LEN);
  const vaultOk = isSkln(vault) ? vault[8] === 1 : hasMagic(vault, MAGIC_VAULT) && vault[4] === 1;
  if (!hasMagic(slot, MAGIC_SLOT) || slot[4] !== 1 || !vaultOk) {
    throw new VaultError('not-a-vault', "This isn't a Silk file.");
  }
'@
@'
  // The vault file: with the right VEK this only fails if the file was changed.
  let plain;
  try {
    plain = await decryptGcm(vek, vault.subarray(VAULT_AAD, VAULT_AAD + NONCE_LEN), vault.subarray(0, VAULT_AAD), vault.subarray(VAULT_AAD + NONCE_LEN));
  } catch {
    throw damaged();
  } finally {
    vek.fill(0);
  }
  const member = unpack(plain).get('vault.json');
  if (!member) throw damaged();
  const doc = parseDoc(member);
'@
@'
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
'@
)
Edit-File 'browser-extension/test/helpers.js' @(
@'
// Builds vault files exactly the way the app does (core/src/vault.rs for old files, core/src/backup.rs +
// keyslot.rs + interim.rs for backups), so the extension can be tested without the app.
import { argon2, TYPES } from '../src/argon2.js';

'@
@'
// Builds vault files exactly the way the app does (core/src/vault.rs for old files, core/src/backup.rs +
// keyslot.rs + skln.rs for backups, interim.rs for backups from before .skln), so the extension can be
// tested without the app. The .skln sealing here uses node:crypto, not src/chacha.js, so the two are
// independent of each other.
import { createCipheriv, hkdfSync } from 'node:crypto';
import { argon2, TYPES } from '../src/argon2.js';

'@
@'
}

/** A Silk backup: "SKBK" | 1 | key slot[91] | vault file. The VEK is random; the Argon2id key only wraps it. */
export async function sealBundle(entries, password, keyFile, kdf = { t: 1, m: 64, p: 1 }, revision = 1) {
  const sha = async (b) => new Uint8Array(await crypto.subtle.digest('SHA-256', b));
  const gcm = async (key, iv, aad, data) => {
'@
@'
}

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
 * `format` is 'skln' (what the app writes now) or 'interim' (the stand-in "SKIM" file of older backups).
 */
export async function sealBundle(entries, password, keyFile, kdf = { t: 1, m: 64, p: 1 }, revision = 1, format = 'skln', chunkLog2 = 20) {
  const sha = async (b) => new Uint8Array(await crypto.subtle.digest('SHA-256', b));
  const gcm = async (key, iv, aad, data) => {
'@
@'
  const slot = concat(slotHeader, slotNonce, await gcm(kek, slotNonce, slotHeader, vek));

  // archive with one member, then the vault file
  const name = new TextEncoder().encode('vault.json');
'@
@'
  const slot = concat(slotHeader, slotNonce, await gcm(kek, slotNonce, slotHeader, vek));

  const body0 = new TextEncoder().encode(JSON.stringify({ entries }));
  if (format === 'skln') {
    const vault = sealSkln(vek, [['vault.json', body0]], revision, chunkLog2);
    return concat(new Uint8Array([0x53, 0x4b, 0x42, 0x4b, 1]), slot, vault);
  }

  // archive with one member, then the vault file
  const name = new TextEncoder().encode('vault.json');
'@
)
Edit-File 'browser-extension/test/vault.test.js' @(
@'
});

// RFC 6238 appendix B vectors (8 digits). The seeds are the ASCII strings "1234567890" repeated to 20, 32 and 64 bytes.
const b32 = (str) => {
'@
@'
});

test('still opens a Silk backup whose vault file is the stand-in "SKIM" kind', async () => {
  const kf = new Uint8Array(64).fill(7);
  const old = await sealBundle([entry], 'correct horse', kf, undefined, 5, 'interim');
  assert.equal(parseHeader(old).kind, 'silk');
  assert.equal(old[5 + 91], 0x53); // "SKIM", not the .skln magic
  const back = await openVault(old, 'correct horse', kf);
  assert.equal(back[0].title, 'GitHub');
  await assert.rejects(openVault(old, 'wrong', kf), { code: 'wrong-credentials' });
});

test('opens a .skln vault that spans many records', async () => {
  const many = Array.from({ length: 200 }, (_, i) => ({ ...entry, id: String(i), title: `Site ${i}`, notes: 'n'.repeat(150) }));
  const b = await sealBundle(many, 'password1', null, undefined, 9, 'skln', 12);
  const vault = b.subarray(5 + 91);
  assert.ok(vault.length > 5 * 4096, 'more than a few 4 KiB records');
  const back = await openVault(b, 'password1', null);
  assert.equal(back.length, 200);
  assert.equal(back[199].title, 'Site 199');
  assert.equal(back[0].notes.length, 150);
});

test('rejects a damaged .skln vault file', async () => {
  const many = Array.from({ length: 100 }, (_, i) => ({ ...entry, id: String(i), notes: 'n'.repeat(150) }));
  const b = await sealBundle(many, 'password1', null, undefined, 3, 'skln', 12);
  const at = 5 + 91; // where the .skln starts
  const record = 4 + 4096 + 16; // a full record with chunk_log2 = 12
  const flip = (offset) => {
    const c = b.slice();
    c[offset] ^= 1;
    return c;
  };
  const damaged = { code: 'corrupt' };
  await assert.rejects(openVault(flip(at + 9), 'password1', null), damaged); // flags
  await assert.rejects(openVault(flip(at + 11), 'password1', null), damaged); // chunk_log2
  await assert.rejects(openVault(flip(at + 13), 'password1', null), damaged); // revision
  await assert.rejects(openVault(flip(at + 20), 'password1', null), damaged); // salt
  await assert.rejects(openVault(flip(at + 36), 'password1', null), damaged); // a record length
  await assert.rejects(openVault(flip(at + 36 + 4 + 7), 'password1', null), damaged); // ciphertext
  await assert.rejects(openVault(flip(b.length - 1), 'password1', null), damaged); // last tag
  await assert.rejects(openVault(b.slice(0, b.length - 1), 'password1', null), damaged); // cut short
  await assert.rejects(openVault(b.slice(0, at + 36 + record), 'password1', null), damaged); // cut at a record boundary
  await assert.rejects(openVault(b.slice(0, at + 36 + 10), 'password1', null), damaged); // cut inside the first record
  await assert.rejects(openVault(Uint8Array.from([...b, 0]), 'password1', null), damaged); // appended byte
  const swapped = b.slice();
  swapped.set(b.subarray(at + 36, at + 36 + record), at + 36 + record);
  swapped.set(b.subarray(at + 36 + record, at + 36 + 2 * record), at + 36);
  await assert.rejects(openVault(swapped, 'password1', null), damaged); // two records swapped
  assert.equal((await openVault(b, 'password1', null)).length, 100); // the original is fine
});

// RFC 6238 appendix B vectors (8 digits). The seeds are the ASCII strings "1234567890" repeated to 20, 32 and 64 bytes.
const b32 = (str) => {
'@
)
Edit-File 'core/Cargo.toml' @(
@'
getrandom = "0.2"
hmac = "0.12"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
'@
@'
getrandom = "0.2"
hmac = "0.12"
kiln-skln = { git = "https://github.com/prokylebrandon2/kiln-rust", branch = "main" }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
'@
)
Edit-File 'core/src/archive.rs' @(
@'
//! The archive layer: what turns the entries into the encrypted vault file stored next to the key slot.
//!
//! The intended archive is Kiln's `.skln` (Kiln is a separate project; `.skln` is not in it yet).
//! Until it is, [`crate::interim`] stands in so the rest of the cloud flow can be built and
//! tested. Everything above this layer talks to [`Archiver`] only, so moving to Kiln is a new
//! `impl Archiver` and a one-line change to [`Current`].
//!
//! What the flow needs from an archiver:
//! - **A raw 32-byte key.** Silk runs Argon2id itself and hands over the VEK. A password-based
//!   envelope (Kiln's current scrypt lock) is not what is wanted here.
//! - **Bytes in, bytes out.** No temp files, no paths: the vault is a few hundred KB and lives in memory.
//! - **An authenticated revision counter** readable from the plain header, so a replayed old file can be noticed.
//! - **A small, lean build:** no CLI or multi-codec dependencies pulled into the Android library.
use crate::error::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// One named blob inside an archive. Wiped on drop.
#[derive(Clone, Debug, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct Member {
    pub name: String,
    pub data: Vec<u8>,
}

impl Member {
    pub fn new(name: &str, data: Vec<u8>) -> Member {
        Member {
            name: name.to_owned(),
            data,
        }
    }
}

/// A decrypted archive.
'@
@'
//! The archive layer: what turns the entries into the encrypted vault file stored next to the key slot.
//!
//! The archive is Kiln's `.skln` (the `kiln-skln` crate; the format is in Kiln's `docs/FORMAT.md`),
//! connected by [`crate::skln`]. Everything above this layer talks to [`Archiver`] only. Vault
//! files from the stand-in format that came first ([`crate::interim`]) are still read, never written.
//!
//! What the flow needs from an archiver:
//! - **A raw 32-byte key.** Silk runs Argon2id itself and hands over the VEK. A password-based
//!   envelope (Kiln's scrypt lock) is not what is wanted here.
//! - **Bytes in, bytes out.** No temp files, no paths: the vault is a few hundred KB and lives in memory.
//! - **An authenticated revision counter** readable from the plain header, so a replayed old file can be noticed.
//! - **A small, lean build:** no CLI or multi-codec dependencies pulled into the Android library.
use crate::error::Error;

/// One named blob inside an archive. Wiped on drop.
pub use kiln_skln::bundle::Member;

/// A decrypted archive.
'@
@'
    /// Name of the stored object, for example `vault.skln`.
    fn file_name(&self) -> &'static str;
    /// Archives `members` and encrypts them with the VEK. Every call uses a fresh nonce.
    fn seal(&self, vek: &[u8; 32], revision: u64, members: &[Member]) -> Result<Vec<u8>, Error>;
    /// Decrypts and unpacks. A wrong key, a changed header and a changed body all fail with `Corrupt`.
'@
@'
    /// Name of the stored object, for example `vault.skln`.
    fn file_name(&self) -> &'static str;
    /// Archives `members` and encrypts them with the VEK. Every call uses a fresh salt.
    fn seal(&self, vek: &[u8; 32], revision: u64, members: &[Member]) -> Result<Vec<u8>, Error>;
    /// Decrypts and unpacks. A wrong key, a changed header and a changed body all fail with `Corrupt`.
'@
@'
}

/// The archiver in use. Change this one line when Kiln's `.skln` is ready.
pub type Current = crate::interim::Interim;

pub fn current() -> Current {
'@
@'
}

/// The archiver in use.
pub type Current = crate::skln::Skln;

pub fn current() -> Current {
'@
)
Edit-File 'core/src/cloud.rs' @(
@'
//! ```
//!
//! The archiver is Kiln's `.skln` once that exists (see [`crate::archive`]). [`CloudVault`] holds
//! the unlocked state (VEK + entries, both wiped on drop). The pure functions work on byte
//! buffers; `unlock_remote` / `save_remote` add the cloud round trips through a [`RemoteStore`].
'@
@'
//! ```
//!
//! The archiver is Kiln's `.skln` (see [`crate::archive`]). [`CloudVault`] holds
//! the unlocked state (VEK + entries, both wiped on drop). The pure functions work on byte
//! buffers; `unlock_remote` / `save_remote` add the cloud round trips through a [`RemoteStore`].
'@
)
Edit-File 'core/src/interim.rs' @(
@'
//! Interim stand-in for Kiln's `.skln` archive. **This is not the `.skln` format.**
//!
//! Kiln is a separate project and `.skln` is not in it yet. This module exists so the cloud flow
//! (`cloud`, `keyslot`, `remote`) can be built and tested now. It is a small authenticated
//! container with its own magic (`SKIM`, deliberately not Kiln's) and its own object name
//! (`vault.interim`), so it can never be mistaken for a real `.skln`. Replace it by writing an
//! `impl Archiver` over Kiln and changing `archive::Current`; nothing else needs to change.
//!
//! ```text
'@
@'
//! The stand-in archive that came before Kiln's `.skln`, kept as a **read-only source**. This is
//! not the `.skln` format.
//!
//! The cloud flow was built on this while `.skln` did not exist yet, so real vaults were written in it
//! (file `vault.interim`, magic `SKIM`, deliberately not Kiln's). Silk now writes `.skln` (see
//! [`crate::skln`]) but must keep opening these: [`crate::skln::Skln`] reads them, and
//! `session::unlock` rewrites one as `.skln` the first time it is opened. Only the tests still write it.
//!
//! ```text
'@
@'
//! The 14-byte header is bound in as associated data. Every length is checked against what is left
//! in the buffer, so a crafted file can't make the reader allocate or read past its input.
use crate::archive::{Archiver, Member, Opened};
use crate::error::Error;
use aes_gcm::aead::{Aead, KeyInit, Payload};
'@
@'
//! The 14-byte header is bound in as associated data. Every length is checked against what is left
//! in the buffer, so a crafted file can't make the reader allocate or read past its input.
use crate::archive::{Member, Opened};
use crate::error::Error;
use aes_gcm::aead::{Aead, KeyInit, Payload};
'@
@'
pub const MAX_MEMBERS: usize = 1024;
pub const MAX_NAME_LEN: usize = 255;
pub const MAX_ARCHIVE_LEN: usize = 64 * 1024 * 1024;

'@
@'
pub const MAX_MEMBERS: usize = 1024;
pub const MAX_NAME_LEN: usize = 255;
#[cfg(test)]
pub const MAX_ARCHIVE_LEN: usize = 64 * 1024 * 1024;

'@
@'
/// Packs members into the archive layout. The buffer is allocated once at its final size, so no
/// stale copies are left behind by reallocation, and it is wiped on drop.
pub fn pack(members: &[Member]) -> Result<Zeroizing<Vec<u8>>, Error> {
    if members.len() > MAX_MEMBERS {
'@
@'
/// Packs members into the archive layout. The buffer is allocated once at its final size, so no
/// stale copies are left behind by reallocation, and it is wiped on drop.
#[cfg(test)]
pub fn pack(members: &[Member]) -> Result<Zeroizing<Vec<u8>>, Error> {
    if members.len() > MAX_MEMBERS {
'@
@'
}

/// Checks that `file` looks like a `.skln` without needing the key.
pub fn validate(file: &[u8]) -> Result<(), Error> {
    if file.len() < HEADER_LEN + NONCE_LEN + TAG_LEN || &file[0..4] != MAGIC || file[4] != VERSION {
'@
@'
}

/// Whether `file` starts with the stand-in's magic, which decides how it is read.
pub fn is_interim(file: &[u8]) -> bool {
    file.starts_with(MAGIC)
}

/// Checks that `file` looks like a stand-in vault file without needing the key.
pub fn validate(file: &[u8]) -> Result<(), Error> {
    if file.len() < HEADER_LEN + NONCE_LEN + TAG_LEN || &file[0..4] != MAGIC || file[4] != VERSION {
'@
@'

/// Archives `members` and encrypts them with the VEK under a fresh random nonce.
pub fn seal(vek: &[u8; 32], revision: u64, members: &[Member]) -> Result<Vec<u8>, Error> {
    let archive = pack(members)?;
'@
@'

/// Archives `members` and encrypts them with the VEK under a fresh random nonce.
#[cfg(test)]
pub fn seal(vek: &[u8; 32], revision: u64, members: &[Member]) -> Result<Vec<u8>, Error> {
    let archive = pack(members)?;
'@
@'
}

/// Decrypts and unpacks a `.skln`. A wrong VEK, a changed header and a changed body all fail the
/// same way (`Corrupt`): the VEK comes out of the key slot, so a bad password never reaches here.
pub fn open(vek: &[u8; 32], file: &[u8]) -> Result<Opened, Error> {
'@
@'
}

/// Decrypts and unpacks a stand-in vault file. A wrong VEK, a changed header and a changed body all fail the
/// same way (`Corrupt`): the VEK comes out of the key slot, so a bad password never reaches here.
pub fn open(vek: &[u8; 32], file: &[u8]) -> Result<Opened, Error> {
'@
@'
    let members = unpack(&plain)?;
    Ok(Opened { revision, members })
}

/// The stand-in archiver. See the module docs.
#[derive(Clone, Copy, Debug, Default)]
pub struct Interim;

impl Archiver for Interim {
    fn file_name(&self) -> &'static str {
        "vault.interim"
    }

    fn seal(&self, vek: &[u8; 32], revision: u64, members: &[Member]) -> Result<Vec<u8>, Error> {
        seal(vek, revision, members)
    }

    fn open(&self, vek: &[u8; 32], file: &[u8]) -> Result<Opened, Error> {
        open(vek, file)
    }

    fn revision(&self, file: &[u8]) -> Result<u64, Error> {
        revision(file)
    }
}

'@
@'
    let members = unpack(&plain)?;
    Ok(Opened { revision, members })
}

'@
)
Edit-File 'core/src/lib.rs' @(
@'
//! Silk core: vault file format, key derivation, TOTP and autofill matching.
//! Cloud architecture: `cloud` (unlock/save flow) -> `keyslot` (Argon2id key wraps the VEK) -> `archive`
//! (Kiln's `.skln`; `interim` stands in until it exists). `local` keeps the on-device copy of both
//! objects, `session` is the unlocked state the app holds, `backup` is the one-file backup.
//! Cloud: `auth` speaks Supabase Auth (who the user is) and `supabase` speaks Supabase Storage (the two
'@
@'
//! Silk core: vault file format, key derivation, TOTP and autofill matching.
//! Cloud architecture: `cloud` (unlock/save flow) -> `keyslot` (Argon2id key wraps the VEK) -> `archive`
//! (Kiln's `.skln`, through `skln`; `interim` is the older stand-in format, read-only). `local` keeps the on-device copy of both
//! objects, `session` is the unlocked state the app holds, `backup` is the one-file backup.
//! Cloud: `auth` speaks Supabase Auth (who the user is) and `supabase` speaks Supabase Storage (the two
'@
@'
pub mod session;
pub mod settings;
pub mod supabase;
pub mod sync;
'@
@'
pub mod session;
pub mod settings;
pub mod skln;
pub mod supabase;
pub mod sync;
'@
)
Edit-File 'core/src/local.rs' @(
@'
//! ```text
//! keyslot.skvk     the key slot (VEK wrapped by the Argon2id key)
//! vault.interim    the vault file (vault.skln once Kiln's archive is in)
//! vault.pvlt       a vault from before the key slot existed; converted on first unlock, then removed
//! seen.rev         the highest vault revision this device has seen (rollback guard)
'@
@'
//! ```text
//! keyslot.skvk     the key slot (VEK wrapped by the Argon2id key)
//! vault.skln       the vault file (Kiln's `.skln`)
//! vault.interim    a vault file of the stand-in format that came before; read when there is no vault.skln,
//!                  and removed when the next save writes vault.skln
//! vault.pvlt       a vault from before the key slot existed; converted on first unlock, then removed
//! seen.rev         the highest vault revision this device has seen (rollback guard)
'@
@'
/// The vault file of the old, pre-key-slot format.
pub const LEGACY_FILE: &str = "vault.pvlt";
const SEEN_FILE: &str = "seen.rev";
const LINK_FILE: &str = "sync.uid";
'@
@'
/// The vault file of the old, pre-key-slot format.
pub const LEGACY_FILE: &str = "vault.pvlt";
/// The vault file of the stand-in format that came before `.skln` (see `interim`).
const INTERIM_FILE: &str = "vault.interim";
const SEEN_FILE: &str = "seen.rev";
const LINK_FILE: &str = "sync.uid";
'@
@'
    }

    pub fn has(&self, object: Object) -> bool {
        self.path(object).is_file()
    }

'@
@'
    }

    fn interim_path(&self) -> PathBuf {
        self.dir.join(INTERIM_FILE)
    }

    pub fn has(&self, object: Object) -> bool {
        self.path(object).is_file() || (object == Object::Archive && self.interim_path().is_file())
    }

'@
@'

    pub fn remove(&self, object: Object) -> Result<(), Error> {
        remove_if_exists(&self.path(object))
    }

'@
@'

    pub fn remove(&self, object: Object) -> Result<(), Error> {
        remove_if_exists(&self.path(object))?;
        if object == Object::Archive {
            remove_if_exists(&self.interim_path())?;
        }
        Ok(())
    }

'@
@'

impl RemoteStore for DirStore {
    fn get(&self, object: Object) -> Result<Option<Vec<u8>>, Error> {
        read_optional(&self.path(object))
    }

    fn put(&self, object: Object, data: &[u8]) -> Result<(), Error> {
        write_atomic(&self.path(object), data)
    }

    fn delete(&self, object: Object) -> Result<(), Error> {
        remove_if_exists(&self.path(object))
    }
}
'@
@'

impl RemoteStore for DirStore {
    /// The vault file falls back to a stand-in `vault.interim` when there is no `vault.skln` yet.
    /// Whatever archiver reads the bytes tells the two formats apart by their magic.
    fn get(&self, object: Object) -> Result<Option<Vec<u8>>, Error> {
        let found = read_optional(&self.path(object))?;
        if found.is_none() && object == Object::Archive {
            return read_optional(&self.interim_path());
        }
        Ok(found)
    }

    /// Writing the vault file replaces a stand-in `vault.interim`: it is removed once the new file
    /// is in place. If removing fails nothing is lost, because `vault.skln` is read first.
    fn put(&self, object: Object, data: &[u8]) -> Result<(), Error> {
        write_atomic(&self.path(object), data)?;
        if object == Object::Archive {
            let _ = remove_if_exists(&self.interim_path());
        }
        Ok(())
    }

    fn delete(&self, object: Object) -> Result<(), Error> {
        self.remove(object)
    }
}
'@
@'

    #[test]
    fn legacy_file_round_trips_and_goes_away() {
        let s = temp_store();
'@
@'

    #[test]
    fn a_stand_in_vault_file_is_read_until_the_next_write_replaces_it() {
        let s = temp_store();
        std::fs::create_dir_all(s.dir()).unwrap();
        std::fs::write(s.dir().join(INTERIM_FILE), b"interim").unwrap();
        assert!(s.has(Object::Archive));
        assert_eq!(s.get(Object::Archive).unwrap().unwrap(), b"interim");
        // Only the vault file falls back; the key slot never does.
        assert_eq!(s.get(Object::KeySlot).unwrap(), None);

        s.put(Object::Archive, b"skln").unwrap();
        assert_eq!(s.get(Object::Archive).unwrap().unwrap(), b"skln");
        assert!(s.dir().join("vault.skln").is_file());
        assert!(!s.dir().join(INTERIM_FILE).exists());

        std::fs::write(s.dir().join(INTERIM_FILE), b"interim").unwrap();
        s.remove(Object::Archive).unwrap();
        assert!(!s.has(Object::Archive));
        assert_eq!(s.get(Object::Archive).unwrap(), None);
    }

    #[test]
    fn legacy_file_round_trips_and_goes_away() {
        let s = temp_store();
'@
)
Edit-File 'core/src/session.rs' @(
@'
//!
//! Vaults from before the key slot existed (`vault.pvlt`) are converted the first time they are
//! unlocked with the password: new VEK, new key slot, same entries.
use crate::backup;
use crate::cloud::{CloudVault, Flow};
use crate::error::Error;
use crate::local::DirStore;
use crate::remote::{Object, RemoteStore};
'@
@'
//!
//! Vaults from before the key slot existed (`vault.pvlt`) are converted the first time they are
//! unlocked with the password: new VEK, new key slot, same entries. A vault file of the stand-in
//! format (`vault.interim`) is rewritten as `.skln` the first time it is opened.
use crate::backup;
use crate::cloud::{CloudVault, Flow};
use crate::error::Error;
use crate::interim;
use crate::local::DirStore;
use crate::remote::{Object, RemoteStore};
'@
@'
        }
    }
    let (vault, flow) = CloudVault::unlock_remote(store, password, key_file, kdf)?;
    let outcome = match flow {
        Flow::FirstTimeSetup => Outcome::Created,
        Flow::Subsequent => {
            store.check_revision(vault.revision())?;
            Outcome::Unlocked
        }
'@
@'
        }
    }
    let (mut vault, flow) = CloudVault::unlock_remote(store, password, key_file, kdf)?;
    let outcome = match flow {
        Flow::FirstTimeSetup => Outcome::Created,
        Flow::Subsequent => {
            store.check_revision(vault.revision())?;
            upgrade(store, &mut vault)?;
            Outcome::Unlocked
        }
'@
@'
}

/// Biometric quick unlock: the VEK comes from the Keystore, so there is no Argon2id.
pub fn unlock_with_vek(store: &DirStore, vek: &[u8; 32]) -> Result<CloudVault, Error> {
    let slot = store.get(Object::KeySlot)?.ok_or(Error::NotAVault)?;
    let file = store.get(Object::Archive)?;
    let vault = CloudVault::unlock_with_vek(&slot, file.as_deref(), vek)?;
    store.check_revision(vault.revision())?;
    Ok(vault)
}
'@
@'
}

/// A vault file of the stand-in format is saved again as `.skln` (revision + 1, so the rollback mark
/// still holds). The save writes `vault.skln` and then removes `vault.interim`. Nothing happens for
/// a vault that is already `.skln`.
fn upgrade(store: &DirStore, vault: &mut CloudVault) -> Result<(), Error> {
    match store.get(Object::Archive)? {
        Some(file) if interim::is_interim(&file) => vault.save_remote(store),
        _ => Ok(()),
    }
}

/// Biometric quick unlock: the VEK comes from the Keystore, so there is no Argon2id.
pub fn unlock_with_vek(store: &DirStore, vek: &[u8; 32]) -> Result<CloudVault, Error> {
    let slot = store.get(Object::KeySlot)?.ok_or(Error::NotAVault)?;
    let file = store.get(Object::Archive)?;
    let mut vault = CloudVault::unlock_with_vek(&slot, file.as_deref(), vek)?;
    store.check_revision(vault.revision())?;
    upgrade(store, &mut vault)?;
    Ok(vault)
}
'@
@'
mod tests {
    use super::*;
    use crate::vault::new_id;

'@
@'
mod tests {
    use super::*;
    use crate::archive::Archiver;
    use crate::vault::new_id;

'@
@'
    }

    #[test]
    fn biometric_unlock_uses_the_vek_and_rejects_a_wrong_one() {
'@
@'
    }

    /// Rewrites the vault file on disk as a stand-in `vault.interim`, the way an older build left it.
    fn downgrade_to_interim(s: &mut Session) {
        let store = s.store().unwrap();
        let vek = s.export_vek().unwrap();
        let file = store.get(Object::Archive).unwrap().unwrap();
        let opened = crate::archive::current().open(&vek, &file).unwrap();
        let old = interim::seal(&vek, opened.revision, &opened.members).unwrap();
        store.remove(Object::Archive).unwrap();
        std::fs::write(store.dir().join("vault.interim"), old).unwrap();
        s.lock();
    }

    #[test]
    fn a_stand_in_vault_file_is_rewritten_as_skln_on_unlock() {
        let mut s = temp_session();
        open_with(&mut s, "password1");
        s.upsert(entry("1")).unwrap();
        let before = s.store().unwrap().seen_revision();
        downgrade_to_interim(&mut s);

        let store = s.store().unwrap();
        assert!(store.dir().join("vault.interim").is_file());
        assert!(!store.dir().join("vault.skln").exists());
        assert_eq!(open_with(&mut s, "password1"), Outcome::Unlocked);
        assert_eq!(s.entries().unwrap()[0].id, "1");
        assert!(!store.dir().join("vault.interim").exists());
        let file = store.get(Object::Archive).unwrap().unwrap();
        assert!(!interim::is_interim(&file));
        // One revision up, so the rollback mark still agrees with the file.
        assert_eq!(crate::archive::current().revision(&file).unwrap(), before + 1);
        assert_eq!(store.seen_revision(), before + 1);
    }

    #[test]
    fn a_stand_in_vault_file_is_rewritten_as_skln_on_biometric_unlock() {
        let mut s = temp_session();
        open_with(&mut s, "password1");
        s.upsert(entry("1")).unwrap();
        let vek = s.export_vek().unwrap();
        downgrade_to_interim(&mut s);

        let store = s.store().unwrap();
        let vault = unlock_with_vek(&store, &vek).unwrap();
        assert_eq!(vault.entries.len(), 1);
        assert!(!store.dir().join("vault.interim").exists());
        assert!(store.dir().join("vault.skln").is_file());
    }

    #[test]
    fn biometric_unlock_uses_the_vek_and_rejects_a_wrong_one() {
'@
)
Edit-File 'core/src/supabase.rs' @(
@'
            assert_eq!(uploads[1].body, a.get(Object::Archive).unwrap().unwrap());
            assert!(uploads[0].body.starts_with(b"SKVK"));
            assert!(uploads[1].body.starts_with(b"SKIM"));
            // No plaintext anywhere in anything that was sent: bodies, URLs or headers.
            for req in world.seen.borrow().iter() {
'@
@'
            assert_eq!(uploads[1].body, a.get(Object::Archive).unwrap().unwrap());
            assert!(uploads[0].body.starts_with(b"SKVK"));
            assert!(uploads[1].body.starts_with(b"\x89SKLN"));
            // No plaintext anywhere in anything that was sent: bodies, URLs or headers.
            for req in world.seen.borrow().iter() {
'@
)
Edit-File 'scripts/allowed-dependencies.txt' @(
@'

# silk-core: crypto and parsing only. No network, no async, no HTTP client, no unsafe code.
core: aes-gcm argon2 getrandom hmac serde serde_json sha1 sha2 zeroize
#   aes-gcm, argon2, sha2, hmac, sha1  the vault, key slot and TOTP (RFC 6238 needs HMAC-SHA1/256/512)
#   getrandom                          random bytes on Android and desktop alike
#   serde, serde_json                  entries, settings, key-file login, Supabase replies
'@
@'

# silk-core: crypto and parsing only. No network, no async, no HTTP client, no unsafe code.
core: aes-gcm argon2 getrandom hmac kiln-skln serde serde_json sha1 sha2 zeroize
#   aes-gcm, argon2, sha2, hmac, sha1  the vault, key slot and TOTP (RFC 6238 needs HMAC-SHA1/256/512)
#   kiln-skln                          Kiln's .skln container (the vault file): bytes in, bytes out, no
#                                      network or async. Brings chacha20poly1305 and hkdf with it, which
#                                      is why MAX_CORE_CRATES in check-bloat.sh went up by five.
#   getrandom                          random bytes on Android and desktop alike
#   serde, serde_json                  entries, settings, key-file login, Supabase replies
'@
)
Edit-File 'scripts/check-bloat.sh' @(
@'
MAX_TRACKED_KB=2048    # all tracked files together (about 1.2 MB today)
MAX_LOCK_PACKAGES=560  # packages in Cargo.lock (545 today, nearly all of them Slint's)
MAX_CORE_CRATES=55     # crates silk-core pulls in at run time (51 today)
# Crates that mean "a second way of doing something we already do". All network goes through the
# `Http` trait in core/src/auth.rs and android/.../Net.java.
'@
@'
MAX_TRACKED_KB=2048    # all tracked files together (about 1.2 MB today)
MAX_LOCK_PACKAGES=560  # packages in Cargo.lock (545 today, nearly all of them Slint's)
MAX_CORE_CRATES=56     # crates silk-core pulls in at run time (51 before kiln-skln, which adds five)
# Crates that mean "a second way of doing something we already do". All network goes through the
# `Http` trait in core/src/auth.rs and android/.../Net.java.
'@
)
Edit-File 'supabase/storage-policies.sql' @(
@'
-- This file has not been run against a live project by the author: read it before you run it.
--
-- Files Silk stores, per user:   vaults/<user id>/keyslot.skvk
--                                vaults/<user id>/vault.interim   (vault.skln once Kiln's format exists)
-- Everything in them is already encrypted on the device.
--
-- Users sign in with Supabase Auth (email and password, done by the app), so their token already has
'@
@'
-- This file has not been run against a live project by the author: read it before you run it.
--
-- Files Silk stores, per user:   vaults/<user id>/keyslot.skvk
--                                vaults/<user id>/vault.skln
-- Everything in them is already encrypted on the device.
--
-- Users sign in with Supabase Auth (email and password, done by the app), so their token already has
'@
@'
    and array_length(storage.foldername(name), 1) = 2
    and (storage.foldername(name))[1] = 'vaults'
    and (storage.foldername(name))[2] = (select auth.jwt() ->> 'sub')
    and storage.filename(name) in ('keyslot.skvk', 'vault.interim', 'vault.skln')
  );

create policy "silk: create own vault files" on storage.objects
'@
@'
    and array_length(storage.foldername(name), 1) = 2
    and (storage.foldername(name))[1] = 'vaults'
    and (storage.foldername(name))[2] = (select auth.jwt() ->> 'sub')
    and storage.filename(name) in ('keyslot.skvk', 'vault.skln')
  );

create policy "silk: create own vault files" on storage.objects
'@
@'
    and array_length(storage.foldername(name), 1) = 2
    and (storage.foldername(name))[1] = 'vaults'
    and (storage.foldername(name))[2] = (select auth.jwt() ->> 'sub')
    and storage.filename(name) in ('keyslot.skvk', 'vault.interim', 'vault.skln')
  );

create policy "silk: replace own vault files" on storage.objects
'@
@'
    and array_length(storage.foldername(name), 1) = 2
    and (storage.foldername(name))[1] = 'vaults'
    and (storage.foldername(name))[2] = (select auth.jwt() ->> 'sub')
    and storage.filename(name) in ('keyslot.skvk', 'vault.skln')
  );

create policy "silk: replace own vault files" on storage.objects
'@
@'
    and array_length(storage.foldername(name), 1) = 2
    and (storage.foldername(name))[1] = 'vaults'
    and (storage.foldername(name))[2] = (select auth.jwt() ->> 'sub')
    and storage.filename(name) in ('keyslot.skvk', 'vault.interim', 'vault.skln')
  )
  with check (
    bucket_id = 'silk-vaults'
    and array_length(storage.foldername(name), 1) = 2
    and (storage.foldername(name))[1] = 'vaults'
    and (storage.foldername(name))[2] = (select auth.jwt() ->> 'sub')
    and storage.filename(name) in ('keyslot.skvk', 'vault.interim', 'vault.skln')
  );

create policy "silk: delete own vault files" on storage.objects
'@
@'
    and array_length(storage.foldername(name), 1) = 2
    and (storage.foldername(name))[1] = 'vaults'
    and (storage.foldername(name))[2] = (select auth.jwt() ->> 'sub')
    and storage.filename(name) in ('keyslot.skvk', 'vault.skln')
  )
  with check (
    bucket_id = 'silk-vaults'
    and array_length(storage.foldername(name), 1) = 2
    and (storage.foldername(name))[1] = 'vaults'
    and (storage.foldername(name))[2] = (select auth.jwt() ->> 'sub')
    and storage.filename(name) in ('keyslot.skvk', 'vault.skln')
  );

create policy "silk: delete own vault files" on storage.objects
'@
@'
    and array_length(storage.foldername(name), 1) = 2
    and (storage.foldername(name))[1] = 'vaults'
    and (storage.foldername(name))[2] = (select auth.jwt() ->> 'sub')
    and storage.filename(name) in ('keyslot.skvk', 'vault.interim', 'vault.skln')
  );

-- ============================================================ PART 3: check the policies (optional)
'@
@'
    and array_length(storage.foldername(name), 1) = 2
    and (storage.foldername(name))[1] = 'vaults'
    and (storage.foldername(name))[2] = (select auth.jwt() ->> 'sub')
    and storage.filename(name) in ('keyslot.skvk', 'vault.skln')
  );

-- ============================================================ PART 3: check the policies (optional)
'@
)
New-TextFile 'core/src/skln.rs' @'
//! Kiln's `.skln` as Silk's vault file (`vault.skln`): the [`Archiver`] in use.
//!
//! The `kiln-skln` crate does the sealing: a bundle whose one member is `vault.json`, cut into
//! ChaCha20-Poly1305 records under a key derived from the VEK and a fresh salt, with the revision in
//! the plain header (authenticated, readable without the key). This file only connects it to the
//! trait and turns its errors into Silk's.
//!
//! Vault files of the stand-in format (`SKIM`, see [`crate::interim`]) are still opened, so a device
//! that holds one keeps working; the next save writes `.skln`. Revisions carry on across the two
//! formats, so the rollback mark stays valid.
use crate::archive::{Archiver, Member, Opened};
use crate::error::Error;
use crate::interim;
use kiln_skln::bundle;

#[derive(Clone, Copy, Debug, Default)]
pub struct Skln;

fn convert(e: kiln_skln::Error) -> Error {
    use kiln_skln::Error as E;
    match e {
        E::NotSkln | E::Unsupported => Error::NotAVault,
        E::Corrupt | E::Limit => Error::Corrupt,
        E::Random => Error::Random,
        E::Internal => Error::Crypto,
    }
}

impl Archiver for Skln {
    fn file_name(&self) -> &'static str {
        "vault.skln"
    }

    fn seal(&self, vek: &[u8; 32], revision: u64, members: &[Member]) -> Result<Vec<u8>, Error> {
        bundle::seal_bundle(vek, revision, members).map_err(convert)
    }

    fn open(&self, vek: &[u8; 32], file: &[u8]) -> Result<Opened, Error> {
        if interim::is_interim(file) {
            return interim::open(vek, file);
        }
        let opened = bundle::open_bundle(vek, file).map_err(convert)?;
        Ok(Opened {
            revision: opened.revision,
            members: opened.members,
        })
    }

    fn revision(&self, file: &[u8]) -> Result<u64, Error> {
        if interim::is_interim(file) {
            return interim::revision(file);
        }
        kiln_skln::revision(file).map_err(convert)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [9u8; 32];

    fn sample() -> Vec<Member> {
        vec![
            Member::new("vault.json", b"{\"entries\":[]}".to_vec()),
            Member::new("readme.txt", b"hello".to_vec()),
        ]
    }

    #[test]
    fn seal_and_open_round_trip() {
        let f = Skln.seal(&KEY, 7, &sample()).unwrap();
        assert!(f.starts_with(&kiln_skln::MAGIC));
        assert_eq!(Skln.revision(&f).unwrap(), 7);
        let back = Skln.open(&KEY, &f).unwrap();
        assert_eq!(back.revision, 7);
        assert_eq!(back.members, sample());
        assert_eq!(back.get("readme.txt").unwrap().data, b"hello");
        assert!(back.get("missing").is_none());
    }

    #[test]
    fn every_seal_is_different() {
        assert_ne!(
            Skln.seal(&KEY, 1, &sample()).unwrap(),
            Skln.seal(&KEY, 1, &sample()).unwrap()
        );
    }

    #[test]
    fn wrong_key_and_tampering_are_rejected() {
        let f = Skln.seal(&KEY, 3, &sample()).unwrap();
        assert_eq!(Skln.open(&[1u8; 32], &f).err(), Some(Error::Corrupt));

        let mut body = f.clone();
        let last = body.len() - 1;
        body[last] ^= 1;
        assert_eq!(Skln.open(&KEY, &body).err(), Some(Error::Corrupt));

        // The revision is authenticated: a server can't quietly rewrite it.
        let mut hdr = f.clone();
        hdr[12] ^= 1;
        assert_eq!(Skln.open(&KEY, &hdr).err(), Some(Error::Corrupt));
    }

    #[test]
    fn other_files_are_not_vault_files() {
        assert_eq!(Skln.open(&KEY, b"nope").err(), Some(Error::NotAVault));
        assert_eq!(Skln.revision(b"nope").err(), Some(Error::NotAVault));
        assert_eq!(Skln.open(&KEY, &[0u8; 64]).err(), Some(Error::NotAVault));
    }

    #[test]
    fn a_skln_that_is_not_a_bundle_is_refused() {
        let f = kiln_skln::seal(&KEY, kiln_skln::Kind::Archive, 1, b"x").unwrap();
        assert_eq!(Skln.open(&KEY, &f).err(), Some(Error::NotAVault));
    }

    #[test]
    fn stand_in_files_still_open_and_the_next_seal_is_skln() {
        let old = interim::seal(&KEY, 4, &sample()).unwrap();
        assert!(!old.starts_with(&kiln_skln::MAGIC));
        assert_eq!(Skln.revision(&old).unwrap(), 4);
        let back = Skln.open(&KEY, &old).unwrap();
        assert_eq!(back.revision, 4);
        assert_eq!(back.members, sample());
        assert_eq!(Skln.open(&[1u8; 32], &old).err(), Some(Error::Corrupt));

        let next = Skln.seal(&KEY, back.revision + 1, &back.members).unwrap();
        assert!(next.starts_with(&kiln_skln::MAGIC));
        assert_eq!(Skln.revision(&next).unwrap(), 5);
    }
}
'@
New-TextFile 'browser-extension/src/chacha.js' @'
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
'@
New-TextFile 'browser-extension/src/skln.js' @'
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
'@
New-TextFile 'browser-extension/test/skln.test.js' @'
import test from 'node:test';
import assert from 'node:assert/strict';
import { createCipheriv, randomBytes } from 'node:crypto';
import { chacha20Poly1305Open } from '../src/chacha.js';
import { openSkln, parseSkln, unpackBundle, isSkln } from '../src/skln.js';
import { sealSkln } from './helpers.js';

const hex = (h) => Uint8Array.from(h.match(/../g), (b) => parseInt(b, 16));
const seal = (key, nonce, aad, plain) => {
  const c = createCipheriv('chacha20-poly1305', key, nonce, { authTagLength: 16 });
  c.setAAD(aad);
  return new Uint8Array(Buffer.concat([c.update(plain), c.final(), c.getAuthTag()]));
};

test('ChaCha20-Poly1305 matches RFC 8439 section 2.8.2', () => {
  const key = Uint8Array.from({ length: 32 }, (_, i) => 0x80 + i);
  const nonce = hex('070000004041424344454647');
  const aad = hex('50515253c0c1c2c3c4c5c6c7');
  const plain = new TextEncoder().encode("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.");
  const sealed = seal(key, nonce, aad, plain);
  assert.equal(Buffer.from(sealed.subarray(sealed.length - 16)).toString('hex'), '1ae10b594f09e26a7e902ecbd0600691');
  assert.deepEqual(chacha20Poly1305Open(key, nonce, aad, sealed), plain);
});

test('ChaCha20-Poly1305 agrees with node:crypto for every length around the block sizes', () => {
  const key = randomBytes(32);
  const nonce = randomBytes(12);
  for (let n = 0; n <= 200; n++) {
    const plain = randomBytes(n);
    const aad = randomBytes(n % 37);
    const sealed = seal(key, nonce, aad, plain);
    assert.deepEqual(Buffer.from(chacha20Poly1305Open(key, nonce, aad, sealed)), plain, `length ${n}`);
  }
});

test('ChaCha20-Poly1305 refuses any changed byte, the aad, and short input', () => {
  const key = randomBytes(32);
  const nonce = randomBytes(12);
  const aad = new Uint8Array([1, 2, 3]);
  const sealed = seal(key, nonce, aad, randomBytes(70));
  for (let i = 0; i < sealed.length; i++) {
    const c = sealed.slice();
    c[i] ^= 0x80;
    assert.throws(() => chacha20Poly1305Open(key, nonce, aad, c), /tag mismatch/, `byte ${i}`);
  }
  assert.throws(() => chacha20Poly1305Open(key, nonce, new Uint8Array([1, 2, 4]), sealed), /tag mismatch/);
  assert.throws(() => chacha20Poly1305Open(key, nonce, aad, sealed.subarray(0, 15)), /bad ChaCha20-Poly1305 input/);
});

test('opens a .skln written with several record sizes, and reads its header without the key', async () => {
  const vek = randomBytes(32);
  for (const chunkLog2 of [12, 13, 20]) {
    const members = [['vault.json', randomBytes(10_000)], ['empty', new Uint8Array(0)], ['b', randomBytes(3)]];
    const file = sealSkln(vek, members, 77, chunkLog2);
    assert.ok(isSkln(file));
    const h = parseSkln(file);
    assert.equal(h.revision, 77n);
    assert.equal(h.kind, 1);
    assert.equal(h.chunkLog2, chunkLog2);
    const opened = await openSkln(vek, file);
    const back = unpackBundle(opened.plaintext);
    assert.deepEqual([...back.keys()], ['vault.json', 'empty', 'b']);
    assert.deepEqual(Buffer.from(back.get('vault.json')), Buffer.from(members[0][1]));
    assert.equal(back.get('empty').length, 0);
    await assert.rejects(openSkln(randomBytes(32), file), { code: 'corrupt' });
  }
});

test('a file that is not a .skln is refused', async () => {
  assert.equal(isSkln(new Uint8Array(3)), false);
  assert.throws(() => parseSkln(new TextEncoder().encode('SKIM and some more bytes, long enough for a header....')), { code: 'not-skln' });
  const file = sealSkln(randomBytes(32), [['a', new Uint8Array(1)]], 1, 12);
  const wrongVersion = file.slice();
  wrongVersion[8] = 2;
  assert.throws(() => parseSkln(wrongVersion), { code: 'not-skln' });
  const unknownFlag = file.slice();
  unknownFlag[9] = 2;
  assert.throws(() => parseSkln(unknownFlag), { code: 'corrupt' });
  for (const log2 of [11, 25]) {
    const bad = file.slice();
    bad[11] = log2;
    assert.throws(() => parseSkln(bad), { code: 'corrupt' });
  }
});

test('the bundle reader checks every length and every name', () => {
  const le = (n, size) => {
    const b = Buffer.alloc(size);
    if (size === 2) b.writeUInt16LE(n);
    else b.writeUInt32LE(n);
    return b;
  };
  const bundle = (...members) =>
    new Uint8Array(Buffer.concat([le(members.length, 4), ...members.flatMap(([n, d]) => [le(Buffer.byteLength(n), 2), Buffer.from(n), le(d.length, 4), Buffer.from(d)])]));
  assert.equal(unpackBundle(bundle(['a', [1, 2]], ['b', []])).get('a').length, 2);
  const corrupt = { code: 'corrupt' };
  for (const bad of ['', '.', '..', 'a/b', 'a\\b', 'nul\0', 'tab\t', 'x'.repeat(256)]) {
    assert.throws(() => unpackBundle(bundle([bad, [1]])), corrupt, JSON.stringify(bad));
  }
  assert.throws(() => unpackBundle(bundle(['a', [1]], ['a', [2]])), corrupt, 'duplicate name');
  const ok = bundle(['a', [1, 2, 3]]);
  for (let len = 0; len < ok.length; len++) assert.throws(() => unpackBundle(ok.slice(0, len)), corrupt, `cut ${len}`);
  assert.throws(() => unpackBundle(Uint8Array.from([...ok, 0])), corrupt, 'trailing byte');
  assert.throws(() => unpackBundle(new Uint8Array(Buffer.concat([le(1025, 4)]))), corrupt, 'too many members');
  const huge = Buffer.concat([le(1, 4), le(1, 2), Buffer.from('a'), le(0xffffffff, 4)]);
  assert.throws(() => unpackBundle(new Uint8Array(huge)), corrupt, 'a length past the end');
});
'@

foreach ($w in $writes) {
  $dir = Split-Path -Parent $w.Path
  if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir | Out-Null }
  if ($null -ne $w.Bytes) { [IO.File]::WriteAllBytes($w.Path, $w.Bytes) } else { [IO.File]::WriteAllText($w.Path, $w.Text, $utf8) }
}
git diff --stat -- 'CLAUDE.md' 'README.md' 'docs/ARCHITECTURE.md' 'browser-extension/src/vault.js' 'browser-extension/test/helpers.js' 'browser-extension/test/vault.test.js' 'core/Cargo.toml' 'core/src/archive.rs' 'core/src/cloud.rs' 'core/src/interim.rs' 'core/src/lib.rs' 'core/src/local.rs' 'core/src/session.rs' 'core/src/supabase.rs' 'scripts/allowed-dependencies.txt' 'scripts/check-bloat.sh' 'supabase/storage-policies.sql' 'core/src/skln.rs' 'browser-extension/src/chacha.js' 'browser-extension/src/skln.js' 'browser-extension/test/skln.test.js'
git status --short -- 'CLAUDE.md' 'README.md' 'docs/ARCHITECTURE.md' 'browser-extension/src/vault.js' 'browser-extension/test/helpers.js' 'browser-extension/test/vault.test.js' 'core/Cargo.toml' 'core/src/archive.rs' 'core/src/cloud.rs' 'core/src/interim.rs' 'core/src/lib.rs' 'core/src/local.rs' 'core/src/session.rs' 'core/src/supabase.rs' 'scripts/allowed-dependencies.txt' 'scripts/check-bloat.sh' 'supabase/storage-policies.sql' 'core/src/skln.rs' 'browser-extension/src/chacha.js' 'browser-extension/src/skln.js' 'browser-extension/test/skln.test.js'
