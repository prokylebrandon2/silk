# Silk

> Silk was called PassVault. The rename is complete: crates, library, Android package and application ID (`app.silk`), classes, docs. Only the old `.pvlt` file format keeps its `PVLT` magic, because old vaults and backups must still open. **Because the application ID changed, Android treats Silk as a new app:** to bring an old PassVault vault over, back it up in the old app, install Silk and use **Restore from backup** on its first screen. Details in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

An offline Android password manager written in Rust: master password + optional key file, system autofill and TOTP codes. Optional cloud sync (Firebase sign-in, Supabase storage): the only thing that ever leaves the device is the already-encrypted vault.

## How it's built

| Part | Language | What it does |
|---|---|---|
| `core/` | Rust (`silk-core`) | Key slot and vault format, Argon2id, AES-256-GCM, key file, TOTP, autofill field detection and matching, session and idle lock. No Android code, fully unit-tested on a normal machine. |
| `app/` | Rust | The UI (Slint) and the JNI bridge. Builds to `libsilk.so`. |
| `browser-extension/` | JavaScript | A Brave/Chrome extension (Manifest V3) that opens a copy of your vault, fills logins and shows one-time codes. See below. |
| `android/` | Java (about 450 lines, mostly comments and boilerplate) | The part Android makes mandatory: the `AutofillService` class, the document-picker result callback, clipboard, and handing an autofill result back. It holds no logic; it passes strings and bytes to Rust. |

## How the vault is protected

- Master password (and key file, if used) are hashed with SHA-256 and stretched with **Argon2id** (t=3, 64 MiB, p=4) into a 256-bit key. That key only wraps a random 256-bit **VEK** (vault encryption key), stored in a small **key slot** next to the vault.
- The vault file is encrypted with the VEK using **AES-256-GCM**. Every save uses a fresh random nonce, and the headers (KDF settings, salt, revision) are authenticated. Changing the master password only re-wraps the VEK; the vault file isn't touched.
- Each save raises an authenticated revision number and the device remembers the highest one it has seen, so an older copy of the vault file is refused.
- Vaults from earlier versions (`vault.pvlt`) are converted automatically the first time they are unlocked with the password.
- A **key file** is any file you pick, or a **Silk key file** the app creates (a random 64-byte secret, magic `SKEY`). It is mixed into the key, so the vault can't be opened without it. Keep a copy somewhere other than this phone. Lose the password or the key file and the vault is gone. The app remembers where the key file is, never its contents.
- **The cloud sign-in is saved in the Silk key file automatically.** When you sign in to the cloud account, Silk writes the account's email, user id and refresh token (never the account password) after the secret in the key file, and removes them again when you sign out or the sign-in expires. Only the 64-byte secret feeds the key derivation, so this never changes the key. Any other file you picked as a key file is hashed whole, as always, and Silk never writes into it; with one of those, the sign-in lasts until Silk closes. Older 64-byte key files keep working unchanged.
- **Planned:** the `.key` file will be encrypted inside a `.skln`. That comes in a later update, after the security update in Kiln, because the encryption engine for it is going to be built in Kiln. Until then the key file, refresh token included, is stored unencrypted wherever you saved it, so treat it like a password: whoever holds it can sign in to your cloud account (they still can't read the vault without the master password).
- Data stays in app-private storage. `allowBackup=false`, screenshots are blocked, the clipboard is flagged sensitive and cleared after 5 minutes. Keys and entries are zeroized when the vault locks.
- The vault locks after 5 idle minutes, when the screen turns off and when you leave the app with Back. Tune the KDF in `core/src/vault.rs` (`Kdf::default`) and the idle time in `core/src/session.rs`.
- **Back up** (list screen) saves the still-encrypted key slot and vault file as one `.silk` file, and keeps that file up to date after every change. **Restore from backup** is on the create screen; it also accepts old `.pvlt` backups.

## Autofill

Tap **Turn on** in the app (or Settings > Passwords & autofill > Autofill service > Silk). In Chrome also enable Settings > Autofill services > Autofill using another service.

A login is offered when its **Website or app** field matches the page: `https://example.com` for sites (subdomains match) or `androidapp://com.example.app` for apps. If the vault is locked the dropdown shows "Unlock Silk", which opens a small unlock screen and returns the login to the app you were in.

## Screens

Four tabs along the bottom: **Logins**, **Codes**, **Generator** and **More**.

## Codes (built-in authenticator)

The **Codes** tab lists every login that has a one-time password, with a live code and countdown. Tap a row to copy its code, **Edit** to open the login, **Add** to set up a new authenticator from a Base32 setup key or an `otpauth://` link (it is saved as its own entry). TOTP with SHA-1/256/512, 6 to 8 digits, any period (RFC 6238, tested against the RFC vectors). There is no QR scanner yet: paste the setup key the site shows next to the QR code.

## Password generator

The **Generator** tab sets the length (8 to 64), which sets to use (a-z, A-Z, 0-9, symbols), whether to leave out look-alikes (`l I 1 O 0 o`) and whether new logins start with a generated password. Every selected set is guaranteed to appear. The choices are saved in `settings.json` in the app's private storage (nothing secret in it). The **Generate** link on the login form uses the same settings.

## Proton Pass import and export

**More > Import from Proton Pass** reads an *unencrypted* Proton Pass export: `.json` (or the `Data.json` inside the `.zip`) or `.csv`. Logins, notes, aliases and cards are brought over (cards and other non-login items become entries whose notes hold the fields). Items in Proton's trash are skipped, passkeys cannot be moved, and logins that already exist in the vault (same title, username, website and password) are skipped. Other CSVs with the usual columns (`name`, `url`, `username`, `password`, `note`, `totp`) also work, including Bitwarden's.

**More > Export for Proton Pass** writes CSV (Proton's own column layout) or JSON. These files are **not encrypted**; the app asks you to confirm and reminds you to delete the file after importing it. Encrypted (PGP) Proton exports are not supported: export again without encryption.

The JSON layout is reconstructed from Proton's documented export format, not from a file I could open on a real account. If Proton Pass refuses the JSON, use the CSV.

## Brave extension

`browser-extension/` is a Manifest V3 extension for Brave (and any Chromium browser). It is a read-only copy of your phone's vault:

1. In the app: **More > Back up vault**, move the `.silk` file to your computer.
2. Brave: `brave://extensions`, turn on Developer mode, **Load unpacked**, pick the `browser-extension` folder (or unzip the `silk-brave-extension` artifact from CI).
3. Click the extension, choose the `.silk` file (an old `.pvlt` backup works too), enter the master password (and the key file if the vault uses one).

It opens the same backup format (Argon2id unwraps the VEK, AES-256-GCM decrypts the vault, with its own Argon2 in JavaScript; unlocking takes a few seconds), suggests logins for the current site, fills username and password into the page you are on when you click **Fill**, fills or copies one-time codes, and locks after 5 idle minutes. It asks before filling a login on a site that doesn't match the login's address. Permissions are only `storage`, `alarms`, `activeTab` and `scripting`: it can touch a page only when you click Fill. The encrypted file is kept in the extension's local storage; decrypted logins live in session storage, which the browser never writes to disk. It never edits the vault: to update the copy, back up again in the app and re-add the file. It does not clear the clipboard for you, and JavaScript can't reliably wipe memory.

`cd browser-extension && npm test` runs the tests (Argon2 against the RFC 9106 vectors, opening backups and old vault files, RFC 6238 codes, site matching). Needs Node 18 or newer.

## Cloud architecture: the VEK, Kiln, Firebase and Supabase

The vault uses envelope encryption with Supabase Storage as untrusted storage (Firebase only signs the user in): the master password goes through Argon2id to a key that only wraps a random **VEK**; the VEK encrypts the vault archive. That archive will be Kiln's `.skln` (Kiln is a separate project and `.skln` is not in it yet), so `core/src/interim.rs` stands in behind the `Archiver` trait until it is.

Cloud sync is optional and off until you set up a Firebase project and a Supabase project (steps in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), "Setting up the cloud") and sign in from **More > Cloud sync**. The device always unlocks from its own copy, so offline use never needs the network. After each saved change Silk uploads the two encrypted files (key slot and vault file); **Sync now** also downloads a newer cloud copy. The higher authenticated revision wins, a download goes through the rollback guard, and two vaults that were never linked are never overwritten silently (you are asked which one to keep). The only network code is `android/.../Net.java`, which accepts HTTPS to the two Firebase sign-in hosts and your one Supabase project host, and nothing else. Storage policies: `supabase/storage-policies.sql`.

Diagram, formats, the key file layout, what `.skln` needs to provide and the task list: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Build

```
cargo test -p silk-core                           # core tests, any machine
(cd browser-extension && npm test)                # extension tests, Node 18+

rustup target add aarch64-linux-android x86_64-linux-android
cargo install cargo-ndk
cargo ndk --platform 26 -t arm64-v8a -t x86_64 -o android/app/src/main/jniLibs build --release --package silk
gradle -p android assembleDebug                   # JDK 17, Gradle 8.9, Android SDK + NDK installed
```

Slint's Android backend compiles a small Java helper while building, so `ANDROID_HOME` and a JDK must be set. Commit `Cargo.lock` after the first successful build.

## GitHub Actions (`.github/workflows/android.yml`)

| Trigger | What runs |
|---|---|
| Push to `main`, pull request, manual run | Core tests, then the Android build; the debug APK is uploaded as an artifact |
| Tag `v*` (for example `v1.0.0`) | Everything above, then a signed release APK + AAB attached to a GitHub Release |

Before tagging, add these repository secrets (Settings > Secrets and variables > Actions):

```
keytool -genkeypair -v -keystore release.jks -alias silk -keyalg RSA -keysize 4096 -validity 10000
base64 -w0 release.jks        # paste the output as KEYSTORE_BASE64
```

`KEYSTORE_BASE64`, `KEYSTORE_PASSWORD`, `KEY_ALIAS`, `KEY_PASSWORD`. Then `git tag v1.0.0 && git push --tags`. Back up `release.jks`: you can't update the app without it.

## Not included yet

QR scanning for OTP setup, HOTP, passphrase generation, saving new logins from other apps, KeePass import, editing the vault from the browser extension, an iOS app (needs a separate Swift credential-provider extension and a macOS runner).
