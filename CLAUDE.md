# Rules for agents working on Silk

Read this before changing anything. It exists because the project once grew to 12.6 MB (an archive of
the working folder) while its source is about 1.2 MB. The causes were build output, a stale copy of a
renamed Java package, and copies of the same native library. None of them was needed.

## Keep it small

- **Never hand the project over by zipping or 7-zipping the working folder.** Run `scripts/pack.sh`
  (Linux, macOS) or `scripts/pack.ps1` (Windows PowerShell). They pack only what git tracks (plus new,
  not-ignored files). Hand off a `.zip`: a `.7z` that uses the ARM64 filter cannot be opened in the
  Claude sandbox.
- **Never commit build output**: `target/`, `build/`, `.gradle/`, `jniLibs/`, `.apk`, `.so`, `.zip`,
  `.7z`, keystores, `local.properties`. `.gitignore` covers them; do not weaken it.
- **One copy of everything.** After a rename, delete the old files in the same change. There is one Java
  package, `app/silk`. No `*_old`, `*.bak`, "reference" copies, or commented-out code kept for later.
- **Delete dead code; do not silence it.** No `#[allow(dead_code)]` or unused items kept "for future
  use". If a function is only used by tests, mark it `#[cfg(test)]`.
- **No new dependency without a reason.** Every direct dependency must be listed in
  `scripts/allowed-dependencies.txt` with a comment saying why, in the same change. Never add a second
  way of doing something that exists (HTTP client, JSON, crypto, async runtime). The forbidden crates
  are listed in `scripts/check-bloat.sh`. Slint dominates the lock file; changing its version or
  features changes the size of `libsilk.so`, so say so in the commit message.
- **Network code stays in two places**: the `Http` trait in `core/src/auth.rs` and
  `android/app/src/main/java/app/silk/Net.java`. `silk-core` has no network, async or unsafe code.
- **No new files that nobody asked for** (extra docs, notes, scratch scripts). Update `README.md` and
  `docs/ARCHITECTURE.md` instead.
- **Assets**: one master icon in `assets/`. Do not add another copy of an image that already exists.

## Check before you finish

Run `scripts/check-bloat.sh`. It fails on tracked build output, files over 512 KB, more than 2 MB of
tracked files, a second Java package, dependencies not on the list, forbidden crates, or a `Cargo.lock`
over its package limit. CI runs it too. Raising a limit is a decision to make on purpose and explain in
the commit message, not a way to get the check to pass.

## How this project is built

- Builds and tests run only in GitHub Actions (`.github/workflows/android.yml`). Do not compile, run
  tests or benchmarks as part of a change; the owner runs them and reports errors, and wants warnings
  fixed too.
- The owner works on Windows PowerShell and pushes to GitHub.
- Cloud sync (optional, off without project values): Supabase Auth signs the user in and Supabase
  Storage keeps the two encrypted files. `SUPABASE_URL` and `SUPABASE_PUBLISHABLE_KEY` come from the
  environment or `android/local.properties`. See `docs/ARCHITECTURE.md`, "Setting up the cloud".
- The vault file is Kiln's `.skln` (the `kiln-skln` crate, `core/src/skln.rs`). `core/src/interim.rs` is the
  older stand-in format, kept read-only so existing vaults convert on unlock. Encrypting the `.key` file
  inside a `.skln` still waits for Kiln's security update.
