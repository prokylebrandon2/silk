#!/usr/bin/env bash
# Fails when the project grows in the ways that once made it too large (see CLAUDE.md).
# Run it before every commit and hand-off; CI runs it too.
#
#   scripts/check-bloat.sh
#
# Limits live at the top of this file. Raising one is a decision to make on purpose and to explain
# in the commit message, not something to do to get a check to pass.
set -u
cd "$(dirname "$0")/.."

MAX_FILE_KB=512        # one tracked file (the 1024 px icon master is the largest, ~410 KB)
MAX_TRACKED_KB=2048    # all tracked files together (about 1.2 MB today)
MAX_LOCK_PACKAGES=560  # packages in Cargo.lock (545 today, nearly all of them Slint's)
MAX_CORE_CRATES=56     # crates silk-core pulls in at run time (47 counted today, kiln-skln and its five included)
# Crates that mean "a second way of doing something we already do". All network goes through the
# `Http` trait in core/src/auth.rs and android/.../Net.java.
FORBIDDEN_CRATES="reqwest hyper ureq openssl native-tls rustls curl clap anyhow rand serde_yaml async-std"

fail=0
bad() { echo "FAIL: $*" >&2; fail=1; }
ok()  { echo "ok:   $*"; }

# ---- 1. what is tracked ------------------------------------------------------------------------
if git rev-parse --git-dir >/dev/null 2>&1; then
  tracked=$(git ls-files)

  junk=$(echo "$tracked" | grep -E '(^|/)(target|build|\.gradle|node_modules|jniLibs|\.idea)/|\.(apk|aab|so|jar|dex|class|7z|zip|keystore|jks|key)$' || true)
  if [ -n "$junk" ]; then
    bad "build output, binaries or secrets are tracked (git rm --cached them, and fix .gitignore):"
    echo "$junk" | sed 's/^/        /' >&2
  else
    ok "no build output, binaries or keystores tracked"
  fi

  big=$(git ls-files -z | xargs -0 -r stat -c '%s %n' | awk -v max=$((MAX_FILE_KB * 1024)) '$1 > max { printf "        %d KB  %s\n", $1 / 1024, substr($0, index($0, " ") + 1) }')
  if [ -n "$big" ]; then
    bad "tracked files over ${MAX_FILE_KB} KB:"
    echo "$big" >&2
  else
    ok "no tracked file over ${MAX_FILE_KB} KB"
  fi

  total_kb=$(git ls-files -z | xargs -0 -r stat -c '%s' | awk '{ s += $1 } END { printf "%d", s / 1024 }')
  if [ "$total_kb" -gt "$MAX_TRACKED_KB" ]; then
    bad "tracked files total ${total_kb} KB, limit ${MAX_TRACKED_KB} KB"
  else
    ok "tracked files total ${total_kb} KB (limit ${MAX_TRACKED_KB} KB)"
  fi
else
  echo "note: not a git checkout, skipping the tracked-file checks"
fi

# ---- 2. one copy of everything -----------------------------------------------------------------
# The app was renamed once; the old Java package was left behind and compiled into the APK.
pkgs=$(find android/app/src/main/java -mindepth 2 -maxdepth 2 -type d 2>/dev/null | wc -l)
if [ "$pkgs" -gt 1 ]; then
  bad "more than one Java package under android/app/src/main/java/app (a renamed copy left behind?):"
  find android/app/src/main/java -mindepth 2 -maxdepth 2 -type d | sed 's/^/        /' >&2
else
  ok "one Java package"
fi

# ---- 3. dependencies are on a list -------------------------------------------------------------
# Every direct dependency must be in scripts/allowed-dependencies.txt. Adding a crate means adding a
# line there, with the reason, in the same change.
declared() { # $1 = Cargo.toml : prints the names under [dependencies], [dev-dependencies], [build-dependencies]
  awk '
    /^\[/ { on = ($0 ~ /^\[(dev-|build-)?dependencies\]/); next }
    on && /^[A-Za-z0-9_-]+[ ]*=/ { sub(/[ ]*=.*/, ""); print }
  ' "$1" | sort -u
}
allowed() { # $1 = key (core or app)
  awk -v k="$1" '$1 == k ":" { for (i = 2; i <= NF; i++) { if ($i == "#") break; print $i } }' scripts/allowed-dependencies.txt | sort -u
}
for pair in core:core/Cargo.toml app:app/Cargo.toml; do
  key=${pair%%:*}; file=${pair#*:}
  extra=$(comm -23 <(declared "$file") <(allowed "$key"))
  if [ -n "$extra" ]; then
    bad "$file has dependencies that are not in scripts/allowed-dependencies.txt:"
    echo "$extra" | sed 's/^/        /' >&2
  else
    ok "$file dependencies are all on the list"
  fi
done

if grep -qE '"(dependencies|devDependencies)"' browser-extension/package.json; then
  bad "browser-extension/package.json has dependencies; the extension is dependency-free on purpose"
else
  ok "browser extension has no dependencies"
fi

# ---- 4. the lock file --------------------------------------------------------------------------
pk=$(grep -c '^\[\[package\]\]' Cargo.lock)
if [ "$pk" -gt "$MAX_LOCK_PACKAGES" ]; then
  bad "Cargo.lock has $pk packages, limit $MAX_LOCK_PACKAGES"
else
  ok "Cargo.lock has $pk packages (limit $MAX_LOCK_PACKAGES)"
fi
for c in $FORBIDDEN_CRATES; do
  if grep -q "^name = \"$c\"$" Cargo.lock; then
    bad "Cargo.lock contains '$c' (see FORBIDDEN_CRATES in this script and CLAUDE.md)"
  fi
done

if command -v cargo >/dev/null 2>&1; then
  # --no-dedupe: without it cargo marks repeated subtrees with " (*)", so the same crate shows up as
  # two different lines and is counted twice. tr drops the CR that a Windows toolchain adds.
  n=$(cargo tree -p silk-core -e normal --prefix none --no-dedupe 2>/dev/null |
    tr -d '\r' |
    sort -u |
    grep -v '^silk-core v' |
    wc -l)
  if [ "$n" -eq 0 ]; then
    echo "note: could not run cargo tree, skipping the core crate count"
  elif [ "$n" -gt "$MAX_CORE_CRATES" ]; then
    bad "silk-core pulls in $n crates, limit $MAX_CORE_CRATES"
  else
    ok "silk-core pulls in $n crates (limit $MAX_CORE_CRATES)"
  fi
fi

echo
if [ "$fail" -ne 0 ]; then
  echo "check-bloat: FAILED" >&2
  exit 1
fi
echo "check-bloat: passed"
