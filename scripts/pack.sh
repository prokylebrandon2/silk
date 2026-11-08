#!/usr/bin/env bash
# Makes a clean hand-off archive: the files git tracks (plus new files that are not ignored), never
# build output. Use this instead of zipping or 7-zipping the working folder; that is how the project
# once ended up 18 MB when its source is 1.2 MB.
#
#   scripts/pack.sh                 -> ../silk-rust-src.zip (includes .git, so history comes along)
#   scripts/pack.sh out.zip         -> out.zip
#   scripts/pack.sh out.zip --no-git
set -eu
cd "$(dirname "$0")/.."
root=$(pwd)
out=${1:-"$root/../silk-rust-src.zip"}
case "$out" in /*) ;; *) out="$root/$out" ;; esac
with_git=1
[ "${2:-}" = "--no-git" ] && with_git=0

git rev-parse --git-dir >/dev/null 2>&1 || { echo "not a git checkout: nothing says what is source" >&2; exit 1; }

scripts/check-bloat.sh >/dev/null || { echo "check-bloat failed; run scripts/check-bloat.sh and fix it first" >&2; exit 1; }

rm -f "$out"
list=$(mktemp)
trap 'rm -f "$list"' EXIT
# Tracked files that still exist, plus untracked files that .gitignore does not exclude.
git ls-files -co --exclude-standard | while IFS= read -r f; do [ -e "$f" ] && printf '%s\n' "$f"; done > "$list"
[ "$with_git" -eq 1 ] && find .git -type f >> "$list"
zip -q -9 "$out" -@ < "$list"
echo "wrote $out ($(du -h "$out" | cut -f1), $(wc -l < "$list") files)"
