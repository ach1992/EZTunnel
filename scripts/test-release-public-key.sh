#!/usr/bin/env bash
set -euo pipefail
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
printf '%064d\n' 0 > "$work/expected"
printf '1%063d\n' 0 > "$work/unexpected"
bash scripts/verify-fork-release-public-key.sh "$(cat "$work/expected")" "$work/expected" >/dev/null
if bash scripts/verify-fork-release-public-key.sh "$(cat "$work/unexpected")" "$work/expected" >/dev/null 2>&1; then
  echo 'Unexpected signing seed was accepted' >&2
  exit 1
fi
if bash scripts/verify-fork-release-public-key.sh "$(cat "$work/expected")" /dev/null >/dev/null 2>&1; then
  echo 'Unprovisioned key was accepted' >&2
  exit 1
fi
echo 'Release public-key continuity tests passed (matching, mismatching, unprovisioned).'
