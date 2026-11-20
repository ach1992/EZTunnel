#!/usr/bin/env bash
# Release gate: the private signing seed cannot change the reviewed fork identity.
set -euo pipefail
actual=${1:-}
expected_file=${2:-.github/release-public-key.hex}
if [[ ! -f "$expected_file" ]]; then
  echo "Release signing public key is not pinned in $expected_file" >&2
  exit 1
fi
expected=$(tr -d '\r\n' < "$expected_file")
if [[ ! "$expected" =~ ^[0-9a-f]{64}$ ]]; then
  echo "Release public key has not been provisioned as a reviewed 32-byte hex value in $expected_file" >&2
  exit 1
fi
if [[ ! "$actual" =~ ^[0-9a-f]{64}$ || "$actual" != "$expected" ]]; then
  echo 'Release signing key does not match the reviewed fork public key; refusing to publish an incompatible release.' >&2
  exit 1
fi
echo 'Fork signing public key matches the reviewed pin.'
