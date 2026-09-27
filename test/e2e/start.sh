#!/bin/sh
# Creates a fresh vault and serves it for the Playwright suite.
set -eu
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
AZK="${AZK_BIN:-$ROOT/bin/azk}"
DIR="$(mktemp -d)"
trap 'rm -rf "$DIR"' EXIT
export AZK_VAULT="$DIR/vault.db"
export AZK_PASSPHRASE="e2e-pass"
export AZK_KDF_TIME=1 AZK_KDF_MEMORY=8192 AZK_KDF_THREADS=1
"$AZK" init >/dev/null
"$AZK" key generate seeded-ec --type ec --tag env=e2e >/dev/null
unset AZK_PASSPHRASE
exec "$AZK" serve --listen 127.0.0.1:7799 --idle-timeout 0
