#!/usr/bin/env bash
# Operator-local crosscheck wrapper: runs the generate lane against the real
# KazeTK audit artifacts and prints a parity table.
#
# NEVER run in CI. This script only READS the project files under
# /home/kin/nexustk-emulator; nothing is copied into this repository, and
# nothing outside --out is written. By default the generated model lands in a
# fresh temporary directory (reruns never collide); set KZTK_OUT to keep it.
set -euo pipefail

# Resolve the repository root (this file lives in tools/).
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$here/.." && pwd)"

REPO="${KZTK_REPO:-/home/kin/nexustk-emulator}"
CLIENT="${KZTK_CLIENT:-/home/kin/.local/share/kazetk/vanilla-client/NexusTK.exe}"

# Prefer a release build when it exists; otherwise build one (debug is fine
# for a local parity check).
if [ -x "$repo_root/target/release/deg-nexustk" ]; then
    DEG_NTK="$repo_root/target/release/deg-nexustk"
elif [ -x "$repo_root/target/debug/deg-nexustk" ]; then
    DEG_NTK="$repo_root/target/debug/deg-nexustk"
else
    echo "crosscheck: building deg-nexustk (debug)" >&2
    (cd "$repo_root" && cargo build -q)
    DEG_NTK="$repo_root/target/debug/deg-nexustk"
fi

if [ -n "${KZTK_OUT:-}" ]; then
    exec python3 "$here/crosscheck.py" \
        --repo "$REPO" \
        --client "$CLIENT" \
        --deg-nexustk "$DEG_NTK" \
        --out "$KZTK_OUT"
else
    # No --out: crosscheck.py creates a fresh temporary directory.
    exec python3 "$here/crosscheck.py" \
        --repo "$REPO" \
        --client "$CLIENT" \
        --deg-nexustk "$DEG_NTK"
fi
