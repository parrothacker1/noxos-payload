#!/usr/bin/env bash
# infra/sync-payload.sh
#
# Checks this repo's source into an already-synced AOSP tree. Unlike
# noxos-os/infra/sync.sh, this does NOT run `repo sync` - it reuses the
# noxos-aosp-src EBS snapshot noxos-os's own builds already produced (one
# small native module doesn't need its own multi-hundred-GB tree sync).
# Run from the AOSP source root, after that snapshot's volume is mounted.

set -euo pipefail

TARGET_DIR="device/noxos/payload"
rm -rf "$TARGET_DIR"
git clone --depth 1 https://github.com/parrothacker1/noxos-payload.git "$TARGET_DIR"

echo "sync-payload.sh: done. noxos-payload checked out at $TARGET_DIR"
