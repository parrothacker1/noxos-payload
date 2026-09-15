#!/usr/bin/env bash
# infra/build-all-abis.sh
#
# Builds every supported ABI in one run, uploading all artifacts under the
# same S3 prefix so they can be released together as one multi-asset
# GitHub release. Must run from the AOSP source root, after
# infra/sync-payload.sh. Each ABI is a full separate product lunch/build -
# this roughly doubles total build time versus infra/build-payload.sh alone,
# there's no way around that (different lunch targets can't share one Soong
# analysis pass).

set -euo pipefail

export AWS_DEFAULT_REGION="${AWS_DEFAULT_REGION:-us-east-1}"
export S3_PREFIX="${S3_PREFIX:-payload-build/$(date -u +%Y%m%dT%H%M%SZ)}"

SCRIPT_DIR="$(dirname "$0")"

LUNCH_TARGET=noxos_cf_x86_64_phone-trunk_staging-userdebug ABI=x86_64 \
  bash "$SCRIPT_DIR/build-payload.sh"

LUNCH_TARGET=aosp_cf_arm64_phone-trunk_staging-userdebug ABI=arm64-v8a \
  bash "$SCRIPT_DIR/build-payload.sh"

echo "build-all-abis.sh: done. artifacts under s3://${NOXOS_S3_BUCKET:-noxos-releases}/${S3_PREFIX}/"
