#!/usr/bin/env bash
# infra/build-payload.sh
#
# Builds the noxos_payload_stub Soong module for one ABI, against the tree
# infra/sync-payload.sh just checked this repo into. Must run from the AOSP
# source root. For all supported ABIs in one run, see build-all-abis.sh.

set -euo pipefail

export AWS_DEFAULT_REGION="${AWS_DEFAULT_REGION:-us-east-1}"

LUNCH_TARGET="${LUNCH_TARGET:-noxos_cf_x86_64_phone-trunk_staging-userdebug}"
MODULE="${MODULE:-noxos_payload_stub}"
ABI="${ABI:-x86_64}"

source build/envsetup.sh
lunch "$LUNCH_TARGET"
m "$MODULE"

OUT_SO=$(find out/target/product \( -name "${MODULE}.so" -o -name "lib${MODULE}.so" \) 2>/dev/null | head -1)
if [ -z "$OUT_SO" ]; then
  echo "build-payload.sh: no compiled .so found for module $MODULE under out/target/product" >&2
  exit 1
fi

echo "build-payload.sh: done. compiled artifact: $OUT_SO"
file "$OUT_SO"

ASSET_NAME="libnoxos_payload_stub-${ABI}.so"
S3_BUCKET="${NOXOS_S3_BUCKET:-noxos-releases}"
S3_PREFIX="${S3_PREFIX:-payload-build/$(date -u +%Y%m%dT%H%M%SZ)}"
aws s3 cp "$OUT_SO" "s3://${S3_BUCKET}/${S3_PREFIX}/${ASSET_NAME}"
echo "build-payload.sh: uploaded to s3://${S3_BUCKET}/${S3_PREFIX}/${ASSET_NAME}"
