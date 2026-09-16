#!/bin/bash
# infra/bootstrap.sh
#
# EC2 instance UserData for the noxos-payload build fleet. Unlike
# noxos-os/infra/bootstrap.sh, this does not run a fresh `repo sync` or
# snapshot the result afterward - it reuses noxos-os's already-synced
# noxos-aosp-src EBS snapshot (found by tag, always the latest one) purely
# to compile one small Soong module, then terminates. Deliberately does not
# write a new "noxos-aosp-src"-tagged snapshot, so it never becomes the
# "latest" tree other builds resume from.

set -euo pipefail
export HOME=/root
exec > /var/log/noxos-payload-bootstrap.log 2>&1

# ami-0aa111eb1f0bcbc94 already has awscli/git/repo/JDK baked in - no apt-get
# needed here, unlike a stock Ubuntu AMI.

imds_token() { curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 300"; }
imds() { curl -s -H "X-aws-ec2-metadata-token: $(imds_token)" "http://169.254.169.254/latest/meta-data/$1"; }

REGION=$(imds placement/region)
AZ=$(imds placement/availability-zone)
INSTANCE_ID=$(imds instance-id)
export AWS_DEFAULT_REGION="$REGION"

LOG_BUCKET="noxos-releases"
LOG_PREFIX="logs-payload/${INSTANCE_ID}"
push_logs() {
  aws s3 cp /var/log/ "s3://${LOG_BUCKET}/${LOG_PREFIX}/$(date -u +%Y%m%dT%H%M%SZ)/" \
    --recursive --exclude '*' --include 'noxos-*.log' 2>/dev/null || true
}
trap push_logs EXIT

VOL_TAG_NAME="noxos-aosp-src"
SNAP_ID=$(aws ec2 describe-snapshots --owner-ids self \
  --filters "Name=tag:Name,Values=$VOL_TAG_NAME" "Name=status,Values=completed" \
  --query 'sort_by(Snapshots,&StartTime)[-1].SnapshotId' --output text)
USE_VOL=$(aws ec2 create-volume --availability-zone "$AZ" --snapshot-id "$SNAP_ID" --size 620 \
  --volume-type gp3 --tag-specifications "ResourceType=volume,Tags=[{Key=Name,Value=noxos-payload-build-src}]" \
  --query 'VolumeId' --output text)
aws ec2 wait volume-available --volume-ids "$USE_VOL"

aws ec2 attach-volume --volume-id "$USE_VOL" --instance-id "$INSTANCE_ID" --device /dev/sdf
aws ec2 wait volume-in-use --volume-ids "$USE_VOL"
aws ec2 modify-instance-attribute --instance-id "$INSTANCE_ID" \
  --block-device-mappings "[{\"DeviceName\":\"/dev/sdf\",\"Ebs\":{\"DeleteOnTermination\":true}}]"
sleep 5

ROOT_DEV=$(lsblk -no PKNAME "$(findmnt -n -o SOURCE /)" 2>/dev/null || echo nvme0n1)
DEV="/dev/$(lsblk -dno NAME,TYPE | awk '$2=="disk"{print $1}' | grep -v "^${ROOT_DEV}$" | head -1)"

mkdir -p /mnt/aosp
mount "$DEV" /mnt/aosp
if [ "$(stat -c '%U' /mnt/aosp)" != "ubuntu" ]; then
  chown -R ubuntu:ubuntu /mnt/aosp
fi

# soong_build's full-product-graph analysis for noxos_cf_x86_64_phone has been
# observed climbing past 25GB+ RSS (session 2026-09-15, real data, not a
# hypothetical) - real headroom, not just raw instance RAM, since even the
# 32GB fleet sizing isn't confirmed sufficient alone yet.
if ! swapon --show | grep -q /mnt/aosp/swapfile; then
  fallocate -l 24G /mnt/aosp/swapfile
  chmod 600 /mnt/aosp/swapfile
  mkswap /mnt/aosp/swapfile
  swapon /mnt/aosp/swapfile
fi

git config --global --add safe.directory '*'

set +e
sudo -u ubuntu -H bash -c "
  set -euo pipefail
  export AWS_DEFAULT_REGION='$REGION'
  cd /mnt/aosp
  git clone --branch infra --depth 1 https://github.com/parrothacker1/noxos-payload.git /tmp/noxos-payload-infra
  bash /tmp/noxos-payload-infra/infra/sync-payload.sh
  bash /tmp/noxos-payload-infra/infra/build-all-abis.sh
"
BUILD_EXIT=$?
set -e

echo "=== build-all-abis.sh exited with code $BUILD_EXIT ==="

KEEP_ALIVE=$(aws ec2 describe-tags --filters "Name=resource-id,Values=$INSTANCE_ID" "Name=key,Values=KeepAlive" \
  --query 'Tags[0].Value' --output text)
if [ "$KEEP_ALIVE" = "true" ]; then
  echo "KeepAlive=true tag set on this instance - leaving fleet and instance up for reuse, not scaling down or terminating"
  exit 0
fi

FLEET_ID=$(aws ec2 describe-tags --filters "Name=resource-id,Values=$INSTANCE_ID" "Name=key,Values=aws:ec2:fleet-id" \
  --query 'Tags[0].Value' --output text)
if [ -n "$FLEET_ID" ] && [ "$FLEET_ID" != "None" ]; then
  aws ec2 modify-fleet --fleet-id "$FLEET_ID" --target-capacity-specification TotalTargetCapacity=0 \
    --excess-capacity-termination-policy no-termination
fi

if [ "$BUILD_EXIT" -ne 0 ]; then
  echo "build-all-abis.sh failed - leaving instance up for inspection instead of terminating"
  exit 0
fi

aws ec2 terminate-instances --instance-ids "$INSTANCE_ID"
