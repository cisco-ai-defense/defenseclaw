#!/bin/bash
# Stage the microVM assets for Agent Substrate v1.0.0 on EKS.
#   BUCKET=my-snapshots SUBSTRATE_DIR=~/substrate ./stage-assets.sh
# SUBSTRATE_DIR is a checkout of the Substrate v1.0.0 tag after
#   ate-setup deploy sandboxconfig --sandbox-classes gvisor,microvm
# has assembled bin/microvm-assets/amd64 (that command fails at its last step on
# EKS; that is expected). The assets go outside the snapshot prefix: the object
# store plugin refuses asset URLs under snapshots/.
set -euo pipefail
: "${BUCKET:?set BUCKET to the snapshot bucket}"
: "${SUBSTRATE_DIR:?set SUBSTRATE_DIR to the Substrate checkout}"
cd "$SUBSTRATE_DIR"
T=manifests/ate-install/sandboxconfig-microvm.yaml.tmpl
A=bin/microvm-assets/amd64
for p in cloud-hypervisor:cloud-hypervisor virtiofsd:virtiofsd kata-kernel:vmlinux kata-image:rootfs.img; do
  k=${p%%:*}; f=${p##*:}
  sha=$(sha256sum "$A/$f" | cut -d" " -f1)
  grep -q "amd64/$sha" "$T" || { echo "MISMATCH $k: the file does not match the template"; exit 1; }
  aws s3 cp --only-show-errors "$A/$f" "s3://$BUCKET/microvm-assets/amd64/$sha" && echo "staged $k"
done
export BUCKET_SCHEME=s3 ASSET_BUCKET_NAME="$BUCKET"
envsubst < "$T" > sandboxconfig-microvm.yaml
kubectl apply -f sandboxconfig-microvm.yaml
kubectl get sandboxconfig
