#!/usr/bin/env bash
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
#
# Build the Agent Substrate images and chart of a release from its Linux
# gateway archives (the release workflow's substrate-images job; also runs
# by hand against a test registry):
#   - defenseclaw-gateway, linux/amd64 + linux/arm64, with SBOM and
#     provenance attestations (deploy/images/gateway/Dockerfile);
#   - one kit image per connector recipe deploy/images/actor-kit/<c>/Dockerfile,
#     built with the build context "kitbin" holding linux-<arch>/ binaries;
#   - the defenseclaw-substrate chart, its image pinned to the pushed
#     gateway digest, packaged and pushed as an OCI artifact.
# Signing is not done here: the workflow signs every digest in images.txt
# with cosign keyless, under the identity that signs checksums.txt.
#
# usage: substrate-images.sh --version X.Y.Z --registry REG --dist DIR --out DIR [--push]
#   --dist  the directory with defenseclaw-X.Y.Z-linux-{amd64,arm64}.tar.gz
#   --out   receives defenseclaw-substrate-X.Y.Z.tgz and images.txt
#   without --push nothing leaves the machine: the images are built into the
#   buildx cache only and images.txt lists them without digests.
set -euo pipefail

version="" registry="" dist="" out="" push=false
while (($#)); do
  case "$1" in
    --version) version=$2; shift 2 ;;
    --registry) registry=${2%/}; shift 2 ;;
    --dist) dist=$2; shift 2 ;;
    --out) out=$2; shift 2 ;;
    --push) push=true; shift ;;
    *) echo "substrate-images: unknown argument $1" >&2; exit 2 ;;
  esac
done
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] || { echo "substrate-images: --version X.Y.Z is required" >&2; exit 2; }
[[ -n "$registry" && -d "$dist" && -n "$out" ]] || { echo "substrate-images: --registry, --dist and --out are required" >&2; exit 2; }
root=$(cd "$(dirname "$0")/../.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$out"
: > "$out/images.txt"

# 1. The release's own Linux binaries, per architecture.
ctx="$work/gateway"
mkdir -p "$ctx"
cp "$root/LICENSE" "$root/NOTICE" "$root/THIRD_PARTY_LICENSES.txt" "$ctx/"
for arch in amd64 arm64; do
  archive="$dist/defenseclaw-$version-linux-$arch.tar.gz"
  [[ -f "$archive" ]] || { echo "substrate-images: $archive is missing" >&2; exit 1; }
  mkdir -p "$ctx/linux-$arch" "$work/x-$arch"
  tar -xzf "$archive" -C "$work/x-$arch"
  bin=$(find "$work/x-$arch" -type f -name defenseclaw-gateway | head -n 1)
  [[ -n "$bin" ]] || { echo "substrate-images: no defenseclaw-gateway in $archive" >&2; exit 1; }
  cp "$bin" "$ctx/linux-$arch/defenseclaw-gateway"
  for kit in defenseclaw-actor-hook defenseclaw-actor-relay; do
    found=$(find "$work/x-$arch" -type f -name "$kit" | head -n 1)
    if [[ -n "$found" ]]; then mkdir -p "$work/kitbin/linux-$arch"; cp "$found" "$work/kitbin/linux-$arch/"; fi
  done
done

# build NAME DOCKERFILE CONTEXT [extra buildx args...]: build (and push) one
# multi-arch image; append REF@DIGEST (or REF) to images.txt.
build() {
  local name=$1 file=$2 context=$3; shift 3
  local ref="$registry/$name:$version" meta="$work/$name.meta.json"
  local args=(buildx build --platform linux/amd64,linux/arm64 -f "$file" --build-arg "VERSION=$version"
    --label "org.opencontainers.image.revision=${GITHUB_SHA:-unknown}" --tag "$ref" --metadata-file "$meta" "$@")
  if [[ "$push" == true ]]; then
    args+=(--push --sbom=true --provenance=mode=max)
  fi
  docker "${args[@]}" "$context"
  if [[ "$push" == true ]]; then
    local digest
    digest=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["containerimage.digest"])' "$meta")
    [[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]] || { echo "substrate-images: no digest for $ref" >&2; exit 1; }
    echo "$registry/$name@$digest" >> "$out/images.txt"
    printf '%s' "$digest"
  else
    echo "$ref" >> "$out/images.txt"
  fi
}

gateway_digest=$(build defenseclaw-gateway "$root/deploy/images/gateway/Dockerfile" "$ctx")

# 2. Kit images, one per connector recipe (A5: deploy/images/actor-kit).
shopt -s nullglob
recipes=("$root"/deploy/images/actor-kit/*/Dockerfile)
if ((${#recipes[@]})) && [[ ! -d "$work/kitbin" ]]; then
  echo "substrate-images: kit recipes exist but the archives carry no defenseclaw-actor-hook/relay" >&2
  exit 1
fi
for recipe in "${recipes[@]}"; do
  connector=$(basename "$(dirname "$recipe")")
  build "defenseclaw-kit-$connector" "$recipe" "$root/deploy/images/actor-kit" --build-context "kitbin=$work/kitbin" >/dev/null
done

# 3. The chart, pinned to the gateway image just built.
chart="$work/chart/defenseclaw-substrate"
mkdir -p "$work/chart"
cp -R "$root/deploy/helm/defenseclaw-substrate" "$chart"
rm -rf "$chart/tests"
python3 - "$chart/values.yaml" "$registry/defenseclaw-gateway" "$version" "${gateway_digest:-}" <<'PY'
import re, sys
path, repo, version, digest = sys.argv[1:]
text = open(path).read()
block = re.search(r"(?ms)^image:\n(?:  .*\n)+", text)
if not block:
    sys.exit("values.yaml: no image block")
new = block.group(0)
for key, value in (("repository", repo), ("tag", version), ("digest", digest)):
    new, n = re.subn(rf"(?m)^  {key}: .*$", f'  {key}: "{value}"' if key != "repository" else f"  {key}: {value}", new)
    if n != 1:
        sys.exit(f"values.yaml: image.{key} not found once")
open(path, "w").write(text.replace(block.group(0), new))
PY
helm lint "$chart" --kube-version 1.34.0 >/dev/null
helm package "$chart" --version "$version" --app-version "$version" --destination "$out" >/dev/null
tgz="$out/defenseclaw-substrate-$version.tgz"
[[ -f "$tgz" ]] || { echo "substrate-images: helm package wrote no $tgz" >&2; exit 1; }
if [[ "$push" == true ]]; then
  pushed=$(helm push "$tgz" "oci://$registry/charts" 2>&1)
  digest=$(sed -n 's/^Digest: //p' <<<"$pushed")
  [[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]] || { echo "substrate-images: helm push gave no digest: $pushed" >&2; exit 1; }
  echo "$registry/charts/defenseclaw-substrate@$digest" >> "$out/images.txt"
else
  echo "$registry/charts/defenseclaw-substrate:$version" >> "$out/images.txt"
fi
cat "$out/images.txt"
