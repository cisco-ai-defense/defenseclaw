#!/usr/bin/env bash
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

# Build a release-shaped asset directory from the working tree, for testing
# the installers without publishing (`install.sh --local DIR`,
# `install.ps1 -Local DIR`). The working tree is copied and stamped in a
# scratch directory, so the checkout is never modified.
#
#   scripts/build-release-assets.sh 1.0.0 /tmp/dc-1.0.0 [os/arch ...]
#
# Default targets: the host platform. The Release workflow builds the same
# asset names with goreleaser.

set -euo pipefail

VERSION="${1:?usage: $0 VERSION OUTDIR [os/arch ...]}"
OUT="${2:?usage: $0 VERSION OUTDIR [os/arch ...]}"
shift 2
TARGETS=("$@")
if [[ ${#TARGETS[@]} -eq 0 ]]; then
    TARGETS=("$(go env GOOS)/$(go env GOARCH)")
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mkdir -p "${OUT}"
OUT="$(cd "${OUT}" && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

rsync -a --delete \
    --exclude .git --exclude .claude --exclude docs-site --exclude benchmarks --exclude .venv \
    --exclude dist --exclude build --exclude output --exclude '__pycache__' --exclude '*.egg-info' \
    "${ROOT}/" "${WORK}/src/"
cd "${WORK}/src"
scripts/stamp-version.sh "${VERSION}" >/dev/null
make --no-print-directory dist-cli dist-installers dist-requirements DIST_DIR="${OUT}" >/dev/null
make --no-print-directory sync-openclaw-extension >/dev/null

for target in "${TARGETS[@]}"; do
    goos="${target%/*}"
    goarch="${target#*/}"
    stage="${WORK}/stage-${goos}-${goarch}"
    mkdir -p "${stage}"
    exe=""
    [[ "${goos}" == windows ]] && exe=".exe"
    ldflags="-s -w -X main.version=${VERSION}"
    GOOS="${goos}" GOARCH="${goarch}" CGO_ENABLED=0 go build -trimpath -ldflags "${ldflags}" \
        -o "${stage}/defenseclaw-gateway${exe}" ./cmd/defenseclaw
    GOOS="${goos}" GOARCH="${goarch}" CGO_ENABLED=0 go build -trimpath -ldflags "${ldflags}" \
        -o "${stage}/defenseclaw-acp${exe}" ./cmd/defenseclaw-acp
    if [[ "${goos}" == windows ]]; then
        GOOS="${goos}" GOARCH="${goarch}" CGO_ENABLED=0 go build -trimpath -ldflags "${ldflags} -H=windowsgui" \
            -o "${stage}/defenseclaw-hook.exe" ./cmd/defenseclaw-hook
        (cd "${stage}" && rm -f "${OUT}/defenseclaw-${VERSION}-${goos}-${goarch}.zip" \
            && zip -q "${OUT}/defenseclaw-${VERSION}-${goos}-${goarch}.zip" ./*)
    else
        COPYFILE_DISABLE=1 tar -czf "${OUT}/defenseclaw-${VERSION}-${goos}-${goarch}.tar.gz" -C "${stage}" .
    fi
done

make --no-print-directory dist-checksums DIST_DIR="${OUT}" >/dev/null
ls -1 "${OUT}"
