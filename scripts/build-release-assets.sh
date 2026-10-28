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
# The archives keep the mode go build gives the binaries, which follows the
# umask: a shared build host with umask 0002 archived them 0775 (GAP-0108).
umask 022

VERSION="${1:?usage: $0 VERSION OUTDIR [os/arch ...]}"
OUT="${2:?usage: $0 VERSION OUTDIR [os/arch ...]}"
shift 2
TARGETS=("$@")
if [[ ${#TARGETS[@]} -eq 0 ]]; then
    TARGETS=("$(go env GOOS)/$(go env GOARCH)")
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# The scratch copy has no .git, so read the commit here. `defenseclaw version`
# then names the build instead of "commit=unknown, built=unknown".
COMMIT="$(git -C "${ROOT}" rev-parse --short HEAD 2>/dev/null || echo unknown)"
BUILT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
mkdir -p "${OUT}"
OUT="$(cd "${OUT}" && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

if command -v rsync >/dev/null 2>&1; then
    rsync -a --delete \
        --exclude .git --exclude .claude --exclude docs-site --exclude benchmarks --exclude .venv \
        --exclude dist --exclude build --exclude output --exclude '__pycache__' --exclude '*.egg-info' \
        "${ROOT}/" "${WORK}/src/"
else
    # Release smoke builds also run in minimal POSIX environments with no
    # rsync. The target is a new scratch directory, so no delete is needed.
    python3 - "${ROOT}" "${WORK}/src" <<'PY'
import shutil
import sys

shutil.copytree(
    sys.argv[1], sys.argv[2], symlinks=True,
    ignore=shutil.ignore_patterns(
        ".git", ".claude", "docs-site", "benchmarks", ".venv",
        "dist", "build", "output", "__pycache__", "*.egg-info",
    ),
)
PY
fi
# dist-cli builds the Fleet archive, whose policy compiler CTest reads this
# page. Keep the rest of docs-site out of the release smoke source copy.
FLEET_POLICY_PAGE="docs-site/content/docs/edge-connector/policies.mdx"
mkdir -p "${WORK}/src/${FLEET_POLICY_PAGE%/*}"
cp "${ROOT}/${FLEET_POLICY_PAGE}" "${WORK}/src/${FLEET_POLICY_PAGE}"
cd "${WORK}/src"
scripts/stamp-version.sh "${VERSION}" >/dev/null
make --no-print-directory dist-cli dist-installers dist-requirements DIST_DIR="${OUT}" >/dev/null
make --no-print-directory sync-openclaw-extension >/dev/null

for target in "${TARGETS[@]}"; do
    goos="${target%/*}"
    goarch="${target#*/}"
    stage="${WORK}/stage-${goos}-${goarch}"
    mkdir -p "${stage}"
    # Match GoReleaser: carry the version-matched compiler as an inert payload.
    # Installers copy it into the active data directory only when Fleet is on.
    mkdir -p "${stage}/edge-connector/tools"
    cp "${WORK}/src/edge-connector/tools/policy_compiler.py" \
        "${stage}/edge-connector/tools/policy_compiler.py"
    exe=""
    [[ "${goos}" == windows ]] && exe=".exe"
    ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${BUILT}"
    GOOS="${goos}" GOARCH="${goarch}" CGO_ENABLED=0 go build -trimpath -ldflags "${ldflags}" \
        -o "${stage}/defenseclaw-gateway${exe}" ./cmd/defenseclaw
    GOOS="${goos}" GOARCH="${goarch}" CGO_ENABLED=0 go build -trimpath -ldflags "${ldflags}" \
        -o "${stage}/defenseclaw-acp${exe}" ./cmd/defenseclaw-acp
    if [[ "${goos}" != windows ]]; then
        GOOS="${goos}" GOARCH="${goarch}" CGO_ENABLED=0 go build -trimpath -ldflags "${ldflags}" \
            -o "${stage}/defenseclaw-hook-post" ./cmd/defenseclaw-hook-post
        # The sandbox kernel feed (Linux); the release archive carries it on
        # every POSIX target, as .goreleaser.yaml's default archive does.
        GOOS="${goos}" GOARCH="${goarch}" CGO_ENABLED=0 go build -trimpath -ldflags "${ldflags}" \
            -o "${stage}/defenseclaw-sensor-helper" ./cmd/defenseclaw-sensor-helper
    fi
    if [[ "${goos}" == windows ]]; then
        GOOS="${goos}" GOARCH="${goarch}" CGO_ENABLED=0 go build -trimpath -ldflags "${ldflags} -H=windowsgui" \
            -o "${stage}/defenseclaw-hook.exe" ./cmd/defenseclaw-hook
        (cd "${stage}" && rm -f "${OUT}/defenseclaw-${VERSION}-${goos}-${goarch}.zip" \
            && zip -qr "${OUT}/defenseclaw-${VERSION}-${goos}-${goarch}.zip" ./*)
    else
        COPYFILE_DISABLE=1 tar -czf "${OUT}/defenseclaw-${VERSION}-${goos}-${goarch}.tar.gz" -C "${stage}" .
    fi
done

make --no-print-directory dist-checksums DIST_DIR="${OUT}" >/dev/null
ls -1 "${OUT}"
