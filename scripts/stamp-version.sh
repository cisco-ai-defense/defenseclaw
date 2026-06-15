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

#
# Stamp a single semver across every in-repo version source.
#
# The git tag is the source of truth for releases; the release workflow
# invokes this script before building so that the wheel
# (`defenseclaw-X.Y.Z-py3-none-any.whl`) and plugin tarball
# (`defenseclaw-plugin-X.Y.Z.tar.gz`) names match the tag, which in turn
# matches what `install.sh` and `defenseclaw upgrade` look up.
#
# Sources kept in lock-step:
#   1. Makefile                                 (VERSION := X.Y.Z)
#   2. pyproject.toml                           (version = "X.Y.Z")
#   3. cli/defenseclaw/__init__.py              (__version__ = "X.Y.Z")
#   4. extensions/defenseclaw/package.json      ("version": "X.Y.Z")
#
# Usage:
#   scripts/stamp-version.sh 0.4.0
#   make set-version VERSION=0.4.0
#
# Idempotent: re-running with the same version is a no-op. The script
# fails loudly if any of the four files cannot be located or already
# contains a value that does not match the regex it expects, so a silent
# drift never reaches a release artifact.

set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "usage: $0 <version>" >&2
    exit 64
fi

VERSION="$1"

# Strict semver only. Refuse pre-release / build-metadata suffixes for now —
# the upgrade flow's URL builders assume bare X.Y.Z, so anything else would
# silently 404 on `defenseclaw upgrade --version <pre-release>`. Reject here
# rather than producing a release that the upgrade script cannot consume.
if [[ ! "${VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "error: version must be X.Y.Z (got: ${VERSION})" >&2
    exit 64
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

# Cross-platform sed -i wrapper: BSD sed (macOS) requires an explicit empty
# string after -i, GNU sed (Linux) does not. Detect and dispatch so this
# script works on both developer macs and the ubuntu-latest GH runner.
sed_in_place() {
    if sed --version >/dev/null 2>&1; then
        sed -i "$@"
    else
        sed -i '' "$@"
    fi
}

# Each stamp_*() is a separate function so a failure pinpoints which file
# is malformed (the trap prints the failing function name).

stamp_makefile() {
    local f="Makefile"
    [[ -f "${f}" ]] || { echo "error: ${f} not found" >&2; return 1; }
    grep -qE '^VERSION[[:space:]]*:=[[:space:]]*[0-9]+\.[0-9]+\.[0-9]+[[:space:]]*$' "${f}" \
        || { echo "error: ${f} does not match expected 'VERSION := X.Y.Z' line" >&2; return 1; }
    sed_in_place -E "s/^(VERSION[[:space:]]*:=[[:space:]]*)[0-9]+\.[0-9]+\.[0-9]+([[:space:]]*)\$/\1${VERSION}\2/" "${f}"
}

stamp_pyproject() {
    local f="pyproject.toml"
    [[ -f "${f}" ]] || { echo "error: ${f} not found" >&2; return 1; }
    grep -qE '^version[[:space:]]*=[[:space:]]*"[0-9]+\.[0-9]+\.[0-9]+"[[:space:]]*$' "${f}" \
        || { echo "error: ${f} does not match expected 'version = \"X.Y.Z\"' line" >&2; return 1; }
    sed_in_place -E "s/^(version[[:space:]]*=[[:space:]]*\")[0-9]+\.[0-9]+\.[0-9]+(\"[[:space:]]*)\$/\1${VERSION}\2/" "${f}"
}

stamp_init_py() {
    local f="cli/defenseclaw/__init__.py"
    [[ -f "${f}" ]] || { echo "error: ${f} not found" >&2; return 1; }
    grep -qE '^__version__[[:space:]]*=[[:space:]]*"[0-9]+\.[0-9]+\.[0-9]+"[[:space:]]*$' "${f}" \
        || { echo "error: ${f} does not match expected '__version__ = \"X.Y.Z\"' line" >&2; return 1; }
    sed_in_place -E "s/^(__version__[[:space:]]*=[[:space:]]*\")[0-9]+\.[0-9]+\.[0-9]+(\"[[:space:]]*)\$/\1${VERSION}\2/" "${f}"
}

stamp_package_json() {
    local f="extensions/defenseclaw/package.json"
    [[ -f "${f}" ]] || { echo "error: ${f} not found" >&2; return 1; }
    # Anchor on the leading-two-space indentation that npm uses for package.json
    # so we only touch the top-level "version" field, never a nested one inside
    # dependency/devDependency blocks.
    grep -qE '^  "version":[[:space:]]*"[0-9]+\.[0-9]+\.[0-9]+",?[[:space:]]*$' "${f}" \
        || { echo "error: ${f} does not match expected '  \"version\": \"X.Y.Z\",' line" >&2; return 1; }
    sed_in_place -E "s/^(  \"version\":[[:space:]]*\")[0-9]+\.[0-9]+\.[0-9]+(\",?[[:space:]]*)\$/\1${VERSION}\2/" "${f}"
}

stamp_makefile
stamp_pyproject
stamp_init_py
stamp_package_json

echo "stamped version ${VERSION} into:"
echo "  Makefile"
echo "  pyproject.toml"
echo "  cli/defenseclaw/__init__.py"
echo "  extensions/defenseclaw/package.json"
