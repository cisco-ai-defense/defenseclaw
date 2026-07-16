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
# The manually dispatched release workflow's validated version input is the
# source of truth for published artifacts. It invokes this helper in each
# isolated build checkout before building, so every release-owned package and
# manifest receives the same version without requiring a version-only PR.
#
# Sources kept in lock-step:
#   1. Makefile                                 (VERSION := X.Y.Z)
#   2. pyproject.toml                           (version = "X.Y.Z")
#   3. cli/defenseclaw/__init__.py              (__version__ = "X.Y.Z")
#   4. extensions/defenseclaw/package.json      ("version": "X.Y.Z")
#   5. extensions/defenseclaw/package-lock.json (root package versions)
#   6. uv.lock                                  (editable project version)
#   7. macos/DefenseClawMac Xcode project       (MARKETING_VERSION = X.Y.Z)
#   8. release/source-install-identity.json      (source_release)
#
# Usage:
#   scripts/stamp-version.sh 0.4.0
#   make set-version VERSION=0.4.0
#
# Idempotent: re-running with the same version is a no-op. The script
# fails loudly if any of the eight files cannot be located or already
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

stamp_package_lock() {
    local f="extensions/defenseclaw/package-lock.json"
    [[ -f "${f}" ]] || { echo "error: ${f} not found" >&2; return 1; }
    python3 - "${f}" "${VERSION}" <<'PY'
from pathlib import Path
import json
import sys

path = Path(sys.argv[1])
version = sys.argv[2]
payload = json.loads(path.read_text(encoding="utf-8"))
packages = payload.get("packages")
root = packages.get("") if isinstance(packages, dict) else None
if not isinstance(payload.get("version"), str) or not isinstance(root, dict):
    raise SystemExit(f"error: {path} lacks npm root-package version fields")
if not isinstance(root.get("version"), str):
    raise SystemExit(f"error: {path} root package lacks a version")
payload["version"] = version
root["version"] = version
path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
PY
}

stamp_uv_lock() {
    local f="uv.lock"
    [[ -f "${f}" ]] || { echo "error: ${f} not found" >&2; return 1; }
    python3 - "${f}" "${VERSION}" <<'PY'
from pathlib import Path
import re
import sys

path = Path(sys.argv[1])
version = sys.argv[2]
text = path.read_text(encoding="utf-8")
pattern = re.compile(
    r'(^\[\[package\]\]\nname = "defenseclaw"\nversion = ")[^"]+("\nsource = \{ editable = "\." \}$)',
    re.MULTILINE,
)
updated, count = pattern.subn(rf"\g<1>{version}\g<2>", text)
if count != 1:
    raise SystemExit(f"error: {path} must contain one editable defenseclaw package version")
path.write_text(updated, encoding="utf-8")
PY
}

stamp_macos_project() {
    local f="macos/DefenseClawMac/DefenseClawMac.xcodeproj/project.pbxproj"
    [[ -f "${f}" ]] || { echo "error: ${f} not found" >&2; return 1; }
    local count
    count="$(grep -cE '^[[:space:]]*MARKETING_VERSION[[:space:]]*=[[:space:]]*[0-9]+\.[0-9]+\.[0-9]+;[[:space:]]*$' "${f}")"
    [[ "${count}" == "2" ]] \
        || { echo "error: ${f} must contain exactly two MARKETING_VERSION = X.Y.Z lines (found ${count})" >&2; return 1; }
    sed_in_place -E "s/^([[:space:]]*MARKETING_VERSION[[:space:]]*=[[:space:]]*)[0-9]+\.[0-9]+\.[0-9]+(;[[:space:]]*)\$/\1${VERSION}\2/" "${f}"
}

stamp_source_install_identity() {
    local f="release/source-install-identity.json"
    [[ -f "${f}" ]] || { echo "error: ${f} not found" >&2; return 1; }
    python3 - "${f}" "${VERSION}" <<'PY'
from pathlib import Path
import json
import sys

path = Path(sys.argv[1])
version = sys.argv[2]
payload = json.loads(path.read_text(encoding="utf-8"))
expected = {
    "runtime_config_version",
    "schema_version",
    "source_install_compatibility_epoch",
    "source_release",
}
if not isinstance(payload, dict) or set(payload) != expected or payload.get("schema_version") != 1:
    raise SystemExit(f"error: {path} has an unsupported source-install identity schema")
payload["source_release"] = version
path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
}

stamp_makefile
stamp_pyproject
stamp_init_py
stamp_package_json
stamp_package_lock
stamp_uv_lock
stamp_macos_project
stamp_source_install_identity
python3 scripts/source_release_identity.py check --expected-release "${VERSION}"

echo "stamped version ${VERSION} into:"
echo "  Makefile"
echo "  pyproject.toml"
echo "  cli/defenseclaw/__init__.py"
echo "  extensions/defenseclaw/package.json"
echo "  extensions/defenseclaw/package-lock.json"
echo "  uv.lock"
echo "  macos/DefenseClawMac/DefenseClawMac.xcodeproj/project.pbxproj"
echo "  release/source-install-identity.json"
