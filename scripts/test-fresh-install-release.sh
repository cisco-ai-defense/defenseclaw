#!/usr/bin/env bash
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

# Exercise the exact sealed candidate through the public POSIX fresh installer.
# A second invocation must refuse before changing any installed byte or mode.

set -euo pipefail
umask 077

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ $# -ne 2 ]]; then
    echo "usage: $0 RELEASE_DIR VERSION" >&2
    exit 64
fi

RELEASE_DIR="$(cd "$1" && pwd)"
VERSION="$2"
[[ "${VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || {
    echo "invalid release version: ${VERSION}" >&2
    exit 64
}

for command_name in uv cosign python3; do
    command -v "${command_name}" >/dev/null 2>&1 || {
        echo "required command is unavailable: ${command_name}" >&2
        exit 1
    }
done

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/defenseclaw-fresh-release.XXXXXX")"
cleanup() {
    local status=$?
    chmod -R u+w "${WORKDIR}" 2>/dev/null || true
    rm -rf "${WORKDIR}"
    return "${status}"
}
trap cleanup EXIT

mkdir -p "${WORKDIR}/home/.local/bin" "${WORKDIR}/tmp"
export HOME="${WORKDIR}/home"
export DEFENSECLAW_HOME="${HOME}/.defenseclaw"
export TMPDIR="${WORKDIR}/tmp"
export PATH="${HOME}/.local/bin:$(dirname "$(command -v uv)"):$(dirname "$(command -v cosign)"):$(dirname "$(command -v python3)"):/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin"

snapshot_tree() {
    local output="$1"
    python3 - "${HOME}" "${output}" <<'PY'
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

root = Path(sys.argv[1])
output = Path(sys.argv[2])
rows = []
for path in [root, *sorted(root.rglob("*"), key=lambda item: str(item))]:
    info = path.lstat()
    row = {
        "path": "." if path == root else str(path.relative_to(root)),
        "mode": stat.S_IMODE(info.st_mode),
        "mtime_ns": info.st_mtime_ns,
        "type": stat.S_IFMT(info.st_mode),
        "uid": info.st_uid,
        "gid": info.st_gid,
    }
    if stat.S_ISLNK(info.st_mode):
        row["target"] = os.readlink(path)
    elif stat.S_ISREG(info.st_mode):
        row["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        row["size"] = info.st_size
    rows.append(row)
output.write_text(json.dumps(rows, sort_keys=True, separators=(",", ":")), encoding="utf-8")
PY
}

assert_exact_version() {
    local command_path="$1"
    local output
    output="$("${command_path}" --version 2>&1)" || {
        echo "version probe failed: ${command_path}" >&2
        exit 1
    }
    python3 - "${output}" "${VERSION}" <<'PY'
import re
import sys

output, expected = sys.argv[1:]
versions = re.findall(r"(?<![0-9.])([0-9]+\.[0-9]+\.[0-9]+)(?![0-9.])", output)
if versions != [expected]:
    raise SystemExit(f"version output did not report exact {expected}: {output!r}")
PY
}

VERSION="${VERSION}" bash "${ROOT}/scripts/install.sh" \
    --local "${RELEASE_DIR}" \
    --yes \
    --connector none \
    >"${WORKDIR}/install.log" 2>&1

assert_exact_version "${HOME}/.local/bin/defenseclaw"
assert_exact_version "${HOME}/.local/bin/defenseclaw-gateway"
snapshot_tree "${WORKDIR}/before.json"

set +e
VERSION="${VERSION}" bash "${ROOT}/scripts/install.sh" \
    --local "${RELEASE_DIR}" \
    --yes \
    --connector none \
    >"${WORKDIR}/refusal.log" 2>&1
refusal_status=$?
set -e

[[ "${refusal_status}" -ne 0 ]] || {
    echo "second fresh-installer invocation unexpectedly succeeded" >&2
    exit 1
}
grep -Fq "An existing DefenseClaw installation was detected" "${WORKDIR}/refusal.log"
grep -Fq "No changes were made" "${WORKDIR}/refusal.log"
if grep -Fq "Detecting platform" "${WORKDIR}/refusal.log"; then
    echo "second fresh-installer invocation crossed the preflight boundary" >&2
    exit 1
fi

snapshot_tree "${WORKDIR}/after.json"
cmp "${WORKDIR}/before.json" "${WORKDIR}/after.json" >/dev/null || {
    echo "second fresh-installer invocation changed installed state" >&2
    exit 1
}

echo "fresh POSIX install passed: ${VERSION} ($(uname -s)/$(uname -m))"
