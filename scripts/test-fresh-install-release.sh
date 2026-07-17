#!/usr/bin/env bash
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

# Exercise the exact sealed candidate through the public POSIX fresh installer.
# The primary install deliberately hides the runner's Cosign so the pinned,
# temporary verifier path is release-gated. A separate isolated install keeps
# the preinstalled/external Cosign path covered. The primary install's second
# invocation must refuse before changing any installed byte or mode.

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

EXTERNAL_COSIGN="$(command -v cosign)"

sha256_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    else
        echo "sha256sum or shasum is required" >&2
        exit 1
    fi
}

EXTERNAL_COSIGN_SHA256="$(sha256_file "${EXTERNAL_COSIGN}")"

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/defenseclaw-fresh-release.XXXXXX")"
WORKDIR="$(cd "${WORKDIR}" && pwd -P)"
cleanup() {
    local status=$?
    chmod -R u+w "${WORKDIR}" 2>/dev/null || true
    rm -rf "${WORKDIR}"
    return "${status}"
}
trap cleanup EXIT

BOOTSTRAP_HOME="${WORKDIR}/bootstrap/home"
BOOTSTRAP_TMP="${WORKDIR}/bootstrap/tmp"
EXTERNAL_HOME="${WORKDIR}/external/home"
EXTERNAL_TMP="${WORKDIR}/external/tmp"
COMMON_TOOL_BIN="${WORKDIR}/common-tool-bin"
EXTERNAL_TOOL_BIN="${WORKDIR}/external-tool-bin"
EXTERNAL_COSIGN_MARKER="${WORKDIR}/external-cosign-invoked"

mkdir -p \
    "${BOOTSTRAP_HOME}/.local/bin" \
    "${BOOTSTRAP_TMP}" \
    "${EXTERNAL_HOME}/.local/bin" \
    "${EXTERNAL_TMP}" \
    "${COMMON_TOOL_BIN}" \
    "${EXTERNAL_TOOL_BIN}"

# Do not inherit Homebrew, /usr/local, or the Actions tool cache into the
# bootstrap case. Only the explicitly selected uv/Python plus OS base tools
# are visible. This makes an accidentally preinstalled Cosign unable to mask
# the installer's pinned bootstrap path.
ln -s "$(command -v uv)" "${COMMON_TOOL_BIN}/uv"
ln -s "$(command -v python3)" "${COMMON_TOOL_BIN}/python3"
readonly BASE_TOOL_PATH="${COMMON_TOOL_BIN}:/usr/bin:/bin:/usr/sbin:/sbin"
readonly BOOTSTRAP_PATH="${BOOTSTRAP_HOME}/.local/bin:${BASE_TOOL_PATH}"

if HOME="${BOOTSTRAP_HOME}" PATH="${BOOTSTRAP_PATH}" command -v cosign >/dev/null 2>&1; then
    echo "bootstrap fresh-install case still exposes an ambient Cosign" >&2
    exit 1
fi

# The external-Cosign case uses an explicit wrapper so the gate proves that
# the installer invoked the already-present verifier instead of bootstrapping.
python3 - "${EXTERNAL_TOOL_BIN}/cosign" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
path.write_text(
    "#!/bin/sh\n"
    "set -eu\n"
    "printf 'invoked\\n' >> \"${EXTERNAL_COSIGN_MARKER:?}\"\n"
    "exec \"${EXTERNAL_COSIGN_PATH:?}\" \"$@\"\n",
    encoding="utf-8",
)
path.chmod(0o700)
PY
readonly EXTERNAL_PATH="${EXTERNAL_HOME}/.local/bin:${EXTERNAL_TOOL_BIN}:${BASE_TOOL_PATH}"

snapshot_tree() {
    local root="$1" output="$2"
    python3 - "${root}" "${output}" <<'PY'
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

assert_bootstrap_retired_privately() {
    local normalized_os normalized_arch filename
    normalized_os="$(uname -s | tr '[:upper:]' '[:lower:]')"
    case "$(uname -m)" in
        x86_64|amd64) normalized_arch="amd64" ;;
        arm64|aarch64) normalized_arch="arm64" ;;
        *)
            echo "unsupported architecture in fresh-install gate: $(uname -m)" >&2
            exit 1
            ;;
    esac
    filename="cosign-${normalized_os}-${normalized_arch}"
    python3 - "${BOOTSTRAP_TMP}" "${filename}" <<'PY'
from pathlib import Path
import stat
import sys

root = Path(sys.argv[1])
filename = sys.argv[2]
matches = list(root.rglob(filename))
if len(matches) != 1:
    raise SystemExit(
        f"expected exactly one retired temporary Cosign verifier, found {len(matches)}"
    )
relative = matches[0].relative_to(root)
parts = relative.parts
if (
    len(parts) != 3
    or not parts[0].startswith(".defenseclaw-install-custody-")
    or not parts[1].startswith("retired-")
    or parts[2] != filename
):
    raise SystemExit(f"temporary Cosign was not retired into bounded custody: {relative}")
for path in (matches[0], matches[0].parent, matches[0].parent.parent):
    if stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise SystemExit(f"temporary Cosign custody is not private: {path}")
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

if ! HOME="${BOOTSTRAP_HOME}" \
    DEFENSECLAW_HOME="${BOOTSTRAP_HOME}/.defenseclaw" \
    TMPDIR="${BOOTSTRAP_TMP}" \
    PATH="${BOOTSTRAP_PATH}" \
    VERSION="${VERSION}" \
    /bin/bash "${ROOT}/scripts/install.sh" \
    --local "${RELEASE_DIR}" \
    --yes \
    --connector none \
    >"${WORKDIR}/bootstrap-install.log" 2>&1
then
    echo "fresh installer without ambient Cosign failed; captured output follows:" >&2
    cat "${WORKDIR}/bootstrap-install.log" >&2
    exit 1
fi

grep -Fq "Cosign was not found; authenticating temporary Cosign 2.6.3" \
    "${WORKDIR}/bootstrap-install.log"
grep -Fq "Temporary Cosign verifier authenticated" "${WORKDIR}/bootstrap-install.log"
grep -Fq "Authenticated policy material was retired, not deleted" \
    "${WORKDIR}/bootstrap-install.log"
assert_bootstrap_retired_privately
[[ ! -e "${BOOTSTRAP_HOME}/.local/bin/cosign" && ! -L "${BOOTSTRAP_HOME}/.local/bin/cosign" ]] || {
    echo "temporary Cosign was installed into the user's executable path" >&2
    exit 1
}
if HOME="${BOOTSTRAP_HOME}" PATH="${BOOTSTRAP_PATH}" command -v cosign >/dev/null 2>&1; then
    echo "temporary Cosign remained globally discoverable after installation" >&2
    exit 1
fi

assert_exact_version "${BOOTSTRAP_HOME}/.local/bin/defenseclaw"
assert_exact_version "${BOOTSTRAP_HOME}/.local/bin/defenseclaw-gateway"
snapshot_tree "${BOOTSTRAP_HOME}" "${WORKDIR}/before.json"

set +e
HOME="${BOOTSTRAP_HOME}" \
DEFENSECLAW_HOME="${BOOTSTRAP_HOME}/.defenseclaw" \
TMPDIR="${BOOTSTRAP_TMP}" \
PATH="${BOOTSTRAP_PATH}" \
VERSION="${VERSION}" \
/bin/bash "${ROOT}/scripts/install.sh" \
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

snapshot_tree "${BOOTSTRAP_HOME}" "${WORKDIR}/after.json"
cmp "${WORKDIR}/before.json" "${WORKDIR}/after.json" >/dev/null || {
    echo "second fresh-installer invocation changed installed state" >&2
    exit 1
}

if ! HOME="${EXTERNAL_HOME}" \
    DEFENSECLAW_HOME="${EXTERNAL_HOME}/.defenseclaw" \
    TMPDIR="${EXTERNAL_TMP}" \
    PATH="${EXTERNAL_PATH}" \
    EXTERNAL_COSIGN_PATH="${EXTERNAL_COSIGN}" \
    EXTERNAL_COSIGN_MARKER="${EXTERNAL_COSIGN_MARKER}" \
    VERSION="${VERSION}" \
    /bin/bash "${ROOT}/scripts/install.sh" \
    --local "${RELEASE_DIR}" \
    --yes \
    --connector none \
    >"${WORKDIR}/external-install.log" 2>&1
then
    echo "fresh installer with external Cosign failed; captured output follows:" >&2
    cat "${WORKDIR}/external-install.log" >&2
    exit 1
fi

[[ -s "${EXTERNAL_COSIGN_MARKER}" ]] || {
    echo "external Cosign wrapper was not invoked" >&2
    exit 1
}
if grep -Fq "Cosign was not found" "${WORKDIR}/external-install.log"; then
    echo "external-Cosign case unexpectedly used the bootstrap verifier" >&2
    exit 1
fi
if find "${EXTERNAL_TMP}" -name 'cosign-*' -print -quit | grep -q .; then
    echo "external-Cosign case left an unexpected bootstrap verifier" >&2
    exit 1
fi
assert_exact_version "${EXTERNAL_HOME}/.local/bin/defenseclaw"
assert_exact_version "${EXTERNAL_HOME}/.local/bin/defenseclaw-gateway"

[[ "$(command -v cosign)" == "${EXTERNAL_COSIGN}" ]] || {
    echo "the ambient Cosign command changed during fresh-install testing" >&2
    exit 1
}
[[ "$(sha256_file "${EXTERNAL_COSIGN}")" == "${EXTERNAL_COSIGN_SHA256}" ]] || {
    echo "the ambient Cosign binary changed during fresh-install testing" >&2
    exit 1
}

echo "fresh POSIX installs passed with temporary and external Cosign: ${VERSION} ($(uname -s)/$(uname -m))"
