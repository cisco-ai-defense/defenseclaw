#!/usr/bin/env bash
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

# Exercise an authenticated exact release candidate on a native Intel macOS
# runner and prove its fresh installer or upgrader refuses before invoking a
# dependency/network tool or creating product/recovery state.

set -euo pipefail

usage() {
    echo "usage: $0 --surface fresh-install|upgrade --release-dir DIR --version X.Y.Z" >&2
    exit 2
}

surface=""
release_dir=""
version=""
while (($#)); do
    case "$1" in
        --surface) [[ $# -ge 2 ]] || usage; surface="$2"; shift 2 ;;
        --release-dir) [[ $# -ge 2 ]] || usage; release_dir="$2"; shift 2 ;;
        --version) [[ $# -ge 2 ]] || usage; version="$2"; shift 2 ;;
        *) usage ;;
    esac
done

case "${surface}" in
    fresh-install|upgrade) ;;
    *) usage ;;
esac
[[ "${version}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || usage
[[ "$(uname -s)" == "Darwin" && "$(uname -m)" == "x86_64" ]] || {
    echo "this refusal gate requires native Intel macOS (Darwin/x86_64)" >&2
    exit 1
}
release_dir="$(cd -P -- "${release_dir}" && pwd -P)"
snapshot_python="$(command -v python3)"
platform_uname="$(command -v uname)"
[[ -n "${snapshot_python}" ]] || {
    echo "python3 is required to snapshot the exact candidate and isolated install roots" >&2
    exit 1
}
[[ -n "${platform_uname}" ]] || {
    echo "uname is required to exercise the native platform guard" >&2
    exit 1
}

snapshot_tree() {
    "${snapshot_python}" - "$1" <<'PY'
import hashlib
import os
import stat
import sys

root = os.path.realpath(sys.argv[1])
digest = hashlib.sha256()


def record(path: str, relative: str) -> None:
    metadata = os.lstat(path)
    fields = (
        relative,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_size,
        metadata.st_mtime_ns,
    )
    digest.update(repr(fields).encode("utf-8") + b"\0")
    if stat.S_ISLNK(metadata.st_mode):
        digest.update(os.readlink(path).encode("utf-8") + b"\0")
    elif stat.S_ISREG(metadata.st_mode):
        with open(path, "rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)


def walk(path: str, relative: str) -> None:
    record(path, relative)
    if not stat.S_ISDIR(os.lstat(path).st_mode):
        return
    with os.scandir(path) as entries:
        children = sorted(entries, key=lambda entry: os.fsencode(entry.name))
    for child in children:
        child_relative = child.name if relative == "." else f"{relative}/{child.name}"
        walk(child.path, child_relative)


walk(root, ".")
print(digest.hexdigest())
PY
}

case "${surface}" in
    fresh-install)
        controller="${release_dir}/install.sh"
        controller_args=(--local "${release_dir}" --yes --connector none)
        ;;
    upgrade)
        controller="${release_dir}/defenseclaw-upgrade.sh"
        controller_args=(--yes --version "${version}")
        ;;
esac
[[ -f "${controller}" && ! -L "${controller}" ]] || {
    echo "missing exact-candidate controller: ${controller}" >&2
    exit 1
}

test_root="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/defenseclaw-intel-refusal.XXXXXX")"
cleanup() {
    local status=$?
    rm -rf -- "${test_root}"
    return "${status}"
}
trap cleanup EXIT
chmod 700 "${test_root}"
home="${test_root}/home"
temp="${test_root}/tmp"
shims="${test_root}/shims"
command_log="${test_root}/commands.log"
stdout_log="${test_root}/${surface}.stdout"
stderr_log="${test_root}/${surface}.stderr"
mkdir -m 700 "${home}" "${temp}" "${shims}"

cat > "${shims}/blocked-command" <<'SH'
#!/bin/sh
printf '%s\n' "$0" >> "${DEFENSECLAW_INTEL_REFUSAL_COMMAND_LOG:?}"
exit 97
SH
chmod 700 "${shims}/blocked-command"
for command_name in \
    curl wget uv python python3 pip pip3 node npm go git \
    launchctl systemctl service brew docker podman openclaw \
    install installer pkgutil mkdir mktemp cp mv rm chmod chown touch ln tar unzip ditto; do
    ln -s blocked-command "${shims}/${command_name}"
done
# Preserve the platform probe selected by the calling environment so the same
# harness can exercise the real installer in a deterministic unit regression.
ln -s "${platform_uname}" "${shims}/uname"
# The fresh installer intentionally probes for existing product commands before
# platform detection. Exposing product shims there would manufacture an install
# and prevent the architecture guard from running. The upgrader has no such
# preflight, so retain product-command interception on that surface.
if [[ "${surface}" == "upgrade" ]]; then
    ln -s blocked-command "${shims}/defenseclaw"
    ln -s blocked-command "${shims}/defenseclaw-gateway"
fi

candidate_before="$(snapshot_tree "${release_dir}")"
home_before="$(snapshot_tree "${home}")"
temp_before="$(snapshot_tree "${temp}")"

set +e
/usr/bin/env -i \
    HOME="${home}" \
    TMPDIR="${temp}" \
    PATH="${shims}:/usr/bin:/bin:/usr/sbin:/sbin" \
    LANG=C \
    LC_ALL=C \
    CI=1 \
    DEFENSECLAW_HOME="${home}/.defenseclaw" \
    OPENCLAW_HOME="${home}/.openclaw" \
    DEFENSECLAW_INTEL_REFUSAL_COMMAND_LOG="${command_log}" \
    /bin/bash "${controller}" "${controller_args[@]}" \
    >"${stdout_log}" 2>"${stderr_log}"
status=$?
set -e

[[ "${status}" -ne 0 ]] || {
    echo "${surface} unexpectedly accepted Intel macOS" >&2
    exit 1
}
grep -q "Intel macOS" "${stdout_log}" "${stderr_log}" || {
    echo "${surface} did not report the Intel macOS support boundary" >&2
    cat "${stdout_log}" "${stderr_log}" >&2
    exit 1
}
[[ ! -s "${command_log}" ]] || {
    echo "${surface} invoked a dependency, network, service, or mutation command before refusal:" >&2
    cat "${command_log}" >&2
    exit 1
}
candidate_after="$(snapshot_tree "${release_dir}")"
home_after="$(snapshot_tree "${home}")"
temp_after="$(snapshot_tree "${temp}")"
if [[ "${candidate_after}" != "${candidate_before}" \
    || "${home_after}" != "${home_before}" \
    || "${temp_after}" != "${temp_before}" ]]; then
    echo "${surface} changed the exact candidate, install, recovery, or temporary state before refusal" >&2
    exit 1
fi

echo "Intel macOS ${surface} refusal passed before dependency, network, or state effects"
