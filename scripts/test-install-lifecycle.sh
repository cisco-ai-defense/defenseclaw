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

# End-to-end install/upgrade/rollback test for scripts/install.sh.
#
#   scripts/test-install-lifecycle.sh --assets DIR [--previous-assets DIR]
#       [--lanes "fresh upgrade-previous upgrade-0.8.10 handoff drills macos-app"] [--keep]
#
# upgrade-0.X.Y upgrades from any published 0.x release (upgrade-0.8.4 imports
# a pre-v8 configuration).
#
# Every lane runs in its own throwaway HOME with the gateway on a free port,
# so it never touches the real install. DIR holds release-shaped assets
# (scripts/build-release-assets.sh or a downloaded release).

set -euo pipefail

ASSETS=""
PREVIOUS_ASSETS=""
LANES="fresh"
KEEP=false
LEGACY_VERSION="0.8.10"
while [[ $# -gt 0 ]]; do
    case "$1" in
        --assets) ASSETS="$(cd "$2" && pwd)"; shift ;;
        --previous-assets) PREVIOUS_ASSETS="$(cd "$2" && pwd)"; shift ;;
        --lanes) LANES="$2"; shift ;;
        --keep) KEEP=true ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
    shift
done
[[ -n "${ASSETS}" ]] || { echo "--assets DIR is required" >&2; exit 2; }

# Physical path: DefenseClaw refuses a data dir reached through a symlink
# (macOS /tmp and /var/folders are symlinks).
ROOT="$(cd "$(mktemp -d "${TMPDIR:-/tmp}/dc-lifecycle.XXXXXX")" && pwd -P)"
chmod 700 "${ROOT}"
TOOLS="${ROOT}/tools"
mkdir -p "${TOOLS}"
ln -s "$(command -v uv)" "${TOOLS}/uv"
# --color never: FORCE_COLOR would otherwise wrap the paths in escape codes,
# which then read as relative paths under the installer's working directory.
REAL_UV_CACHE="$(uv --color never cache dir 2>/dev/null || true)"
REAL_UV_PYTHON="$(uv --color never python dir 2>/dev/null || true)"
# cosign stays off the lane PATH, so installers only see it through with_cosign.
COSIGN_BIN="${ROOT}/cosign-bin"
if command -v cosign >/dev/null 2>&1; then
    mkdir -p "${COSIGN_BIN}"
    ln -s "$(command -v cosign)" "${COSIGN_BIN}/cosign"
fi
LANE_HOMES=()
FAILURES=0

version_of() { grep -Eo '[0-9]+\.[0-9]+\.[0-9]+' <<<"$1" | head -1; }
TARGET="$(ls "${ASSETS}"/defenseclaw-*-py3-none-any.whl | head -1)"
TARGET="$(version_of "$(basename "${TARGET}")")"

log() { printf '\n\033[1m[lifecycle] %s\033[0m\n' "$*"; }
fail() { printf '\033[31m[lifecycle] FAIL: %s\033[0m\n' "$*" >&2; FAILURES=$((FAILURES + 1)); return 1; }
# must CMD...: run a step; a failure is recorded and ends the lane.
must() { "$@" || { fail "step failed: $*"; return 1; }; }

# enter_lane NAME: fresh HOME and environment for one lane.
enter_lane() {
    export HOME="${ROOT}/$1"
    mkdir -p "${HOME}"
    chmod 700 "${HOME}"
    LANE_HOMES+=("${HOME}")
    export PATH="${HOME}/.local/bin:${TOOLS}:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
    export DEFENSECLAW_NO_UPDATE_CHECK=1
    # Never touch a real /Applications/DefenseClawMac.app.
    export DEFENSECLAW_APP_PATH=none
    export UV_CACHE_DIR="${REAL_UV_CACHE:-${ROOT}/uv-cache}"
    [[ -n "${REAL_UV_PYTHON}" ]] && export UV_PYTHON_INSTALL_DIR="${REAL_UV_PYTHON}"
    unset DEFENSECLAW_HOME DEFENSECLAW_CONFIG DEFENSECLAW_UPGRADE_FRESH_PROCESS
    DC_HOME="${HOME}/.defenseclaw"
}

free_port() {
    python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])'
}

# with_cosign CMD...: run CMD with cosign on PATH, when this host has it.
with_cosign() { PATH="${COSIGN_BIN}:${PATH}" "$@"; }

install_candidate() { bash "$1/install.sh" --local "$1" --yes; }
# The documented one-liner pipes install.sh into bash; the script arrives on stdin.
install_candidate_piped() { cat "$1/install.sh" | bash -s -- --local "$1" --yes; }

# install_legacy: install LEGACY_VERSION with its own installer. Releases before
# 0.8.5 published it only in the source tree.
install_legacy() {
    local installer="${ROOT}/install-${LEGACY_VERSION}.sh"
    [[ -f "${installer}" ]] || curl -fsSL -o "${installer}" \
        "https://github.com/cisco-ai-defense/defenseclaw/releases/download/${LEGACY_VERSION}/install.sh" \
        || curl -fsSL -o "${installer}" \
        "https://raw.githubusercontent.com/cisco-ai-defense/defenseclaw/${LEGACY_VERSION}/scripts/install.sh"
    # The 0.8.4 installer refuses to run without cosign on PATH.
    VERSION="${LEGACY_VERSION}" with_cosign bash "${installer}" --yes --no-openclaw
}

# init_and_start: create a config, move the gateway to a free port, start it.
# Callers run it under "must", where errexit is off, so every step returns.
init_and_start() {
    local init=(init --non-interactive --no-start-gateway --no-verify --skip-install) help
    # Releases before 0.8.5 have no "--connector none"; their init defaults to codex.
    help="$("${HOME}/.local/bin/defenseclaw" init --help 2>/dev/null || true)"
    if [[ "${help}" == *"|none]"* ]]; then
        init+=(--connector none)
    fi
    "${HOME}/.local/bin/defenseclaw" "${init[@]}" >/dev/null || return 1
    PORT="$(free_port)"
    "${DC_HOME}/.venv/bin/python" -I - "${DC_HOME}/config.yaml" "${PORT}" <<'PY' || return 1
import sys, yaml
path, port = sys.argv[1], int(sys.argv[2])
with open(path, encoding="utf-8") as stream:
    config = yaml.safe_load(stream)
config.setdefault("gateway", {})["api_port"] = port
with open(path, "w", encoding="utf-8") as stream:
    yaml.safe_dump(config, stream, sort_keys=False)
PY
    echo "lifecycle-marker" > "${DC_HOME}/lifecycle-marker.txt" || return 1
    "${HOME}/.local/bin/defenseclaw-gateway" start >/dev/null
}

# rechecksum DIR: rewrite checksums.txt after a drill edited assets; the release
# signature no longer applies.
rechecksum() {
    (cd "$1" && rm -f checksums.txt.bundle checksums.txt.sig checksums.txt.pem \
        && find . -maxdepth 1 -type f ! -name '.*' ! -name 'checksums.txt*' | sed 's#^\./##' | sort | xargs shasum -a 256 > checksums.txt)
}

# break_migration WHEEL: after the swap, migrate writes to config.yaml and then
# fails; migrate --check still passes.
break_migration() {
    python3 - "$1" <<'PY'
import base64, hashlib, os, sys, zipfile

path, target = sys.argv[1], "defenseclaw/migrations.py"
drill = b"""

_drill_real_migrate = migrate


def migrate(data_dir, **kwargs):
    if not kwargs.get("check"):
        with open(os.path.join(data_dir, "config.yaml"), "a", encoding="utf-8") as stream:
            stream.write("\\ndrill_partial_migration: true\\n")
        raise MigrationError("drill: this release's migration fails halfway")
    return _drill_real_migrate(data_dir, **kwargs)
"""
with zipfile.ZipFile(path) as wheel:
    infos = wheel.infolist()
    files = {info.filename: wheel.read(info.filename) for info in infos}
files[target] += drill
record = next(name for name in files if name.endswith(".dist-info/RECORD"))
digest = base64.urlsafe_b64encode(hashlib.sha256(files[target]).digest()).rstrip(b"=").decode()
files[record] = "".join(
    f"{target},sha256={digest},{len(files[target])}\n" if line.split(",")[0] == target else line + "\n"
    for line in files[record].decode().splitlines()
).encode()
with zipfile.ZipFile(path + ".new", "w", zipfile.ZIP_DEFLATED) as wheel:
    for info in infos:
        wheel.writestr(info, files[info.filename])
os.replace(path + ".new", path)
PY
}

# installer_copies: temporary installer copies that upgrade and rollback left in TMPDIR.
installer_copies() {
    find "${TMPDIR:-/tmp}/" -maxdepth 1 \( -name 'defenseclaw-upgrade-*' -o -name 'defenseclaw-rollback-*' \) 2>/dev/null \
        | wc -l | tr -d ' '
}

assert_versions() {
    local want="$1" cli gateway
    cli="$(version_of "$("${HOME}/.local/bin/defenseclaw" --version 2>/dev/null)")"
    gateway="$(version_of "$("${HOME}/.local/bin/defenseclaw-gateway" --version 2>/dev/null)")"
    [[ "${cli}" == "${want}" && "${gateway}" == "${want}" ]] \
        || fail "expected ${want}, got cli=${cli:-none} gateway=${gateway:-none}"
}

assert_healthy() {
    local port
    port="$("${DC_HOME}/.venv/bin/python" -I -c 'import sys, yaml; print(yaml.safe_load(open(sys.argv[1]))["gateway"]["api_port"])' "${DC_HOME}/config.yaml")"
    curl -fsS -o /dev/null "http://127.0.0.1:${port}/health" || fail "gateway on port ${port} is not healthy"
}

assert_data_kept() {
    [[ "$(cat "${DC_HOME}/lifecycle-marker.txt" 2>/dev/null)" == lifecycle-marker ]] || fail "data dir lost the marker file"
    [[ -f "${DC_HOME}/config.yaml" ]] || fail "config.yaml is missing"
}

stop_lane() {
    [[ -x "${HOME}/.local/bin/defenseclaw-gateway" ]] && "${HOME}/.local/bin/defenseclaw-gateway" stop >/dev/null 2>&1 || true
}

lane_fresh() {
    enter_lane fresh
    log "fresh install of ${TARGET} (piped, as the one-liner runs it)"
    must with_cosign install_candidate_piped "${ASSETS}" || return 1
    assert_versions "${TARGET}"
    if [[ -x "${COSIGN_BIN}/cosign" && -f "${ASSETS}/checksums.txt.bundle" ]]; then
        grep -q "Release signature verified" "$(ls -t "${DC_HOME}"/logs/install-*.log | head -1)" \
            || fail "cosign is installed but the installer did not verify the release signature"
    fi
    [[ ! -e "${DC_HOME}/previous" ]] || fail "a fresh install must not leave a rollback slot"
    [[ -f "${DC_HOME}/installer/install.sh" ]] || fail "installer copy was not saved"
    must init_and_start || return 1
    assert_healthy
    log "re-run the same version (repair)"
    local before
    before="$(shasum -a 256 "${DC_HOME}/config.yaml" | awk '{print $1}')"
    must install_candidate "${ASSETS}" || return 1
    assert_versions "${TARGET}"
    assert_healthy
    assert_data_kept
    [[ "$(shasum -a 256 "${DC_HOME}/config.yaml" | awk '{print $1}')" == "${before}" ]] || fail "re-run changed config.yaml"
    [[ ! -e "${DC_HOME}/previous" ]] || fail "a same-version re-run must not create a rollback slot"
    stop_lane
}

# upgrade_lane NAME FROM_VERSION INSTALL_FN: install FROM, upgrade to the
# candidate, roll back, roll forward.
upgrade_lane() {
    local name="$1" from="$2" installer="$3"
    enter_lane "${name}"
    log "${name}: install ${from}"
    must "${installer}" || return 1
    must init_and_start || return 1
    assert_versions "${from}"
    log "${name}: upgrade ${from} -> ${TARGET}"
    must install_candidate "${ASSETS}" || return 1
    assert_versions "${TARGET}"
    assert_healthy
    assert_data_kept
    [[ "$(cat "${DC_HOME}/previous/VERSION" 2>/dev/null)" == "${from}" ]] || fail "previous/VERSION is not ${from}"
    log "${name}: defenseclaw rollback"
    local copies
    copies="$(installer_copies)"
    must "${HOME}/.local/bin/defenseclaw" rollback --yes || return 1
    [[ "$(installer_copies)" == "${copies}" ]] || fail "defenseclaw rollback left its installer copy in ${TMPDIR:-/tmp}"
    assert_versions "${from}"
    assert_healthy
    assert_data_kept
    log "${name}: roll forward again"
    # After rolling back to 0.8.x the 1.x installer is only in previous/.
    local forward="${DC_HOME}/installer/install.sh"
    [[ -f "${forward}" ]] || forward="${DC_HOME}/previous/installer/install.sh"
    must bash "${forward}" --rollback --yes || return 1
    assert_versions "${TARGET}"
    assert_healthy
    if [[ "${name}" == upgrade-previous ]]; then
        log "${name}: moving to another version keeps the data a rollback parked"
        must install_candidate "${PREVIOUS_ASSETS}" || return 1
        assert_versions "${from}"
        ls -d "${DC_HOME}"/backups/rolled-back-* >/dev/null 2>&1 || fail "rolled-back data was not kept in backups/"
    fi
    stop_lane
}

install_previous() { install_candidate "${PREVIOUS_ASSETS}"; }

lane_handoff() {
    enter_lane handoff
    log "handoff: 0.8.x 'defenseclaw upgrade' runs defenseclaw-upgrade.sh"
    must install_legacy || return 1
    must init_and_start || return 1
    must env DEFENSECLAW_UPGRADE_FRESH_PROCESS=1 DEFENSECLAW_UPGRADE_LOCAL_DIR="${ASSETS}" \
        /bin/bash "${ASSETS}/defenseclaw-upgrade.sh" --yes --version "${TARGET}" || return 1
    assert_versions "${TARGET}"
    assert_healthy
    assert_data_kept
    stop_lane
}

app_version() {
    /usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$1/Contents/Info.plist" 2>/dev/null
}

# macOS: install.sh updates the app bundle with the runtime, and rollback
# swaps it back. Needs DefenseClawMac-<v>-macos-arm64.zip in both asset dirs.
lane_macos_app() {
    enter_lane macos-app
    local prev app
    prev="$(version_of "$(basename "$(ls "${PREVIOUS_ASSETS}"/defenseclaw-*-py3-none-any.whl | head -1)")")"
    app="${HOME}/Applications/DefenseClawMac.app"
    mkdir -p "${HOME}/Applications"
    must ditto -xk "${PREVIOUS_ASSETS}/DefenseClawMac-${prev}-macos-arm64.zip" "${HOME}/Applications" || return 1
    export DEFENSECLAW_APP_PATH="${app}" DEFENSECLAW_INSTALL_CALLER=app
    log "macos-app: install ${prev} with the app at ${app}"
    must install_candidate "${PREVIOUS_ASSETS}" || return 1
    must init_and_start || return 1
    [[ "$(app_version "${app}")" == "${prev}" ]] || fail "app is not ${prev} after install"
    log "macos-app: upgrade runtime and app to ${TARGET}"
    must install_candidate "${ASSETS}" || return 1
    assert_versions "${TARGET}"
    [[ "$(app_version "${app}")" == "${TARGET}" ]] || fail "app was not upgraded to ${TARGET}"
    [[ "$(app_version "${DC_HOME}/previous/DefenseClawMac.app")" == "${prev}" ]] || fail "previous/ lacks the ${prev} app"
    codesign --verify --deep --strict "${app}" 2>/dev/null || fail "upgraded app does not verify"
    log "macos-app: rollback restores the ${prev} app"
    must "${HOME}/.local/bin/defenseclaw" rollback --yes || return 1
    assert_versions "${prev}"
    [[ "$(app_version "${app}")" == "${prev}" ]] || fail "rollback did not restore the ${prev} app"
    must bash "${DC_HOME}/installer/install.sh" --rollback --yes || return 1
    [[ "$(app_version "${app}")" == "${TARGET}" ]] || fail "roll forward did not restore the ${TARGET} app"
    stop_lane
    export DEFENSECLAW_APP_PATH=none
    unset DEFENSECLAW_INSTALL_CALLER
}

# Failure drills: each must leave a working install behind.
lane_drills() {
    enter_lane drills
    log "drills: install ${TARGET}"
    must install_candidate "${ASSETS}" || return 1
    must init_and_start || return 1

    log "drills: a release whose gateway never becomes healthy rolls back"
    local broken="${ROOT}/broken-assets" archive stage
    rm -rf "${broken}"
    cp -R "${ASSETS}" "${broken}"
    archive="$(cd "${broken}" && ls defenseclaw-*-"$(uname -s | tr '[:upper:]' '[:lower:]')"-*.tar.gz | head -1)"
    stage="${ROOT}/broken-stage"
    rm -rf "${stage}"; mkdir -p "${stage}"
    tar -xzf "${broken}/${archive}" -C "${stage}"
    printf '#!/bin/sh\ncase "$1" in --version) echo "defenseclaw-gateway version %s" ;; *) exit 1 ;; esac\n' "${TARGET}" \
        > "${stage}/defenseclaw-gateway"
    chmod 755 "${stage}/defenseclaw-gateway"
    COPYFILE_DISABLE=1 tar -czf "${broken}/${archive}" -C "${stage}" .
    rechecksum "${broken}"
    if bash "${broken}/install.sh" --local "${broken}" --yes; then
        fail "a release whose gateway cannot start was reported as installed"
    fi
    assert_versions "${TARGET}"
    assert_healthy
    assert_data_kept
    grep -q "exit 1 ;;" "${HOME}/.local/bin/defenseclaw-gateway" && fail "the broken gateway was left installed"

    log "drills: a release whose migration fails halfway rolls back, data included"
    rm -rf "${broken}"
    cp -R "${ASSETS}" "${broken}"
    must break_migration "$(ls "${broken}"/defenseclaw-*-py3-none-any.whl | head -1)" || return 1
    rechecksum "${broken}"
    if bash "${broken}/install.sh" --local "${broken}" --yes; then
        fail "a release whose migration fails was reported as installed"
    fi
    assert_versions "${TARGET}"
    assert_healthy
    assert_data_kept
    grep -q drill_partial_migration "${DC_HOME}/config.yaml" && fail "the half-applied migration was left in config.yaml"
    grep -q "drill: this release" "${DC_HOME}"/.venv/lib/python*/site-packages/defenseclaw/migrations.py \
        && fail "the broken release's Python environment was left installed"

    log "drills: a configuration from a newer release is refused before any change"
    cp "${DC_HOME}/config.yaml" "${ROOT}/config.yaml.orig"
    sed -i.bak 's/^config_version: .*/config_version: 99/' "${DC_HOME}/config.yaml" && rm -f "${DC_HOME}/config.yaml.bak"
    if bash "${ASSETS}/install.sh" --local "${ASSETS}" --yes; then
        fail "an installer accepted a configuration from a newer release"
    fi
    cp "${ROOT}/config.yaml.orig" "${DC_HOME}/config.yaml"
    assert_versions "${TARGET}"

    log "drills: a CLI broken at import can still upgrade itself"
    local main_py
    main_py="$(ls "${DC_HOME}"/.venv/lib/python*/site-packages/defenseclaw/main.py | head -1)"
    printf 'raise ImportError("drill: broken release")\n' | cat - "${main_py}" > "${main_py}.new" && mv "${main_py}.new" "${main_py}"
    if "${HOME}/.local/bin/defenseclaw" status >/dev/null 2>&1; then
        fail "the drill did not break the CLI"
    fi
    local copies
    copies="$(installer_copies)"
    must env DEFENSECLAW_UPGRADE_LOCAL_DIR="${ASSETS}" "${HOME}/.local/bin/defenseclaw" upgrade --version "${TARGET}" --yes || return 1
    [[ "$(installer_copies)" == "${copies}" ]] || fail "defenseclaw upgrade left its installer copy in ${TMPDIR:-/tmp}"
    assert_versions "${TARGET}"
    assert_healthy
    "${HOME}/.local/bin/defenseclaw" status >/dev/null 2>&1 || fail "the upgrade did not repair the broken CLI"

    log "drills: an install killed mid-swap (power loss) is recovered by the next run"
    local out="${ROOT}/killed-install.log" installer tries=0
    bash "${ASSETS}/install.sh" --local "${ASSETS}" --yes > "${out}" 2>&1 &
    installer=$!
    until grep -q "Installing DefenseClaw" "${out}" 2>/dev/null || [[ ${tries} -ge 900 ]]; do
        sleep 0.2; tries=$((tries + 1))
    done
    pkill -9 -P "${installer}" 2>/dev/null || true
    kill -9 "${installer}" 2>/dev/null || true
    wait "${installer}" 2>/dev/null || true
    [[ -f "${DC_HOME}/.repair/COMPLETE" ]] || fail "the killed install left no complete snapshot"
    rm -rf "${DC_HOME}/.install.lock"
    must install_candidate "${ASSETS}" || return 1
    assert_versions "${TARGET}"
    assert_healthy
    assert_data_kept
    [[ ! -e "${DC_HOME}/.repair" ]] || fail "the recovered snapshot was left behind"

    log "drills: a stale gateway.pid naming another process is left alone"
    "${HOME}/.local/bin/defenseclaw-gateway" stop >/dev/null 2>&1 || true
    sleep 300 &
    local bystander=$!
    printf '{"pid":%s}\n' "${bystander}" > "${DC_HOME}/gateway.pid"
    must install_candidate "${ASSETS}" || return 1
    kill -0 "${bystander}" 2>/dev/null || fail "the installer killed an unrelated process"
    kill "${bystander}" 2>/dev/null || true
    stop_lane
}

cleanup() {
    local home
    for home in ${LANE_HOMES[@]+"${LANE_HOMES[@]}"}; do
        [[ -x "${home}/.local/bin/defenseclaw-gateway" ]] && HOME="${home}" "${home}/.local/bin/defenseclaw-gateway" stop >/dev/null 2>&1 || true
    done
    if [[ "${KEEP}" == true ]]; then
        echo "kept ${ROOT}"
    else
        rm -rf "${ROOT}"
    fi
}
trap cleanup EXIT

for lane in ${LANES}; do
    case "${lane}" in
        fresh) lane_fresh || true ;;
        upgrade-previous)
            [[ -n "${PREVIOUS_ASSETS}" ]] || { echo "upgrade-previous needs --previous-assets" >&2; exit 2; }
            prev="$(version_of "$(basename "$(ls "${PREVIOUS_ASSETS}"/defenseclaw-*-py3-none-any.whl | head -1)")")"
            upgrade_lane upgrade-previous "${prev}" install_previous || true ;;
        upgrade-0.*)
            LEGACY_VERSION="${lane#upgrade-}"
            upgrade_lane "${lane}" "${LEGACY_VERSION}" install_legacy || true
            LEGACY_VERSION="0.8.10" ;;
        handoff) lane_handoff || true ;;
        drills) lane_drills || true ;;
        macos-app)
            [[ -n "${PREVIOUS_ASSETS}" ]] || { echo "macos-app needs --previous-assets" >&2; exit 2; }
            lane_macos_app || true ;;
        *) echo "unknown lane: ${lane}" >&2; exit 2 ;;
    esac
done

if [[ ${FAILURES} -gt 0 ]]; then
    printf '\033[31m[lifecycle] %d check(s) failed\033[0m\n' "${FAILURES}"
    exit 1
fi
printf '\033[32m[lifecycle] all lanes passed (%s)\033[0m\n' "${LANES}"
