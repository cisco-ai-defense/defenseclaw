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
#       [--lanes "fresh upgrade-previous upgrade-0.8.10 handoff"] [--keep]
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
REAL_UV_CACHE="$(uv cache dir 2>/dev/null || true)"
REAL_UV_PYTHON="$(uv python dir 2>/dev/null || true)"
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
    export UV_CACHE_DIR="${REAL_UV_CACHE:-${ROOT}/uv-cache}"
    [[ -n "${REAL_UV_PYTHON}" ]] && export UV_PYTHON_INSTALL_DIR="${REAL_UV_PYTHON}"
    unset DEFENSECLAW_HOME DEFENSECLAW_CONFIG DEFENSECLAW_UPGRADE_FRESH_PROCESS
    DC_HOME="${HOME}/.defenseclaw"
}

free_port() {
    python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])'
}

install_candidate() { bash "$1/install.sh" --local "$1" --yes; }

install_legacy() {
    local installer="${ROOT}/install-${LEGACY_VERSION}.sh"
    [[ -f "${installer}" ]] || curl -fsSL -o "${installer}" \
        "https://github.com/cisco-ai-defense/defenseclaw/releases/download/${LEGACY_VERSION}/install.sh"
    VERSION="${LEGACY_VERSION}" bash "${installer}" --yes --no-openclaw
}

# init_and_start: create a config, move the gateway to a free port, start it.
init_and_start() {
    "${HOME}/.local/bin/defenseclaw" init --non-interactive --connector none --no-start-gateway --no-verify \
        --skip-install >/dev/null
    PORT="$(free_port)"
    "${DC_HOME}/.venv/bin/python" -I - "${DC_HOME}/config.yaml" "${PORT}" <<'PY'
import sys, yaml
path, port = sys.argv[1], int(sys.argv[2])
with open(path, encoding="utf-8") as stream:
    config = yaml.safe_load(stream)
config.setdefault("gateway", {})["api_port"] = port
with open(path, "w", encoding="utf-8") as stream:
    yaml.safe_dump(config, stream, sort_keys=False)
PY
    echo "lifecycle-marker" > "${DC_HOME}/lifecycle-marker.txt"
    "${HOME}/.local/bin/defenseclaw-gateway" start >/dev/null
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
    log "fresh install of ${TARGET}"
    must install_candidate "${ASSETS}" || return 1
    assert_versions "${TARGET}"
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
    must "${HOME}/.local/bin/defenseclaw" rollback --yes || return 1
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
        upgrade-0.8.10) upgrade_lane upgrade-legacy "${LEGACY_VERSION}" install_legacy || true ;;
        handoff) lane_handoff || true ;;
        *) echo "unknown lane: ${lane}" >&2; exit 2 ;;
    esac
done

if [[ ${FAILURES} -gt 0 ]]; then
    printf '\033[31m[lifecycle] %d check(s) failed\033[0m\n' "${FAILURES}"
    exit 1
fi
printf '\033[32m[lifecycle] all lanes passed (%s)\033[0m\n' "${LANES}"
