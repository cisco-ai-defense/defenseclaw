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

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO="cisco-ai-defense/defenseclaw"
FROM_VERSION="${FROM_VERSION:-0.7.2}"
FROM_VERSIONS="${FROM_VERSIONS:-}"
TARGET_VERSION="${TARGET_VERSION:-}"
RELEASE_ROOT="${RELEASE_ROOT:-}"
RELEASE_DIR="${RELEASE_DIR:-}"
BASELINE_MODE="${BASELINE_MODE:-auto}" # auto | install | seed
HEALTH_TIMEOUT="${HEALTH_TIMEOUT:-1}"
PORT="${PORT:-}"
KEEP_WORKDIR="${KEEP_WORKDIR:-0}"
PREPARE_ONLY=0
BUILD_PLATFORM=""

WORKDIR=""
SERVER_PID=""
SMOKE_HOME=""
RELEASE_URL=""
FROM_VERSION_LIST=()

usage() {
    cat <<'EOF'
Usage: scripts/test-upgrade-release.sh [options]

Build or consume candidate release artifacts, install an older DefenseClaw in a
throwaway HOME, redirect its upgrade command to the local candidate artifacts,
then run and verify a real upgrade.

Options:
  --from-version VERSION     Installed baseline version to upgrade from (default: 0.7.2)
  --from-versions LIST       Space/comma-separated baseline versions to test
  --target-version VERSION   Candidate version (default: pyproject.toml version)
  --release-dir DIR          Existing artifact dir, e.g. dist/ from the release workflow
  --release-root DIR         Existing local release root containing VERSION/<assets>
  --baseline-mode MODE       auto, install, or seed (default: auto)
  --health-timeout SECONDS   Gateway health wait passed to upgrade (default: 1)
  --port PORT                Local release server port (default: random high port)
  --platform OS/ARCH         Build platform for --prepare-only (default: current host)
  --prepare-only             Build/validate candidate release root, print it, and exit
  --keep-workdir             Keep temp HOME/logs for debugging
  --help                     Show this help

Examples:
  make upgrade-smoke
  scripts/test-upgrade-release.sh --from-version 0.7.2
  scripts/test-upgrade-release.sh --from-versions "0.8.1,0.8.0,0.7.2,0.7.1,0.6.6,0.6.0,0.5.0,0.4.0"
  scripts/test-upgrade-release.sh --release-dir dist --baseline-mode seed

For a Linux host without the repo's Go toolchain, build/copy artifacts first:
  scripts/test-upgrade-release.sh --prepare-only --platform linux/arm64 --keep-workdir
  scp -r /tmp/candidate-root user@linux:/tmp/
  ssh user@linux 'scripts/test-upgrade-release.sh --release-root /tmp/candidate-root'
EOF
}

log() { printf '==> %s\n' "$*"; }
ok() { printf 'OK: %s\n' "$*"; }
warn() { printf 'WARN: %s\n' "$*" >&2; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

cleanup() {
    local status=$?
    stop_smoke_gateway
    if [[ -n "${SERVER_PID:-}" ]]; then
        kill "${SERVER_PID}" >/dev/null 2>&1 || true
        wait "${SERVER_PID}" >/dev/null 2>&1 || true
    fi
    if [[ "${KEEP_WORKDIR}" != "1" && -n "${WORKDIR:-}" && -d "${WORKDIR}" ]]; then
        rm -rf "${WORKDIR}"
    elif [[ -n "${WORKDIR:-}" ]]; then
        warn "Kept smoke workdir: ${WORKDIR}"
    fi
    return "${status}"
}
trap cleanup EXIT

stop_smoke_gateway() {
    if [[ -n "${SMOKE_HOME:-}" && -x "${SMOKE_HOME}/.local/bin/defenseclaw-gateway" ]]; then
        HOME="${SMOKE_HOME}" \
        DEFENSECLAW_HOME="${SMOKE_HOME}/.defenseclaw" \
        PATH="${SMOKE_HOME}/.local/bin:${PATH}" \
            "${SMOKE_HOME}/.local/bin/defenseclaw-gateway" stop \
            >"${SMOKE_HOME}/gateway-stop.log" 2>&1 || true
    fi
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --from-version)
                [[ $# -ge 2 ]] || die "--from-version requires a value"
                FROM_VERSION="$2"; shift 2 ;;
            --from-versions)
                [[ $# -ge 2 ]] || die "--from-versions requires a value"
                FROM_VERSIONS="$2"; shift 2 ;;
            --target-version)
                [[ $# -ge 2 ]] || die "--target-version requires a value"
                TARGET_VERSION="$2"; shift 2 ;;
            --release-dir)
                [[ $# -ge 2 ]] || die "--release-dir requires a value"
                RELEASE_DIR="$2"; shift 2 ;;
            --release-root)
                [[ $# -ge 2 ]] || die "--release-root requires a value"
                RELEASE_ROOT="$2"; shift 2 ;;
            --baseline-mode)
                [[ $# -ge 2 ]] || die "--baseline-mode requires a value"
                BASELINE_MODE="$2"; shift 2 ;;
            --health-timeout)
                [[ $# -ge 2 ]] || die "--health-timeout requires a value"
                HEALTH_TIMEOUT="$2"; shift 2 ;;
            --port)
                [[ $# -ge 2 ]] || die "--port requires a value"
                PORT="$2"; shift 2 ;;
            --platform)
                [[ $# -ge 2 ]] || die "--platform requires a value"
                BUILD_PLATFORM="$2"; shift 2 ;;
            --prepare-only)
                PREPARE_ONLY=1; KEEP_WORKDIR=1; shift ;;
            --keep-workdir)
                KEEP_WORKDIR=1; shift ;;
            --help|-h)
                usage; exit 0 ;;
            *)
                die "unknown argument: $1" ;;
        esac
    done
}

current_version() {
    python3 - <<'PY'
from pathlib import Path
import re

text = Path("pyproject.toml").read_text(encoding="utf-8")
match = re.search(r'^version\s*=\s*"([^"]+)"', text, re.MULTILINE)
if not match:
    raise SystemExit("could not read pyproject.toml version")
print(match.group(1))
PY
}

abs_path() {
    python3 - "$1" <<'PY'
from pathlib import Path
import sys

print(Path(sys.argv[1]).expanduser().resolve())
PY
}

detect_platform() {
    if [[ -n "${BUILD_PLATFORM}" ]]; then
        case "${BUILD_PLATFORM}" in
            linux/amd64|linux/arm64|darwin/amd64|darwin/arm64)
                OS_NAME="${BUILD_PLATFORM%%/*}"
                ARCH_NAME="${BUILD_PLATFORM##*/}"
                return ;;
            *)
                die "--platform must be one of linux/amd64, linux/arm64, darwin/amd64, darwin/arm64" ;;
        esac
    fi
    case "$(uname -s)" in
        Darwin) OS_NAME="darwin" ;;
        Linux) OS_NAME="linux" ;;
        *) die "unsupported OS for upgrade smoke: $(uname -s)" ;;
    esac
    case "$(uname -m)" in
        arm64|aarch64) ARCH_NAME="arm64" ;;
        x86_64|amd64) ARCH_NAME="amd64" ;;
        *) die "unsupported architecture for upgrade smoke: $(uname -m)" ;;
    esac
}

normalize_baseline_versions() {
    local raw="${FROM_VERSION}"
    if [[ -n "${FROM_VERSIONS}" ]]; then
        raw="${FROM_VERSIONS//,/ }"
    fi

    FROM_VERSION_LIST=()
    local version
    for version in ${raw}; do
        [[ -n "${version}" ]] || continue
        [[ "${version}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] \
            || die "invalid baseline version: ${version}"
        if ! version_lte "${version}" "${TARGET_VERSION}"; then
            warn "Skipping baseline ${version}; target ${TARGET_VERSION} is older"
            continue
        fi
        FROM_VERSION_LIST+=("${version}")
    done
    [[ "${#FROM_VERSION_LIST[@]}" -gt 0 ]] || die "no baseline versions provided"
    FROM_VERSION="${FROM_VERSION_LIST[0]}"
}

version_lte() {
    python3 - "$1" "$2" <<'PY'
import sys


def parse(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in version.split("."))


raise SystemExit(0 if parse(sys.argv[1]) <= parse(sys.argv[2]) else 1)
PY
}

validate_inputs() {
    normalize_baseline_versions
    [[ "${TARGET_VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "invalid --target-version: ${TARGET_VERSION}"
    case "${BASELINE_MODE}" in
        auto|install|seed) ;;
        *) die "--baseline-mode must be auto, install, or seed" ;;
    esac
    if [[ -n "${RELEASE_DIR}" && -n "${RELEASE_ROOT}" ]]; then
        die "use only one of --release-dir or --release-root"
    fi
    if [[ "${PREPARE_ONLY}" != "1" && -n "${BUILD_PLATFORM}" ]]; then
        die "--platform is only valid with --prepare-only"
    fi
}

build_candidate_release() {
    RELEASE_ROOT="${WORKDIR}/candidate-release"
    local out="${RELEASE_ROOT}/${TARGET_VERSION}"
    mkdir -p "${out}"

    log "Building candidate CLI wheel"
    make -C "${ROOT}" dist-cli DIST_DIR="${out}"

    log "Building candidate gateway (${OS_NAME}/${ARCH_NAME})"
    make -C "${ROOT}" sync-openclaw-extension
    local stage="${WORKDIR}/gateway-${OS_NAME}-${ARCH_NAME}"
    mkdir -p "${stage}"
    CGO_ENABLED=0 GOOS="${OS_NAME}" GOARCH="${ARCH_NAME}" \
        go build -ldflags "-s -w -X main.version=${TARGET_VERSION}" \
        -o "${stage}/defenseclaw" "${ROOT}/cmd/defenseclaw"
    tar -czf "${out}/defenseclaw_${TARGET_VERSION}_${OS_NAME}_${ARCH_NAME}.tar.gz" \
        -C "${stage}" defenseclaw

    log "Generating candidate upgrade manifest/checksums"
    python3 "${ROOT}/scripts/generate-upgrade-manifest.py" \
        --out "${out}/upgrade-manifest.json"
    (cd "${out}" && find . -type f ! -name checksums.txt ! -name checksums.txt.sig ! -name checksums.txt.pem \
        | sed 's#^\./##' | sort | xargs shasum -a 256 > checksums.txt)
}

prepare_release_root() {
    if [[ -n "${RELEASE_ROOT}" ]]; then
        RELEASE_ROOT="$(abs_path "${RELEASE_ROOT}")"
        return
    fi

    if [[ -n "${RELEASE_DIR}" ]]; then
        local dir
        dir="$(abs_path "${RELEASE_DIR}")"
        [[ -d "${dir}" ]] || die "--release-dir not found: ${dir}"
        RELEASE_ROOT="${WORKDIR}/candidate-release-root"
        mkdir -p "${RELEASE_ROOT}"
        ln -s "${dir}" "${RELEASE_ROOT}/${TARGET_VERSION}"
        return
    fi

    build_candidate_release
}

assert_candidate_assets() {
    local dir="${RELEASE_ROOT}/${TARGET_VERSION}"
    [[ -d "${dir}" ]] || die "release root must contain ${TARGET_VERSION}/: ${RELEASE_ROOT}"
    [[ -f "${dir}/defenseclaw-${TARGET_VERSION}-py3-none-any.whl" ]] \
        || die "candidate wheel missing from ${dir}"
    [[ -f "${dir}/defenseclaw_${TARGET_VERSION}_${OS_NAME}_${ARCH_NAME}.tar.gz" ]] \
        || die "candidate gateway archive missing for ${OS_NAME}/${ARCH_NAME} in ${dir}"
    [[ -f "${dir}/upgrade-manifest.json" ]] || die "upgrade-manifest.json missing from ${dir}"
    [[ -f "${dir}/checksums.txt" ]] || die "checksums.txt missing from ${dir}"
}

start_release_server() {
    local attempt
    for attempt in 1 2 3 4 5; do
        if [[ -z "${PORT}" ]]; then
            PORT=$((18000 + RANDOM % 20000))
        fi
        log "Starting local release server on 127.0.0.1:${PORT}"
        python3 -m http.server "${PORT}" --bind 127.0.0.1 --directory "${RELEASE_ROOT}" \
            >"${WORKDIR}/release-server.log" 2>&1 &
        SERVER_PID=$!
        sleep 1
        if curl -fsSI "http://127.0.0.1:${PORT}/${TARGET_VERSION}/checksums.txt" >/dev/null 2>&1; then
            RELEASE_URL="http://127.0.0.1:${PORT}"
            return
        fi
        kill "${SERVER_PID}" >/dev/null 2>&1 || true
        wait "${SERVER_PID}" >/dev/null 2>&1 || true
        SERVER_PID=""
        PORT=""
    done
    die "could not start local release server; see ${WORKDIR}/release-server.log"
}

tail_log() {
    local file="$1"
    if [[ -f "${file}" ]]; then
        printf '\n--- %s tail ---\n' "${file}" >&2
        tail -80 "${file}" >&2 || true
    fi
}

download_old_asset() {
    local name="$1"
    local dest="$2"
    local url="https://github.com/${REPO}/releases/download/${FROM_VERSION}/${name}"
    curl -fsSL "${url}" -o "${dest}"
}

seed_baseline_install() {
    log "Seeding baseline ${FROM_VERSION} install"
    mkdir -p "${SMOKE_HOME}/.local/bin" "${SMOKE_HOME}/.defenseclaw"

    local old_dir="${WORKDIR}/old-release/${FROM_VERSION}"
    mkdir -p "${old_dir}"
    local old_wheel="${old_dir}/defenseclaw-${FROM_VERSION}-py3-none-any.whl"
    local old_gateway="${old_dir}/defenseclaw_${FROM_VERSION}_${OS_NAME}_${ARCH_NAME}.tar.gz"
    download_old_asset "defenseclaw-${FROM_VERSION}-py3-none-any.whl" "${old_wheel}" \
        || die "could not download old wheel for ${FROM_VERSION}; choose a release with assets"
    download_old_asset "defenseclaw_${FROM_VERSION}_${OS_NAME}_${ARCH_NAME}.tar.gz" "${old_gateway}" \
        || die "could not download old gateway for ${FROM_VERSION}/${OS_NAME}/${ARCH_NAME}"

    uv --no-config venv "${SMOKE_HOME}/.defenseclaw/.venv" --python 3.12 --quiet
    local venv_python="${SMOKE_HOME}/.defenseclaw/.venv/bin/python"
    uv --no-config pip install --python "${venv_python}" --quiet \
        "${RELEASE_URL}/${TARGET_VERSION}/defenseclaw-${TARGET_VERSION}-py3-none-any.whl" \
        >"${SMOKE_HOME}/seed-target-deps.log" 2>&1 \
        || { tail_log "${SMOKE_HOME}/seed-target-deps.log"; die "could not seed target dependency set"; }
    uv --no-config pip install --python "${venv_python}" --quiet --no-deps "${old_wheel}" \
        >"${SMOKE_HOME}/seed-old-wheel.log" 2>&1 \
        || { tail_log "${SMOKE_HOME}/seed-old-wheel.log"; die "could not install old wheel"; }

    ln -sf "${SMOKE_HOME}/.defenseclaw/.venv/bin/defenseclaw" "${SMOKE_HOME}/.local/bin/defenseclaw"

    local gateway_stage="${WORKDIR}/old-gateway/${FROM_VERSION}"
    mkdir -p "${gateway_stage}"
    tar -xzf "${old_gateway}" -C "${gateway_stage}"
    cp "${gateway_stage}/defenseclaw" "${SMOKE_HOME}/.local/bin/defenseclaw-gateway"
    chmod +x "${SMOKE_HOME}/.local/bin/defenseclaw-gateway"
}

install_baseline() {
    if [[ "${BASELINE_MODE}" == "seed" ]]; then
        seed_baseline_install
        return
    fi

    log "Installing baseline ${FROM_VERSION} with scripts/install.sh"
    if HOME="${SMOKE_HOME}" DEFENSECLAW_HOME="${SMOKE_HOME}/.defenseclaw" \
        PATH="${SMOKE_HOME}/.local/bin:${PATH}" VERSION="${FROM_VERSION}" \
        "${ROOT}/scripts/install.sh" --yes --connector none \
        >"${SMOKE_HOME}/install-baseline.log" 2>&1; then
        return
    fi

    if [[ "${BASELINE_MODE}" == "install" ]]; then
        tail_log "${SMOKE_HOME}/install-baseline.log"
        die "baseline install failed"
    fi

    warn "baseline installer failed; falling back to seeded old wheel"
    tail_log "${SMOKE_HOME}/install-baseline.log"
    seed_baseline_install
}

patch_installed_upgrade_endpoint() {
    local upgrade_py
    upgrade_py="$(find "${SMOKE_HOME}/.defenseclaw/.venv" \
        -path '*/site-packages/defenseclaw/commands/cmd_upgrade.py' -print -quit)"
    [[ -n "${upgrade_py}" ]] || die "installed cmd_upgrade.py not found"

    python3 - "${upgrade_py}" "${RELEASE_URL}" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
release_url = sys.argv[2]
text = path.read_text(encoding="utf-8")
old = 'GITHUB_DL = f"https://github.com/{GITHUB_REPO}/releases/download"'
new = f'GITHUB_DL = "{release_url}"'
if old not in text:
    raise SystemExit(f"release URL constant not found in {path}")
path.write_text(text.replace(old, new, 1), encoding="utf-8")
PY
}

upgrade_supports_allow_unverified() {
    HOME="${SMOKE_HOME}" DEFENSECLAW_HOME="${SMOKE_HOME}/.defenseclaw" \
    PATH="${SMOKE_HOME}/.local/bin:${PATH}" \
        defenseclaw upgrade --help 2>/dev/null | grep -q -- "--allow-unverified"
}

candidate_has_checksum_signature() {
    local dir="${RELEASE_ROOT}/${TARGET_VERSION}"
    [[ -f "${dir}/checksums.txt.sig" && -f "${dir}/checksums.txt.pem" ]]
}

run_upgrade() {
    log "Running upgrade ${FROM_VERSION} -> ${TARGET_VERSION}"
    local -a args=(upgrade --version "${TARGET_VERSION}" --yes --health-timeout "${HEALTH_TIMEOUT}")
    if upgrade_supports_allow_unverified && ! candidate_has_checksum_signature; then
        args+=(--allow-unverified)
    fi

    if ! HOME="${SMOKE_HOME}" DEFENSECLAW_HOME="${SMOKE_HOME}/.defenseclaw" \
        PATH="${SMOKE_HOME}/.local/bin:${PATH}" defenseclaw "${args[@]}" \
        >"${SMOKE_HOME}/upgrade.log" 2>&1; then
        tail_log "${SMOKE_HOME}/upgrade.log"
        die "upgrade command failed"
    fi

    if grep -E "Traceback|AttributeError|Required migration\\(s\\).*not recorded|Component drift detected" \
        "${SMOKE_HOME}/upgrade.log" >/dev/null; then
        tail_log "${SMOKE_HOME}/upgrade.log"
        die "upgrade log contains a known regression marker"
    fi
}

verify_upgrade() {
    log "Verifying upgraded install"
    local venv_python="${SMOKE_HOME}/.defenseclaw/.venv/bin/python"
    local release_dir="${RELEASE_ROOT}/${TARGET_VERSION}"

    HOME="${SMOKE_HOME}" DEFENSECLAW_HOME="${SMOKE_HOME}/.defenseclaw" \
    PATH="${SMOKE_HOME}/.local/bin:${PATH}" \
        defenseclaw --version | grep -F "${TARGET_VERSION}" >/dev/null \
        || die "defenseclaw --version does not report ${TARGET_VERSION}"

    HOME="${SMOKE_HOME}" DEFENSECLAW_HOME="${SMOKE_HOME}/.defenseclaw" \
    PATH="${SMOKE_HOME}/.local/bin:${PATH}" \
        defenseclaw-gateway --version | grep -F "${TARGET_VERSION}" >/dev/null \
        || die "defenseclaw-gateway --version does not report ${TARGET_VERSION}"

    "${venv_python}" - "${SMOKE_HOME}/.defenseclaw" "${release_dir}/upgrade-manifest.json" <<'PY'
import json
from pathlib import Path
import sys

data_dir = Path(sys.argv[1])
manifest_path = Path(sys.argv[2])
cursor_path = data_dir / ".migration_state.json"
cursor = json.loads(cursor_path.read_text(encoding="utf-8"))
manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
applied = set(cursor.get("applied", []))
missing = [
    version
    for version in manifest.get("required_cli_migrations", [])
    if isinstance(version, str) and version not in applied
]
if missing:
    raise SystemExit(f"missing required migrations in cursor: {', '.join(missing)}")
print("cursor_applied=" + ",".join(cursor.get("applied", [])))
PY

    "${venv_python}" - <<'PY'
import textual
from defenseclaw.tui.widgets.native_metrics import MetricDatum, MetricTile

metric = MetricDatum(
    key="hook_calls",
    label="Hook Calls",
    value=0,
    progress=0.0,
    detail="gateway offline",
    state="error",
    target_panel="logs",
)
tile = MetricTile(metric)
tile.refresh_metric(metric)
print("textual_version=" + getattr(textual, "__version__", "unknown"))
print("metric_tile_refresh=ok")
PY
}

run_one_upgrade_smoke() {
    FROM_VERSION="$1"
    local home_name="${FROM_VERSION//[^A-Za-z0-9._-]/_}"
    SMOKE_HOME="${WORKDIR}/home-${home_name}"
    rm -rf "${SMOKE_HOME}"
    mkdir -p "${SMOKE_HOME}"

    install_baseline
    patch_installed_upgrade_endpoint
    run_upgrade
    verify_upgrade
    stop_smoke_gateway

    ok "Upgrade smoke passed: ${FROM_VERSION} -> ${TARGET_VERSION} (${OS_NAME}/${ARCH_NAME})"
    if [[ "${KEEP_WORKDIR}" == "1" ]]; then
        ok "Upgrade log: ${SMOKE_HOME}/upgrade.log"
    fi
}

main() {
    parse_args "$@"
    cd "${ROOT}"
    if [[ -z "${TARGET_VERSION}" ]]; then
        TARGET_VERSION="$(current_version)"
    fi
    validate_inputs
    detect_platform

    WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/defenseclaw-upgrade-smoke.XXXXXX")"

    prepare_release_root
    assert_candidate_assets
    if [[ "${PREPARE_ONLY}" == "1" ]]; then
        ok "Prepared candidate release root: ${RELEASE_ROOT}"
        ok "Contains ${TARGET_VERSION} artifacts for ${OS_NAME}/${ARCH_NAME}"
        return
    fi
    start_release_server
    local version
    for version in "${FROM_VERSION_LIST[@]}"; do
        run_one_upgrade_smoke "${version}"
    done

    ok "Upgrade smoke matrix passed for ${#FROM_VERSION_LIST[@]} baseline(s): ${FROM_VERSION_LIST[*]} -> ${TARGET_VERSION} (${OS_NAME}/${ARCH_NAME})"
    if [[ "${KEEP_WORKDIR}" == "1" ]]; then
        ok "Upgrade logs retained under: ${WORKDIR}"
    else
        ok "Temp HOME/logs cleaned automatically; re-run with --keep-workdir to retain them"
    fi
}

main "$@"
