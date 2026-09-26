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
# DefenseClaw installer and upgrader for macOS and Linux.
#
#   curl -LsSf https://github.com/cisco-ai-defense/defenseclaw/releases/latest/download/install.sh | bash
#
# The same command installs, upgrades, repairs, and imports a 0.x install;
# `defenseclaw upgrade` runs it for you. Each release's copy installs exactly
# that release, so the upgrade logic always comes from the version being
# installed. Config and data in ~/.defenseclaw are kept; the replaced install
# is kept in ~/.defenseclaw/previous for `--rollback`.
#
# Permanent interface (never remove or change these; unknown flags are
# ignored with a warning): --yes, --version X.Y.Z, --local DIR, --rollback.
#
set -euo pipefail
umask 077

# The whole script is inside main() so a truncated download never runs.
main() {

# Everything the installer creates (and the gateway it starts) is private to
# this user, whatever the login shell's umask.
umask 077
readonly DC_VERSION="__DEFENSECLAW_VERSION__"
readonly DEFAULT_REPO="cisco-ai-defense/defenseclaw"
REPO="${DEFENSECLAW_REPO:-${DEFAULT_REPO}}"
readonly DEFENSECLAW_HOME="${DEFENSECLAW_HOME:-${HOME}/.defenseclaw}"
export DEFENSECLAW_HOME
readonly VENV="${DEFENSECLAW_HOME}/.venv"
readonly BIN_DIR="${HOME}/.local/bin"
readonly PREVIOUS="${DEFENSECLAW_HOME}/previous"
readonly STAGING="${DEFENSECLAW_HOME}/.staging"
readonly INSTALLER_DIR="${DEFENSECLAW_HOME}/installer"
readonly LOCK_DIR="${DEFENSECLAW_HOME}/.install.lock"
# A copy that the upgrade command or another installer downloaded into a
# temporary directory removes that directory when it finishes, but only when
# the directory holds nothing else.
SELF_TMP="$(dirname "${BASH_SOURCE[0]:-.}")"
case "$(basename "${SELF_TMP}")" in
    defenseclaw-upgrade-*|defenseclaw-rollback-*) ;;
    *) SELF_TMP="" ;;
esac
if [[ -n "${SELF_TMP}" && -n "$(find "${SELF_TMP}" -mindepth 1 -maxdepth 1 \
        ! -name install.sh ! -name checksums.txt -print -quit 2>/dev/null)" ]]; then
    SELF_TMP=""
fi
[[ -z "${SELF_TMP}" ]] || trap 'rm -rf "${SELF_TMP}"' EXIT
readonly OPENCLAW_VERSION="2026.3.24"
readonly MACOS_SYSCTL_BIN="/usr/sbin/sysctl"
# Real files in BIN_DIR. Connector hooks record these paths, so they never move.
readonly MANAGED_BINARIES="defenseclaw-gateway defenseclaw-acp"
# Symlinks in BIN_DIR that point into the venv.
readonly MANAGED_LINKS="defenseclaw skill-scanner mcp-scanner"
# Data-dir entries that are install machinery, not user data.
readonly NOT_DATA=".venv previous previous.new .repair .rollback-hold .staging .failed-* installer logs .install.lock backups"
readonly CONNECTOR_CHOICES="codex claudecode zeptoclaw openclaw hermes cursor devin copilot openhands antigravity opencode amp omnigent kiro none"

if [[ -t 1 ]] || [[ "${FORCE_COLOR:-}" == "1" ]]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
    BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; BLUE=''; CYAN=''; BOLD=''; NC=''
fi

info() { printf "${BLUE}  ▸${NC} %s\n" "$*"; }
ok()   { printf "${GREEN}  ✓${NC} %s\n" "$*"; }
warn() { printf "${YELLOW}  !${NC} %s\n" "$*"; }
err()  { printf "${RED}  ✗${NC} %s\n" "$*" >&2; }
step() { printf "\n${BOLD}${CYAN}─── %s${NC}\n" "$*"; }
die()  { err "$@"; exit 1; }
has()  { command -v "$1" >/dev/null 2>&1; }

# uname reports x86_64 for a shell running under Rosetta; ask the kernel.
macos_hardware_machine() {
    local machine="$1"
    if [[ "${machine}" == "x86_64" || "${machine}" == "amd64" ]] \
        && [[ -x "${MACOS_SYSCTL_BIN}" && ! -L "${MACOS_SYSCTL_BIN}" ]] \
        && [[ "$("${MACOS_SYSCTL_BIN}" -in sysctl.proc_translated 2>/dev/null || true)" == "1" ]]; then
        printf '%s\n' "arm64"
        return 0
    fi
    printf '%s\n' "${machine}"
}

version_key() {
    local IFS=.
    # shellcheck disable=SC2086
    set -- $1
    printf '%05d%05d%05d' "${1:-0}" "${2:-0}" "${3:-0}"
}
version_lt() { [[ "$(version_key "$1")" < "$(version_key "$2")" ]]; }
is_version() { [[ "$1" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; }

sha256_of() {
    if has sha256sum; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

ask_yes_no() {
    local prompt="$1" default="${2:-y}" answer
    [[ "${YES}" == true ]] && return 0
    if [[ "${default}" == y ]]; then prompt="${prompt} [Y/n]"; else prompt="${prompt} [y/N]"; fi
    printf "  %s " "${prompt}" >&2
    read -r answer < /dev/tty 2>/dev/null || answer="${default}"
    answer="${answer:-${default}}"
    [[ "${answer}" =~ ^[Yy]$ ]]
}

is_valid_connector() {
    local candidate
    for candidate in ${CONNECTOR_CHOICES}; do
        [[ "${candidate}" == "$1" ]] && return 0
    done
    return 1
}

# ── Arguments ────────────────────────────────────────────────────────────────

YES=false
TARGET_VERSION=""
LOCAL_DIR=""
ROLLBACK=false
CONNECTOR=""
NO_OPENCLAW=false
RUN_QUICKSTART=false
QUICKSTART_MODE=""
INSTALL_SANDBOX=false
PASSTHROUGH=()

usage() {
    cat <<EOF

Usage:
  curl -LsSf https://github.com/${DEFAULT_REPO}/releases/latest/download/install.sh | bash
  curl ... | bash -s -- [options]

Installs DefenseClaw, or upgrades an existing install in place (config and data
are kept; the replaced install is kept for --rollback).

Options:
  --yes, -y                Do not prompt
  --version X.Y.Z          Install release X.Y.Z (runs that release's installer)
  --local DIR              Take every release asset from DIR instead of GitHub
  --rollback               Restore the install that the last upgrade replaced
  --connector NAME         First install only: agent to guard (${CONNECTOR_CHOICES// /, })
  --no-openclaw            First install only: do not install OpenClaw
  --quickstart             First install only: run 'defenseclaw quickstart' afterwards
  --quickstart-mode MODE   observe or action (implies --quickstart)
  --sandbox                First install only: also install openshell-sandbox (Linux)
  --help, -h               Show this help

Environment:
  DEFENSECLAW_HOME         Data directory (default: ~/.defenseclaw)
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --yes|-y) YES=true ;;
        --version)
            [[ $# -ge 2 ]] || die "--version needs a value such as 1.2.3"
            TARGET_VERSION="${2#v}"; shift ;;
        --version=*) TARGET_VERSION="${1#--version=}"; TARGET_VERSION="${TARGET_VERSION#v}" ;;
        --local)
            [[ $# -ge 2 ]] || die "--local needs a directory"
            LOCAL_DIR="$(cd "$2" 2>/dev/null && pwd)" || die "Directory not found: $2"
            shift ;;
        --rollback) ROLLBACK=true ;;
        --connector)
            [[ $# -ge 2 ]] || die "--connector needs a value (${CONNECTOR_CHOICES})"
            CONNECTOR="$2"; shift
            is_valid_connector "${CONNECTOR}" || die "Invalid --connector '${CONNECTOR}'. Choices: ${CONNECTOR_CHOICES}"
            PASSTHROUGH+=(--connector "${CONNECTOR}") ;;
        --no-openclaw) NO_OPENCLAW=true; PASSTHROUGH+=(--no-openclaw) ;;
        --quickstart) RUN_QUICKSTART=true; PASSTHROUGH+=(--quickstart) ;;
        --quickstart-mode)
            [[ $# -ge 2 ]] || die "--quickstart-mode needs observe or action"
            QUICKSTART_MODE="$2"; shift
            case "${QUICKSTART_MODE}" in observe|action) ;; *) die "invalid --quickstart-mode: ${QUICKSTART_MODE}" ;; esac
            RUN_QUICKSTART=true; PASSTHROUGH+=(--quickstart-mode "${QUICKSTART_MODE}") ;;
        --sandbox) INSTALL_SANDBOX=true; PASSTHROUGH+=(--sandbox) ;;
        --help|-h) usage; exit 0 ;;
        *) warn "Ignoring unknown option: $1" ;;
    esac
    shift
done
if [[ "${NO_OPENCLAW}" == true ]]; then
    [[ "${CONNECTOR}" != openclaw ]] || die "--no-openclaw cannot be combined with --connector openclaw"
    CONNECTOR="${CONNECTOR:-none}"
fi
if [[ -n "${TARGET_VERSION}" ]] && ! is_version "${TARGET_VERSION}"; then
    die "--version must look like 1.2.3, got '${TARGET_VERSION}'"
fi

printf "\n${BOLD}  DefenseClaw Installer${NC}\n"

# ── Platform ─────────────────────────────────────────────────────────────────

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
MACHINE="$(uname -m)"
[[ "${OS}" == darwin ]] && MACHINE="$(macos_hardware_machine "${MACHINE}")"
case "${MACHINE}" in
    x86_64|amd64) ARCH=amd64 ;;
    aarch64|arm64) ARCH=arm64 ;;
    *) die "Unsupported architecture: ${MACHINE}" ;;
esac
case "${OS}" in
    linux) ;;
    darwin)
        [[ "${ARCH}" == arm64 ]] \
            || die "Intel macOS (${MACHINE}) is unsupported. DefenseClaw for macOS requires Apple Silicon (arm64); nothing was changed."
        ;;
    *) die "Unsupported OS: ${OS} (use install.ps1 on Windows)" ;;
esac

# ── Which version does this installer install? ───────────────────────────────

fetch() {
    # fetch ASSET DEST [VERSION]: copy from --local or download from the release.
    local asset="$1" dest="$2" version="${3:-${VERSION}}"
    if [[ -n "${LOCAL_DIR}" ]]; then
        [[ -f "${LOCAL_DIR}/${asset}" ]] || return 1
        cp "${LOCAL_DIR}/${asset}" "${dest}"
    else
        curl -fsSL --retry 3 --proto '=https' --tlsv1.2 -o "${dest}" \
            "https://github.com/${REPO}/releases/download/${version}/${asset}"
    fi
}

latest_release() {
    local location
    location="$(curl -fsSI --proto '=https' --tlsv1.2 "https://github.com/${REPO}/releases/latest" 2>/dev/null \
        | tr -d '\r' | awk 'tolower($1)=="location:"{print $2}' | tail -1)"
    location="${location##*/tag/}"
    location="${location#v}"
    is_version "${location}" || die "Could not determine the latest release of ${REPO}"
    printf '%s' "${location}"
}

# run_release_installer VERSION ARGS...: download VERSION's installer, verify it,
# and run it. Used for --version and for an unstamped (source) copy.
run_release_installer() {
    local version="$1"; shift
    local tmp base="${TMPDIR:-/tmp}"
    tmp="$(mktemp -d "${base%/}/defenseclaw-upgrade-XXXXXX")"
    info "Fetching the installer for DefenseClaw ${version}"
    curl -fsSL --retry 3 --proto '=https' --tlsv1.2 -o "${tmp}/install.sh" \
        "https://github.com/${REPO}/releases/download/${version}/install.sh" \
        || die "Release ${version} has no install.sh (1.x releases start at 1.0.0)"
    curl -fsSL --retry 3 --proto '=https' --tlsv1.2 -o "${tmp}/checksums.txt" \
        "https://github.com/${REPO}/releases/download/${version}/checksums.txt" \
        || die "Release ${version} has no checksums.txt"
    [[ "$(awk '$2=="install.sh"||$2=="*install.sh"{print $1}' "${tmp}/checksums.txt")" == "$(sha256_of "${tmp}/install.sh")" ]] \
        || die "install.sh for ${version} does not match its checksums.txt"
    [[ -z "${SELF_TMP}" ]] || rm -rf "${SELF_TMP}"
    exec bash "${tmp}/install.sh" "$@"
}

FORWARD=()
[[ "${YES}" == true ]] && FORWARD+=(--yes)
FORWARD+=(${PASSTHROUGH[@]+"${PASSTHROUGH[@]}"})

VERSION="${DC_VERSION}"
# Release builds stamp DC_VERSION. Test for a version rather than comparing
# with the placeholder, which stamping would also rewrite.
if ! is_version "${VERSION}"; then
    if [[ -n "${LOCAL_DIR}" ]]; then
        wheel="$(cd "${LOCAL_DIR}" && ls defenseclaw-*-py3-none-any.whl 2>/dev/null | head -1 || true)"
        VERSION="${wheel#defenseclaw-}"; VERSION="${VERSION%-py3-none-any.whl}"
        is_version "${VERSION}" || die "No defenseclaw-X.Y.Z-py3-none-any.whl in ${LOCAL_DIR}"
    elif [[ "${ROLLBACK}" != true ]]; then
        target="${TARGET_VERSION:-$(latest_release)}"
        run_release_installer "${target}" ${FORWARD[@]+"${FORWARD[@]}"}
    fi
fi
if [[ -n "${TARGET_VERSION}" && "${TARGET_VERSION}" != "${VERSION}" && "${ROLLBACK}" != true ]]; then
    version_lt "${TARGET_VERSION}" 1.0.0 \
        && die "DefenseClaw ${TARGET_VERSION} predates this installer; see https://github.com/${REPO}/releases/tag/${TARGET_VERSION}"
    [[ -z "${LOCAL_DIR}" ]] || die "--local ${LOCAL_DIR} holds ${VERSION}, not ${TARGET_VERSION}"
    run_release_installer "${TARGET_VERSION}" ${FORWARD[@]+"${FORWARD[@]}"}
fi

# ── Lock and log ─────────────────────────────────────────────────────────────

mkdir -p "${DEFENSECLAW_HOME}" "${DEFENSECLAW_HOME}/logs"
chmod 700 "${DEFENSECLAW_HOME}" 2>/dev/null || true
if ! mkdir "${LOCK_DIR}" 2>/dev/null; then
    holder="$(cat "${LOCK_DIR}/pid" 2>/dev/null || true)"
    if [[ -n "${holder}" ]] && kill -0 "${holder}" 2>/dev/null; then
        die "Another DefenseClaw install is running (pid ${holder})"
    fi
    rm -rf "${LOCK_DIR}"
    mkdir "${LOCK_DIR}" || die "Could not take the install lock at ${LOCK_DIR}"
fi
echo $$ > "${LOCK_DIR}/pid"
LOG="${DEFENSECLAW_HOME}/logs/install-$(date +%Y%m%dT%H%M%S).log"
exec > >(tee -a "${LOG}") 2>&1
trap 'rm -rf "${LOCK_DIR}" ${SELF_TMP:+"${SELF_TMP}"}' EXIT
trap 'printf "\n"; err "Cancelled."; exit 130' INT TERM

# ── Existing install ─────────────────────────────────────────────────────────

is_gateway_process() {
    # After a crash the PID in gateway.pid can belong to an unrelated process.
    ps -p "$1" -o comm= 2>/dev/null | grep -q defenseclaw
}

gateway_pid() {
    # gateway.pid is JSON ({"pid": N, ...}); accept a bare number too.
    local file="${DEFENSECLAW_HOME}/gateway.pid" pid
    [[ -f "${file}" ]] || return 1
    pid="$(grep -Eo '"pid"[[:space:]]*:[[:space:]]*[0-9]+' "${file}" 2>/dev/null | grep -Eo '[0-9]+$' || true)"
    [[ -n "${pid}" ]] || pid="$(grep -Eo '^[[:space:]]*[0-9]+[[:space:]]*$' "${file}" 2>/dev/null | tr -d '[:space:]' || true)"
    [[ -n "${pid}" ]] && kill -0 "${pid}" 2>/dev/null && is_gateway_process "${pid}" && printf '%s' "${pid}"
}

installed_version() {
    local info
    for info in "${VENV}"/lib/python*/site-packages/defenseclaw-*.dist-info; do
        [[ -d "${info}" ]] || continue
        info="${info##*/defenseclaw-}"
        printf '%s' "${info%.dist-info}"
        return
    done
    if [[ -x "${BIN_DIR}/defenseclaw-gateway" ]]; then
        "${BIN_DIR}/defenseclaw-gateway" --version 2>/dev/null | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true
    fi
}

stop_gateway() {
    # stop_gateway BINARY: stop the running gateway, preferring its own binary.
    local binary="$1" pid waited=0
    pid="$(gateway_pid || true)"
    [[ -n "${pid}" ]] || return 0
    if [[ -x "${binary}" ]]; then
        "${binary}" stop >/dev/null 2>&1 || true
    fi
    while [[ -n "$(gateway_pid || true)" && ${waited} -lt 30 ]]; do
        sleep 1; waited=$((waited + 1))
        [[ ${waited} -eq 15 ]] && kill "${pid}" 2>/dev/null || true
    done
    [[ -z "$(gateway_pid || true)" ]]
}

APP_PATH=""
# DEFENSECLAW_APP_PATH=none skips the macOS app (tests, CLI-only machines).
if [[ "${OS}" == darwin && "${DEFENSECLAW_APP_PATH:-}" != none ]]; then
    for candidate in "${DEFENSECLAW_APP_PATH:-}" /Applications/DefenseClawMac.app "${HOME}/Applications/DefenseClawMac.app"; do
        [[ -n "${candidate}" && -d "${candidate}" ]] || continue
        if [[ "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "${candidate}/Contents/Info.plist" 2>/dev/null)" == com.cisco.defenseclaw.macos ]]; then
            APP_PATH="${candidate}"; break
        fi
    done
fi

recover_interrupted_run

# ── Rollback-only mode ───────────────────────────────────────────────────────

if [[ "${ROLLBACK}" == true ]]; then
    step "Rolling back"
    [[ -s "${PREVIOUS}/VERSION" ]] || die "No previous install to roll back to (${PREVIOUS} is missing)"
    back_to="$(cat "${PREVIOUS}/VERSION")"
    current="$(installed_version)"
    ask_yes_no "Replace DefenseClaw ${current:-?} with the previous install (${back_to})?" \
        || die "Rollback cancelled; nothing was changed"
    was_running=false
    [[ -n "$(gateway_pid || true)" ]] && was_running=true
    stop_gateway "${BIN_DIR}/defenseclaw-gateway" || die "The gateway did not stop; nothing was changed"
    swap_with_previous || die "Rollback failed part-way; see ${LOG}"
    if [[ "${was_running}" == true ]] || [[ "$(cat "${PREVIOUS}/GATEWAY_WAS_RUNNING" 2>/dev/null)" == true ]]; then
        start_gateway && restart_openclaw \
            || warn "The gateway did not start; run 'defenseclaw-gateway start' and check its log"
    fi
    if version_lt "${back_to}" 1.0.0; then
        ok "Now running DefenseClaw ${back_to}. To return to ${current:-1.x}, run: bash ${PREVIOUS}/installer/install.sh --rollback"
    else
        ok "Now running DefenseClaw ${back_to}. Run 'defenseclaw rollback' again to return to ${current:-the other install}."
    fi
    info "Data written since the upgrade is kept in ${PREVIOUS} and comes back if you roll forward."
    exit 0
fi

# ── Stage: nothing live changes until the swap ───────────────────────────────

step "Preparing DefenseClaw ${VERSION} (${OS}/${ARCH})"
PREV_VERSION="$(installed_version || true)"
if [[ -n "${PREV_VERSION}" ]]; then
    info "Installed: ${PREV_VERSION}"
elif [[ -L "${BIN_DIR}/defenseclaw" && ! -e "${BIN_DIR}/defenseclaw" ]]; then
    warn "Found a broken DefenseClaw install (dangling ${BIN_DIR}/defenseclaw); repairing it"
fi

has curl || [[ -n "${LOCAL_DIR}" ]] || die "curl is required"
# Never pick up uv settings (overrides, indexes) from a project in the cwd.
export UV_NO_CONFIG=1
if ! has uv; then
    info "Installing uv (Python package manager)"
    curl -LsSf https://astral.sh/uv/install.sh | env UV_NO_MODIFY_PATH=1 sh >/dev/null \
        || die "Could not install uv; install it from https://docs.astral.sh/uv/ and retry"
    export PATH="${HOME}/.local/bin:${HOME}/.cargo/bin:${PATH}"
    has uv || die "uv was installed but is not on PATH"
fi

rm -rf "${STAGING}"
mkdir -p "${STAGING}/bin"
ARCHIVE="defenseclaw-${VERSION}-${OS}-${ARCH}.tar.gz"
WHEEL="defenseclaw-${VERSION}-py3-none-any.whl"
REQUIREMENTS="defenseclaw-${VERSION}-requirements.txt"
APP_ZIP="DefenseClawMac-${VERSION}-macos-arm64.zip"

info "Downloading and verifying release assets"
fetch checksums.txt "${STAGING}/checksums.txt" || die "Could not get checksums.txt for ${VERSION}"
checksum_ok() {
    local file="$1" name expected
    name="${2:-$(basename "${file}")}"
    expected="$(awk -v n="${name}" '$2==n||$2==("*" n){print $1}' "${STAGING}/checksums.txt")"
    [[ -n "${expected}" && "$(sha256_of "${file}")" == "${expected}" ]]
}
verify() {
    checksum_ok "$@" || die "$(basename "$1") does not match checksums.txt; nothing was changed"
}
cosign_major="$(cosign version 2>/dev/null | awk '/GitVersion/{print $2}' | sed 's/^v//' | cut -d. -f1 || true)"
if [[ "${cosign_major:-0}" =~ ^[0-9]+$ ]] && [[ "${cosign_major:-0}" -ge 2 ]]; then
    if fetch checksums.txt.bundle "${STAGING}/checksums.txt.bundle" 2>/dev/null; then
        cosign verify-blob --bundle "${STAGING}/checksums.txt.bundle" \
            --certificate-identity-regexp "^https://github\.com/${REPO//./\\.}/\.github/workflows/release\.yaml@refs/heads/main$" \
            --certificate-oidc-issuer https://token.actions.githubusercontent.com \
            "${STAGING}/checksums.txt" >/dev/null 2>&1 \
            || die "The release signature on checksums.txt did not verify; nothing was changed"
        ok "Release signature verified"
    elif [[ -z "${LOCAL_DIR}" ]]; then
        # Every published release carries the bundle; a missing one is not a
        # release this workflow produced.
        die "This release has no checksums.txt.bundle to verify with cosign; nothing was changed"
    else
        warn "No checksums.txt.bundle to verify with cosign; relying on checksums"
    fi
elif [[ -z "${LOCAL_DIR}" ]]; then
    info "cosign 2.0 or later is not installed; downloads are checked against checksums.txt only"
fi
for asset in "${ARCHIVE}" "${WHEEL}" "${REQUIREMENTS}"; do
    fetch "${asset}" "${STAGING}/${asset}" || die "Could not get ${asset} for ${VERSION}"
    verify "${STAGING}/${asset}"
done
if [[ -n "${APP_PATH}" ]]; then
    fetch "${APP_ZIP}" "${STAGING}/${APP_ZIP}" || die "Could not get ${APP_ZIP} for ${VERSION}"
    verify "${STAGING}/${APP_ZIP}"
fi
ok "Assets match checksums.txt"

tar -xzf "${STAGING}/${ARCHIVE}" -C "${STAGING}/bin" || die "Could not unpack ${ARCHIVE}"
[[ -f "${STAGING}/bin/defenseclaw-gateway" ]] || die "${ARCHIVE} has no defenseclaw-gateway"
for binary in ${MANAGED_BINARIES}; do
    [[ -f "${STAGING}/bin/${binary}" ]] || continue
    chmod 755 "${STAGING}/bin/${binary}"
    if [[ "${OS}" == darwin ]]; then
        /usr/bin/codesign -f -s - -i "com.cisco.defenseclaw.${binary#defenseclaw-}" "${STAGING}/bin/${binary}" >/dev/null 2>&1 \
            || die "Could not sign ${binary} for this Mac"
    fi
done
"${STAGING}/bin/defenseclaw-gateway" --version 2>/dev/null | grep -qF "${VERSION}" \
    || die "The downloaded gateway does not report version ${VERSION}"

info "Building the Python environment"
make_venv() {
    local venv="$1"
    rm -rf "${venv}"
    uv venv "${venv}" --quiet --python 3.12 2>/dev/null \
        || uv venv "${venv}" --quiet --python '>=3.11,<3.14' \
        || return 1
    # The requirements file is the complete hashed lock, so nothing resolves.
    uv pip install --quiet --python "${venv}/bin/python" --require-hashes --no-deps -r "${STAGING}/${REQUIREMENTS}" \
        && uv pip install --quiet --python "${venv}/bin/python" --no-deps "${STAGING}/${WHEEL}"
}
make_venv "${STAGING}/venv" || die "Could not install the DefenseClaw ${VERSION} Python package; nothing was changed"
"${STAGING}/venv/bin/defenseclaw" --version 2>/dev/null | grep -qF "${VERSION}" \
    || die "The staged CLI does not start; nothing was changed"

migrate_args=()
[[ -n "${PREV_VERSION}" ]] && migrate_args+=(--from-version "${PREV_VERSION}")
set +e
"${STAGING}/venv/bin/defenseclaw" migrate --check \
    --gateway-binary "${STAGING}/bin/defenseclaw-gateway" ${migrate_args[@]+"${migrate_args[@]}"}
check_rc=$?
set -e
case "${check_rc}" in
    0) ;;
    2) die "Your configuration is from a newer DefenseClaw than ${VERSION}; nothing was changed" ;;
    *) die "Your configuration cannot be migrated to ${VERSION}; nothing was changed (see above)" ;;
esac
ok "DefenseClaw ${VERSION} is staged and checked"

# ── Swap ─────────────────────────────────────────────────────────────────────

if [[ -n "${PREV_VERSION}" && "${PREV_VERSION}" == "${VERSION}" ]]; then
    ask_yes_no "Reinstall DefenseClaw ${VERSION}?" || die "Cancelled; nothing was changed"
elif [[ -n "${PREV_VERSION}" ]]; then
    ask_yes_no "Upgrade DefenseClaw ${PREV_VERSION} → ${VERSION}?" || die "Cancelled; nothing was changed"
fi
if [[ -z "${PREV_VERSION}" ]] && [[ "${YES}" != true ]] && [[ -z "${CONNECTOR}" ]]; then
    pick_connector
fi

WAS_RUNNING=false
[[ -n "$(gateway_pid || true)" ]] && WAS_RUNNING=true
if [[ "${WAS_RUNNING}" == true ]]; then
    info "Stopping the gateway"
    stop_gateway "${BIN_DIR}/defenseclaw-gateway" || die "The running gateway did not stop; nothing was changed"
fi

if [[ -n "${PREV_VERSION}" && "${PREV_VERSION}" == "${VERSION}" ]]; then
    SNAP="${DEFENSECLAW_HOME}/.repair"
else
    SNAP="${DEFENSECLAW_HOME}/previous.new"
fi
trap 'warn "Interrupted; finishing or undoing the swap before exiting"' INT TERM
trap '' HUP PIPE
snapshot || { undo_snapshot; restart_old; die "Could not save the current install; nothing was changed"; }

if ! swap_in; then
    err "Installing ${VERSION} failed; restoring ${PREV_VERSION:-the previous state}"
    restore_snapshot
    die "DefenseClaw ${VERSION} was not installed. Your previous install is back. Log: ${LOG}"
fi
START_RC=0
if [[ "${WAS_RUNNING}" == true && ! -f "${DEFENSECLAW_HOME}/config.yaml" && -z "${DEFENSECLAW_CONFIG:-}" ]]; then
    # 0.x gateways ran on defaults without a config; 1.x needs one.
    WAS_RUNNING=false
    warn "The gateway was running without a configuration; run 'defenseclaw init' to set it up"
fi
if [[ "${WAS_RUNNING}" == true ]]; then
    set +e
    start_gateway
    START_RC=$?
    set -e
    if [[ ${START_RC} -ne 0 && ${START_RC} -ne 3 ]]; then
        err "The ${VERSION} gateway did not become healthy; restoring ${PREV_VERSION:-the previous state}"
        stop_gateway "${BIN_DIR}/defenseclaw-gateway" || true
        restore_snapshot
        die "DefenseClaw ${VERSION} was not installed. Your previous install is back. Log: ${LOG}"
    fi
fi
finish_swap
trap - HUP PIPE
trap 'printf "\n"; err "Cancelled."; exit 130' INT TERM

if [[ ${START_RC} -eq 3 ]]; then
    warn "A connector needs attention before it is guarded again (see the gateway output above)"
fi
if [[ "${WAS_RUNNING}" == true ]]; then
    restart_openclaw
fi

if [[ -z "${PREV_VERSION}" ]]; then
    first_install_extras
fi
# Kept until now: the sandbox extra is checked against the staged checksums.txt.
rm -rf "${STAGING}"
ensure_path_hint
printf "\n${BOLD}${GREEN}  DefenseClaw ${VERSION} is installed.${NC}\n"
if [[ -n "${PREV_VERSION}" && "${PREV_VERSION}" != "${VERSION}" ]]; then
    printf "  Upgraded from ${PREV_VERSION}. Undo with: ${CYAN}defenseclaw rollback${NC}\n"
    if pgrep -f "${VENV}/bin/defenseclaw" >/dev/null 2>&1; then
        warn "Restart the DefenseClaw TUI and any other open DefenseClaw commands; they still run ${PREV_VERSION}"
    fi
fi
if [[ -n "${APP_RELAUNCH:-}" ]]; then
    open "${APP_PATH}" >/dev/null 2>&1 || true
fi
printf "\n"
exit ${START_RC}

}

# ── Snapshot, swap, restore ──────────────────────────────────────────────────
# Defined outside main() is fine: bash parses the whole file before main runs.

is_machinery() {
    local name="$1" pattern
    for pattern in ${NOT_DATA}; do
        # shellcheck disable=SC2254
        case "${name}" in ${pattern}) return 0 ;; esac
    done
    return 1
}

data_entries() {
    local path name
    for path in "${DEFENSECLAW_HOME}"/* "${DEFENSECLAW_HOME}"/.[!.]* "${DEFENSECLAW_HOME}"/..?*; do
        [[ -e "${path}" || -L "${path}" ]] || continue
        name="${path##*/}"
        is_machinery "${name}" && continue
        [[ -S "${path}" || -p "${path}" ]] && continue
        printf '%s\n' "${name}"
    done
}

snapshot() {
    local binary link name need have
    rm -rf "${SNAP}"
    mkdir -p "${SNAP}/bin" "${SNAP}/data" || return 1
    need=0
    while IFS= read -r name; do
        need=$((need + $(du -sk "${DEFENSECLAW_HOME}/${name}" 2>/dev/null | awk '{print $1}')))
    done < <(data_entries)
    have="$(df -Pk "${DEFENSECLAW_HOME}" | awk 'NR==2{print $4}')"
    if [[ -n "${need}" && -n "${have}" && "${have}" -lt $((need + 102400)) ]]; then
        err "Not enough free disk space next to ${DEFENSECLAW_HOME} for a rollback copy"
        return 1
    fi
    for binary in ${MANAGED_BINARIES}; do
        [[ -f "${BIN_DIR}/${binary}" ]] && { cp -p "${BIN_DIR}/${binary}" "${SNAP}/bin/${binary}" || return 1; }
    done
    for link in ${MANAGED_LINKS}; do
        [[ -L "${BIN_DIR}/${link}" ]] && { cp -P "${BIN_DIR}/${link}" "${SNAP}/bin/${link}" || return 1; }
    done
    while IFS= read -r name; do
        cp -Rp "${DEFENSECLAW_HOME}/${name}" "${SNAP}/data/" || return 1
    done < <(data_entries)
    if [[ -d "${VENV}" ]]; then mv "${VENV}" "${SNAP}/venv" || return 1; fi
    if [[ -d "${INSTALLER_DIR}" ]]; then mv "${INSTALLER_DIR}" "${SNAP}/installer" || return 1; fi
    if [[ -n "${APP_PATH}" ]]; then
        ditto "${APP_PATH}" "${SNAP}/DefenseClawMac.app" || return 1
    fi
    save_external_config "${SNAP}" || return 1
    printf '%s\n' "${PREV_VERSION:-}" > "${SNAP}/VERSION"
    printf '%s\n' "${WAS_RUNNING}" > "${SNAP}/GATEWAY_WAS_RUNNING"
    : > "${SNAP}/COMPLETE"
}

# A config.yaml outside the data dir (DEFENSECLAW_CONFIG) is part of the snapshot too.
save_external_config() {
    local config="${DEFENSECLAW_CONFIG:-}"
    [[ -n "${config}" && -f "${config}" ]] || return 0
    case "${config}" in "${DEFENSECLAW_HOME}"/*) return 0 ;; esac
    cp -p "${config}" "$1/external-config.yaml" && printf '%s\n' "${config}" > "$1/EXTERNAL_CONFIG"
}

restore_external_config() {
    [[ -f "$1/EXTERNAL_CONFIG" && -f "$1/external-config.yaml" ]] || return 0
    cp -p "$1/external-config.yaml" "$(cat "$1/EXTERNAL_CONFIG")"
}

# recover_interrupted_run: a run killed mid-swap (closed laptop, power loss)
# leaves its snapshot behind. Put the install it saved back before doing
# anything else, so re-running the installer is always the recovery.
recover_interrupted_run() {
    local slot name
    for slot in "${DEFENSECLAW_HOME}/previous.new" "${DEFENSECLAW_HOME}/.repair"; do
        [[ -d "${slot}" ]] || continue
        SNAP="${slot}"
        if [[ -f "${slot}/COMPLETE" ]]; then
            warn "An earlier install was interrupted; restoring the install it replaced"
            stop_gateway "${BIN_DIR}/defenseclaw-gateway" || true
            WAS_RUNNING="$(cat "${slot}/GATEWAY_WAS_RUNNING" 2>/dev/null || echo false)"
            VERSION_BEFORE="${VERSION}"; VERSION="(interrupted)"
            restore_snapshot
            VERSION="${VERSION_BEFORE}"
        else
            # The snapshot never finished, so live data was only copied, not changed.
            undo_snapshot
        fi
    done
    slot="${DEFENSECLAW_HOME}/.rollback-hold"
    if [[ -d "${slot}" ]]; then
        warn "An earlier rollback was interrupted; restoring the install it started from"
        stop_gateway "${BIN_DIR}/defenseclaw-gateway" || true
        if [[ -f "${slot}/STASHED" ]]; then
            # The live install was fully set aside, so anything live now came from previous/.
            mkdir -p "${PREVIOUS}/data"
            while IFS= read -r name; do
                mv "${DEFENSECLAW_HOME}/${name}" "${PREVIOUS}/data/"
            done < <(data_entries)
            if [[ -d "${VENV}" ]]; then mv "${VENV}" "${PREVIOUS}/venv"; fi
            if [[ -d "${INSTALLER_DIR}" ]]; then mv "${INSTALLER_DIR}" "${PREVIOUS}/installer"; fi
        fi
        unstash "${slot}" && rm -rf "${slot}"
    fi
}

# undo_snapshot: put back what snapshot() moved before it failed.
undo_snapshot() {
    if [[ -d "${SNAP}/venv" && ! -e "${VENV}" ]]; then mv "${SNAP}/venv" "${VENV}"; fi
    if [[ -d "${SNAP}/installer" && ! -e "${INSTALLER_DIR}" ]]; then mv "${SNAP}/installer" "${INSTALLER_DIR}"; fi
    rm -rf "${SNAP}"
}

swap_in() {
    local binary link target
    info "Installing DefenseClaw ${VERSION}"
    make_venv "${VENV}" || return 1
    mkdir -p "${BIN_DIR}" || return 1
    for binary in ${MANAGED_BINARIES}; do
        [[ -f "${STAGING}/bin/${binary}" ]] || continue
        cp -p "${STAGING}/bin/${binary}" "${BIN_DIR}/.${binary}.new" \
            && mv -f "${BIN_DIR}/.${binary}.new" "${BIN_DIR}/${binary}" || return 1
    done
    for link in ${MANAGED_LINKS}; do
        target="${VENV}/bin/${link}"
        [[ -x "${target}" ]] || continue
        ln -sfn "${target}" "${BIN_DIR}/${link}" || return 1
    done
    if [[ -n "${APP_PATH}" ]]; then
        swap_app || return 1
    fi
    if [[ -f "${DEFENSECLAW_HOME}/config.yaml" || -n "${DEFENSECLAW_CONFIG:-}" ]]; then
        info "Migrating config and data"
        local args=(migrate --yes)
        [[ -n "${PREV_VERSION}" ]] && args+=(--from-version "${PREV_VERSION}")
        DEFENSECLAW_GATEWAY_BIN="${BIN_DIR}/defenseclaw-gateway" "${VENV}/bin/defenseclaw" "${args[@]}" || return 1
    fi
}

swap_app() {
    local unpacked="${STAGING}/app"
    rm -rf "${unpacked}"
    mkdir -p "${unpacked}"
    # The app is shared by every account on the Mac, unlike the private runtime.
    (umask 022 && ditto -xk "${STAGING}/${APP_ZIP}" "${unpacked}") || return 1
    local new_app
    new_app="$(find "${unpacked}" -maxdepth 1 -name '*.app' -type d | head -1)"
    [[ -n "${new_app}" ]] || return 1
    [[ "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "${new_app}/Contents/Info.plist" 2>/dev/null)" == com.cisco.defenseclaw.macos ]] \
        || return 1
    if [[ "${DEFENSECLAW_INSTALL_CALLER:-}" != app ]] && pgrep -f "${APP_PATH}/Contents/MacOS/" >/dev/null 2>&1; then
        osascript -e 'tell application id "com.cisco.defenseclaw.macos" to quit' >/dev/null 2>&1 || true
        APP_RELAUNCH=1
    fi
    rm -rf "${APP_PATH}.new"
    mv "${new_app}" "${APP_PATH}.new" || return 1
    rm -rf "${APP_PATH}" && mv "${APP_PATH}.new" "${APP_PATH}"
}

restore_snapshot() {
    local failed binary link name
    failed="${DEFENSECLAW_HOME}/.failed-$(date +%Y%m%dT%H%M%S)"
    mkdir -p "${failed}/data"
    for binary in ${MANAGED_BINARIES}; do
        if [[ -f "${SNAP}/bin/${binary}" ]]; then
            cp -p "${SNAP}/bin/${binary}" "${BIN_DIR}/.${binary}.old" && mv -f "${BIN_DIR}/.${binary}.old" "${BIN_DIR}/${binary}"
        else
            rm -f "${BIN_DIR:?}/${binary}"
        fi
    done
    for link in ${MANAGED_LINKS}; do
        rm -f "${BIN_DIR:?}/${link}"
        [[ -L "${SNAP}/bin/${link}" ]] && cp -P "${SNAP}/bin/${link}" "${BIN_DIR}/${link}"
    done
    if [[ -d "${VENV}" ]]; then mv "${VENV}" "${failed}/venv"; fi
    if [[ -d "${SNAP}/venv" ]]; then mv "${SNAP}/venv" "${VENV}"; fi
    rm -rf "${INSTALLER_DIR}"
    if [[ -d "${SNAP}/installer" ]]; then mv "${SNAP}/installer" "${INSTALLER_DIR}"; fi
    while IFS= read -r name; do
        mv "${DEFENSECLAW_HOME}/${name}" "${failed}/data/" 2>/dev/null || rm -rf "${DEFENSECLAW_HOME:?}/${name}"
    done < <(data_entries)
    for name in "${SNAP}/data"/* "${SNAP}/data"/.[!.]* "${SNAP}/data"/..?*; do
        [[ -e "${name}" || -L "${name}" ]] && mv "${name}" "${DEFENSECLAW_HOME}/"
    done
    if [[ -n "${APP_PATH}" && -d "${SNAP}/DefenseClawMac.app" ]]; then
        rm -rf "${APP_PATH}" && mv "${SNAP}/DefenseClawMac.app" "${APP_PATH}"
    fi
    restore_external_config "${SNAP}"
    rm -rf "${SNAP}"
    restart_old
    warn "The failed ${VERSION} install was kept in ${failed} for troubleshooting"
}

restart_old() {
    if [[ "${WAS_RUNNING}" == true ]]; then
        start_gateway >/dev/null 2>&1 || warn "The gateway did not restart; run 'defenseclaw-gateway start'"
    fi
}

start_gateway() {
    info "Starting the gateway"
    PATH="${BIN_DIR}:${PATH}" "${BIN_DIR}/defenseclaw-gateway" start
}

finish_swap() {
    local tmp
    if [[ "${SNAP}" == "${DEFENSECLAW_HOME}/previous.new" && -n "${PREV_VERSION}" ]]; then
        keep_rolled_back_data
        rm -rf "${PREVIOUS}" && mv "${SNAP}" "${PREVIOUS}"
    else
        rm -rf "${SNAP}"
    fi
    mkdir -p "${INSTALLER_DIR}"
    tmp="${INSTALLER_DIR}/.install.sh.new"
    if fetch install.sh "${tmp}" 2>/dev/null && checksum_ok "${tmp}" install.sh; then
        mv -f "${tmp}" "${INSTALLER_DIR}/install.sh"
    elif [[ -f "${BASH_SOURCE[0]:-}" ]] && grep -q "DC_VERSION=\"${VERSION}\"" "${BASH_SOURCE[0]}" 2>/dev/null; then
        cp "${BASH_SOURCE[0]}" "${INSTALLER_DIR}/install.sh"
    fi
    rm -f "${tmp}"
    rm -rf "${DEFENSECLAW_HOME}/.upgrade-recovery" "${DEFENSECLAW_HOME}/.upgrade-receipts" \
        "${HOME}/.defenseclaw-install-custody" "$(dirname "${DEFENSECLAW_HOME}")/.defenseclaw-install-custody"
    find "${TMPDIR:-/tmp}" -maxdepth 1 -user "$(id -u)" -name '.defenseclaw-install-custody-*' \
        -exec rm -rf {} + 2>/dev/null || true
    ok "Installed DefenseClaw ${VERSION}"
}

# A rollback parks the data written since the upgrade in previous/. Keep it
# when a later upgrade reuses the slot: it can hold audit history.
keep_rolled_back_data() {
    [[ -f "${PREVIOUS}/ROLLED_BACK" && -d "${PREVIOUS}/data" ]] || return 0
    local kept
    kept="${DEFENSECLAW_HOME}/backups/rolled-back-$(cat "${PREVIOUS}/VERSION" 2>/dev/null || echo unknown)-$(date +%Y%m%dT%H%M%S)"
    mkdir -p "${DEFENSECLAW_HOME}/backups" && mv "${PREVIOUS}/data" "${kept}" \
        && info "Kept the data from before the last rollback in ${kept}"
}

# stash_live SLOT: move the live install (binaries copied, everything else
# renamed) into SLOT/{bin,data,venv,installer}.
stash_live() {
    local slot="$1" binary link name
    mkdir -p "${slot}/bin" "${slot}/data" || return 1
    for binary in ${MANAGED_BINARIES}; do
        [[ -f "${BIN_DIR}/${binary}" ]] && { cp -p "${BIN_DIR}/${binary}" "${slot}/bin/${binary}" || return 1; }
    done
    for link in ${MANAGED_LINKS}; do
        [[ -L "${BIN_DIR}/${link}" ]] && { cp -P "${BIN_DIR}/${link}" "${slot}/bin/${link}" || return 1; }
    done
    while IFS= read -r name; do
        mv "${DEFENSECLAW_HOME}/${name}" "${slot}/data/" || return 1
    done < <(data_entries)
    if [[ -d "${VENV}" ]]; then mv "${VENV}" "${slot}/venv" || return 1; fi
    if [[ -d "${INSTALLER_DIR}" ]]; then mv "${INSTALLER_DIR}" "${slot}/installer" || return 1; fi
    save_external_config "${slot}"
}

# unstash SLOT: make SLOT the live install again (the inverse of stash_live).
unstash() {
    local slot="$1" binary link name
    for binary in ${MANAGED_BINARIES}; do
        if [[ -f "${slot}/bin/${binary}" ]]; then
            cp -p "${slot}/bin/${binary}" "${BIN_DIR}/.${binary}.old" \
                && mv -f "${BIN_DIR}/.${binary}.old" "${BIN_DIR}/${binary}" || return 1
        else
            rm -f "${BIN_DIR:?}/${binary}"
        fi
    done
    for link in ${MANAGED_LINKS}; do
        rm -f "${BIN_DIR:?}/${link}"
        [[ -L "${slot}/bin/${link}" ]] && { cp -P "${slot}/bin/${link}" "${BIN_DIR}/${link}" || return 1; }
    done
    for name in "${slot}/data"/* "${slot}/data"/.[!.]* "${slot}/data"/..?*; do
        [[ -e "${name}" || -L "${name}" ]] && { mv "${name}" "${DEFENSECLAW_HOME}/" || return 1; }
    done
    if [[ -d "${slot}/venv" ]]; then mv "${slot}/venv" "${VENV}" || return 1; fi
    if [[ -d "${slot}/installer" ]]; then mv "${slot}/installer" "${INSTALLER_DIR}" || return 1; fi
    restore_external_config "${slot}"
}

swap_with_previous() {
    # Exchange the live install and previous/ by renaming, so a second
    # --rollback rolls forward again. Each half undoes itself on failure.
    local hold="${DEFENSECLAW_HOME}/.rollback-hold"
    rm -rf "${hold}"
    if ! stash_live "${hold}"; then
        unstash "${hold}"; rm -rf "${hold}"
        err "Could not set the current install aside; nothing was changed"
        return 1
    fi
    : > "${hold}/STASHED"
    printf '%s\n' "${current}" > "${hold}/VERSION"
    printf '%s\n' "${was_running}" > "${hold}/GATEWAY_WAS_RUNNING"
    if ! unstash "${PREVIOUS}"; then
        stash_live "${PREVIOUS}"; unstash "${hold}"; rm -rf "${hold}"
        err "Could not restore the previous install; the current one is back in place"
        return 1
    fi
    if [[ -n "${APP_PATH}" && -d "${PREVIOUS}/DefenseClawMac.app" ]]; then
        mv "${APP_PATH}" "${hold}/DefenseClawMac.app" && mv "${PREVIOUS}/DefenseClawMac.app" "${APP_PATH}" \
            || warn "Could not swap the macOS app back; it stays at the newer version"
    fi
    date +%Y%m%dT%H%M%S > "${hold}/ROLLED_BACK"
    rm -rf "${PREVIOUS}"
    mv "${hold}" "${PREVIOUS}"
}

# The gateway writes the OpenClaw plugin when it starts; OpenClaw loads it only
# when its own gateway restarts.
restart_openclaw() {
    openclaw_connector_active && has openclaw || return 0
    openclaw gateway restart >/dev/null 2>&1 && ok "OpenClaw gateway restarted" \
        || warn "Restart the OpenClaw gateway to load the updated plugin: openclaw gateway restart"
}

openclaw_connector_active() {
    local state="${DEFENSECLAW_HOME}/active_connector.json"
    [[ -f "${state}" && -x "${VENV}/bin/python" ]] || return 1
    "${VENV}/bin/python" -I - "${state}" <<'PY' >/dev/null 2>&1
import json, sys
state = json.load(open(sys.argv[1], encoding="utf-8"))
names = state.get("names") or [state.get("name")]
sys.exit(0 if "openclaw" in names else 1)
PY
}

pick_connector() {
    step "Pick an agent to guard"
    local index=1 name choice
    for name in ${CONNECTOR_CHOICES}; do
        printf "    ${BOLD}%2d)${NC} %s\n" "${index}" "${name}"
        index=$((index + 1))
    done
    printf "  Choice [default 1=codex]: " >&2
    read -r choice < /dev/tty 2>/dev/null || choice=""
    choice="${choice:-1}"
    index=1
    CONNECTOR=codex
    for name in ${CONNECTOR_CHOICES}; do
        [[ "${index}" == "${choice}" ]] && CONNECTOR="${name}"
        index=$((index + 1))
    done
    ok "Connector: ${CONNECTOR}"
}

first_install_extras() {
    if [[ -n "${CONNECTOR}" && "${CONNECTOR}" != none ]]; then
        printf '%s\n' "${CONNECTOR}" > "${DEFENSECLAW_HOME}/picked_connector"
    fi
    if [[ "${CONNECTOR}" == openclaw ]]; then
        ensure_openclaw
    fi
    if [[ "${INSTALL_SANDBOX}" == true ]]; then
        if [[ "${OS}" != linux || "${CONNECTOR}" != openclaw ]]; then
            warn "--sandbox applies to the OpenClaw connector on Linux only; skipped"
        else
            fetch install-openshell-sandbox.sh "${STAGING}.sandbox.sh" || die "This release has no install-openshell-sandbox.sh"
            verify "${STAGING}.sandbox.sh" install-openshell-sandbox.sh
            bash "${STAGING}.sandbox.sh" || warn "openshell-sandbox installation failed"
            rm -f "${STAGING}.sandbox.sh"
        fi
    fi
    if [[ "${RUN_QUICKSTART}" == true ]]; then
        if [[ -z "${CONNECTOR}" || "${CONNECTOR}" == none ]]; then
            warn "Quickstart needs a connector; run 'defenseclaw init' when ready"
        else
            local args=(quickstart --non-interactive --yes --connector "${CONNECTOR}")
            [[ -n "${QUICKSTART_MODE}" ]] && args+=(--mode "${QUICKSTART_MODE}")
            PATH="${BIN_DIR}:${PATH}" "${VENV}/bin/defenseclaw" "${args[@]}" \
                || warn "Quickstart reported problems; run 'defenseclaw doctor'"
        fi
    elif [[ -n "${CONNECTOR}" && "${CONNECTOR}" != none ]]; then
        printf "\n  Next: ${CYAN}defenseclaw init --connector %s${NC}\n" "${CONNECTOR}"
    else
        printf "\n  Next: ${CYAN}defenseclaw init${NC}\n"
    fi
}

ensure_openclaw() {
    local found
    if has openclaw; then
        found="$(openclaw --version 2>/dev/null | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)"
        if [[ -n "${found}" ]] && ! version_lt "${found}" "${OPENCLAW_VERSION}"; then
            ok "OpenClaw ${found} found"; return
        fi
        ask_yes_no "Update OpenClaw ${found:-?} to ${OPENCLAW_VERSION}?" || { warn "Keeping OpenClaw ${found:-?}"; return; }
    else
        ask_yes_no "Install OpenClaw ${OPENCLAW_VERSION}?" || { warn "Skipping OpenClaw; install it later with npm install -g openclaw@${OPENCLAW_VERSION}"; return; }
    fi
    has npm || { warn "npm is not installed; install OpenClaw with: npm install -g openclaw@${OPENCLAW_VERSION}"; return; }
    npm install -g "openclaw@${OPENCLAW_VERSION}" --loglevel=error \
        || warn "Could not install OpenClaw; run: npm install -g openclaw@${OPENCLAW_VERSION}"
}

ensure_path_hint() {
    case ":${PATH}:" in *":${BIN_DIR}:"*) return ;; esac
    local rc="${HOME}/.profile"
    case "${SHELL:-}" in */zsh) rc="${HOME}/.zshrc" ;; */bash) rc="${HOME}/.bashrc" ;; esac
    printf "\n  Add DefenseClaw to your PATH (then open a new shell):\n"
    printf "    ${CYAN}echo 'export PATH=\"%s:\$PATH\"' >> %s${NC}\n" "${BIN_DIR}" "${rc}"
}

main "$@"
# DefenseClaw POSIX installer complete v2
