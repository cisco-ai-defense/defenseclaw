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
# DEFENSECLAW_REPO (the deprecated alias of config.yaml update.source) is a
# GitHub owner/name or an https mirror base URL. It only changes where release
# bytes come from: signatures are always checked against the official release
# identity, and a mirror's downloads are refused without cosign.
case "${REPO}" in
    https://*) RELEASE_BASE="${REPO%/}" ;;
    *) RELEASE_BASE="https://github.com/${REPO}" ;;
esac
readonly RELEASE_BASE
readonly OFFICIAL_RELEASE_BASE="https://github.com/${DEFAULT_REPO}"
readonly RELEASE_SIGNER='^https://github\.com/cisco-ai-defense/defenseclaw/\.github/workflows/release\.yaml@refs/heads/main$'
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
        ! -name install.sh ! -name checksums.txt ! -name checksums.txt.bundle -print -quit 2>/dev/null)" ]]; then
    SELF_TMP=""
fi
[[ -z "${SELF_TMP}" ]] || trap 'rm -rf "${SELF_TMP}"' EXIT
readonly OPENCLAW_VERSION="2026.3.24"
# The PATH the user's shell has. Installing uv adds BIN_DIR to this process's
# PATH, so the PATH hint at the end checks this copy instead.
readonly CALLER_PATH="${PATH}"
readonly MACOS_SYSCTL_BIN="/usr/sbin/sysctl"
# Real files in BIN_DIR. Connector hooks record these paths, so they never move.
readonly MANAGED_BINARIES="defenseclaw-gateway defenseclaw-acp"
# Symlinks in BIN_DIR that point into the venv.
readonly MANAGED_LINKS="defenseclaw skill-scanner mcp-scanner"
# Data-dir entries that are install machinery, not user data.
readonly NOT_DATA=".venv .uv previous previous.new .repair .rollback-hold .rollback-hold.done .staging .failed-* installer logs .install.lock backups"
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

# Read one answer from the terminal. A terminal left in -icrnl by an earlier
# program sends Enter as a bare carriage return, so map CR to NL for this
# read only, and drop a stray trailing CR from the answer.
read_tty_line() {
    local saved="" line=""
    saved=$(stty -g < /dev/tty 2>/dev/null) && stty icrnl < /dev/tty 2>/dev/null
    read -r line < /dev/tty 2>/dev/null || { [[ -n "${saved}" ]] && stty "${saved}" < /dev/tty 2>/dev/null; return 1; }
    [[ -n "${saved}" ]] && stty "${saved}" < /dev/tty 2>/dev/null
    printf '%s' "${line%$'\r'}"
}

ask_yes_no() {
    local prompt="$1" default="${2:-y}" answer
    [[ "${YES}" == true ]] && return 0
    if [[ "${default}" == y ]]; then prompt="${prompt} [Y/n]"; else prompt="${prompt} [y/N]"; fi
    printf "  %s " "${prompt}" >&2
    answer=$(read_tty_line) || answer="${default}"
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
QUICKSTART_RC=0
OPENCLAW_MISSING=false
OPENCLAW_INSTALLED=false
OPENCLAW_NEXT=""
QUICKSTART_RERUN=""
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
  --quickstart             Run 'defenseclaw quickstart' afterwards if nothing is configured yet
  --quickstart-mode MODE   observe or action (implies --quickstart)
  --sandbox                Deprecated no-op, removed in 1.1.0 (the legacy openshell-sandbox installer was removed)
  --help, -h               Show this help

Exit codes:
  0  Installed        1  Not installed (a previous install is restored)
  3  Installed; a connector needs attention before it is guarded again
  4  Installed; the first-run quickstart failed (re-run it as shown)

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
        --sandbox) INSTALL_SANDBOX=true ;;
        --help|-h) usage; exit 0 ;;
        *) warn "Ignoring unknown option: $1" ;;
    esac
    shift
done
if [[ "${INSTALL_SANDBOX}" == true ]]; then
    # The legacy openshell-sandbox (0.0.x) installer was removed; --sandbox is
    # accepted until 1.1.0 so existing automation keeps working, and does
    # nothing. It is not forwarded to another release's installer either.
    warn "--sandbox is deprecated and ignored, and removed in 1.1.0: the legacy openshell-sandbox installer was removed. To run agents in NVIDIA OpenShell 0.1 sandboxes, run 'defenseclaw sandbox setup' after the install; to remove an old standalone sandbox first, run 'defenseclaw sandbox legacy-cleanup --dry-run'."
fi
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

# ── Managed hosts ────────────────────────────────────────────────────────────

# A computer whose DefenseClaw is managed by the organization is installed
# and updated through its MDM. A per-user copy would compete with the managed
# services for the gateway port and the agents' hooks, so stop before
# changing anything. The platform descriptor is always checked: the
# environment can only add a path (DEFENSECLAW_INSTALL_MANAGED_DESCRIPTOR, for
# tests), never replace it, so a user cannot talk the installer past the check.
case "${OS}" in
    linux) managed_descriptors=(/etc/defenseclaw/managed-runtime.json) ;;
    darwin) managed_descriptors=(/opt/cisco/defenseclaw/etc/managed-runtime.json) ;;
esac
if [[ -n "${DEFENSECLAW_INSTALL_MANAGED_DESCRIPTOR:-}" ]]; then
    managed_descriptors+=("${DEFENSECLAW_INSTALL_MANAGED_DESCRIPTOR}")
fi
for managed_descriptor in "${managed_descriptors[@]}"; do
    if [[ -f "${managed_descriptor}" && ! -L "${managed_descriptor}" ]]; then
        die "This computer's DefenseClaw is managed by your organization (${managed_descriptor}); your IT department installs and updates it. Nothing was changed."
    fi
done

# ── Which version does this installer install? ───────────────────────────────

fetch() {
    # fetch ASSET DEST [VERSION]: copy from --local or download from the release.
    local asset="$1" dest="$2" version="${3:-${VERSION}}"
    if [[ -n "${LOCAL_DIR}" ]]; then
        [[ -f "${LOCAL_DIR}/${asset}" ]] || return 1
        cp "${LOCAL_DIR}/${asset}" "${dest}"
    else
        curl -fsSL --retry 3 --proto '=https' --tlsv1.2 -o "${dest}" \
            "${RELEASE_BASE}/releases/download/${version}/${asset}"
    fi
}

latest_release() {
    local location
    location="$(curl -fsSI --proto '=https' --tlsv1.2 "${RELEASE_BASE}/releases/latest" 2>/dev/null \
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
        "${RELEASE_BASE}/releases/download/${version}/install.sh" \
        || die "Release ${version} has no install.sh (1.x releases start at 1.0.0)"
    curl -fsSL --retry 3 --proto '=https' --tlsv1.2 -o "${tmp}/checksums.txt" \
        "${RELEASE_BASE}/releases/download/${version}/checksums.txt" \
        || die "Release ${version} has no checksums.txt"
    [[ "$(awk '$2=="install.sh"||$2=="*install.sh"{print $1}' "${tmp}/checksums.txt")" == "$(sha256_of "${tmp}/install.sh")" ]] \
        || die "install.sh for ${version} does not match its checksums.txt"
    # With cosign, the installer about to run is checked like the assets it installs.
    local major
    major="$(cosign version 2>/dev/null | awk '/GitVersion/{print $2}' | sed 's/^v//' | cut -d. -f1 || true)"
    if [[ "${major:-0}" =~ ^[0-9]+$ && "${major:-0}" -ge 2 ]]; then
        curl -fsSL --retry 3 --proto '=https' --tlsv1.2 -o "${tmp}/checksums.txt.bundle" \
            "${RELEASE_BASE}/releases/download/${version}/checksums.txt.bundle" \
            || die "Release ${version} has no checksums.txt.bundle to verify with cosign"
        cosign verify-blob --bundle "${tmp}/checksums.txt.bundle" \
            --certificate-identity-regexp "${RELEASE_SIGNER}" \
            --certificate-oidc-issuer https://token.actions.githubusercontent.com \
            "${tmp}/checksums.txt" >/dev/null 2>&1 \
            || die "The release signature on ${version}'s checksums.txt did not verify"
    elif [[ "${RELEASE_BASE}" != "${OFFICIAL_RELEASE_BASE}" ]]; then
        die "Releases from ${RELEASE_BASE} are verified by their signature: install cosign 2.0 or later"
    fi
    # Every release is signed by the same identity, so the signature alone
    # would let a mirror serve another (older) release under this version.
    local stamped
    stamped="$(sed -n 's/^readonly DC_VERSION="\(.*\)"$/\1/p' "${tmp}/install.sh" | head -1)"
    [[ "${stamped#v}" == "${version#v}" ]] \
        || die "The installer served for ${version} is release ${stamped:-unknown}; refusing a mismatched release"
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
        version_lt "${target}" 1.0.0 \
            && die "DefenseClaw ${target} predates this installer; see ${RELEASE_BASE}/releases/tag/${target}"
        run_release_installer "${target}" ${FORWARD[@]+"${FORWARD[@]}"}
    fi
fi
if [[ -n "${TARGET_VERSION}" && "${TARGET_VERSION}" != "${VERSION}" && "${ROLLBACK}" != true ]]; then
    version_lt "${TARGET_VERSION}" 1.0.0 \
        && die "DefenseClaw ${TARGET_VERSION} predates this installer; see ${RELEASE_BASE}/releases/tag/${TARGET_VERSION}"
    [[ -z "${LOCAL_DIR}" ]] || die "--local ${LOCAL_DIR} holds ${VERSION}, not ${TARGET_VERSION}"
    run_release_installer "${TARGET_VERSION}" ${FORWARD[@]+"${FORWARD[@]}"}
fi

[[ "${ROLLBACK}" == true ]] || require_free_space

# ── Lock and log ─────────────────────────────────────────────────────────────

LOCK_HINT="check the free space (df -h ${DEFENSECLAW_HOME%/*}) and that $(id -un) can write there; nothing was changed"
mkdir -p "${DEFENSECLAW_HOME}" "${DEFENSECLAW_HOME}/logs" 2>/dev/null \
    || die "Could not create ${DEFENSECLAW_HOME}/logs: ${LOCK_HINT}"
chmod 700 "${DEFENSECLAW_HOME}" 2>/dev/null || true
if ! mkdir "${LOCK_DIR}" 2>/dev/null; then
    holder="$(cat "${LOCK_DIR}/pid" 2>/dev/null || true)"
    if [[ -n "${holder}" ]] && kill -0 "${holder}" 2>/dev/null; then
        die "Another DefenseClaw install is running (pid ${holder})"
    fi
    rm -rf "${LOCK_DIR}"
    mkdir "${LOCK_DIR}" 2>/dev/null || die "Could not create the install lock ${LOCK_DIR}: ${LOCK_HINT}"
fi
if ! { echo $$ > "${LOCK_DIR}/pid"; } 2>/dev/null; then
    rm -rf "${LOCK_DIR}"
    die "Could not write the install lock ${LOCK_DIR}/pid: ${LOCK_HINT}"
fi
LOG="${DEFENSECLAW_HOME}/logs/install-$(date +%Y%m%dT%H%M%S).log"
# tee ignores Ctrl+C: it went down with the installer's process group, and the
# cancel message then died on a broken pipe (exit 141, GAP-1901).
exec > >(trap '' INT TERM; exec tee -a "${LOG}") 2>&1
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
    # The gateway on PATH is the install that runs. A `make all` source install
    # replaces it (and the CLI link) but leaves an older release venv behind, so
    # that venv's version is only the fallback (GAP-2454).
    local info version=""
    if [[ -x "${BIN_DIR}/defenseclaw-gateway" ]]; then
        version="$("${BIN_DIR}/defenseclaw-gateway" --version 2>/dev/null | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)"
    fi
    if [[ -n "${version}" ]]; then
        printf '%s' "${version}"
        return
    fi
    for info in "${VENV}"/lib/python*/site-packages/defenseclaw-*.dist-info; do
        [[ -d "${info}" ]] || continue
        info="${info##*/defenseclaw-}"
        printf '%s' "${info%.dist-info}"
        return
    done
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
            if [[ -w "${candidate}" && -w "$(dirname "${candidate}")" ]]; then
                APP_PATH="${candidate}"
            elif [[ "${candidate}" == "${DEFENSECLAW_APP_PATH:-}" \
                && "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "${candidate}/Contents/Info.plist" 2>/dev/null)" != "${VERSION}" ]]; then
                # Asked for by name (the app's own Update runs this), so a CLI
                # update alone would leave the app offering the same update.
                die "${candidate} is not writable by $(id -un); nothing was changed (update it from the DMG)"
            else
                warn "${candidate} is not writable by $(id -un); leaving the app as it is (update it from the DMG)"
            fi
            break
        fi
    done
fi

recover_interrupted_run

# ── Rollback-only mode ───────────────────────────────────────────────────────

if [[ "${ROLLBACK}" == true ]]; then
    [[ -s "${PREVIOUS}/VERSION" ]] || { step "Rolling back"; die "No previous install to roll back to (${PREVIOUS} is missing)"; }
    back_to="$(cat "${PREVIOUS}/VERSION")"
    current="$(installed_version)"
    # Run again after a rollback, this goes forward to the newer install.
    if [[ -n "${current}" ]] && version_lt "${current}" "${back_to}"; then
        step "Rolling forward to DefenseClaw ${back_to}"
        question="Replace DefenseClaw ${current} with DefenseClaw ${back_to} (the install you rolled back from)?"
    else
        step "Rolling back to DefenseClaw ${back_to}"
        question="Replace DefenseClaw ${current:-?} with the previous install (${back_to})?"
    fi
    ask_yes_no "${question}" || die "Rollback cancelled; nothing was changed"
    was_running=false
    [[ -n "$(gateway_pid || true)" ]] && was_running=true
    # The swap overwrites previous/GATEWAY_WAS_RUNNING with this install's state.
    restart="${was_running}"
    [[ "$(cat "${PREVIOUS}/GATEWAY_WAS_RUNNING" 2>/dev/null)" == true ]] && restart=true
    stop_gateway "${BIN_DIR}/defenseclaw-gateway" || die "The gateway did not stop; nothing was changed"
    if [[ -n "${current}" ]] && version_lt "${back_to}" 1.0.0 && ! version_lt "${current}" 1.0.0; then
        remove_connector_registrations_for_legacy
    fi
    swapped=0
    swap_with_previous || swapped=$?
    if [[ "${swapped}" -ne 0 ]]; then
        # 1: the swap undid itself, so this install is back and may run again.
        [[ "${swapped}" -eq 1 && "${was_running}" == true ]] && { start_gateway || true; }
        die "Rollback failed part-way; see ${LOG}"
    fi
    rollback_rc=0
    if [[ "${restart}" == true ]]; then
        start_gateway || rollback_rc=$?
        case "${rollback_rc}" in
            0) restart_openclaw ;;
            3) warn "A connector needs attention before it is guarded again (see the gateway output above)"; restart_openclaw ;;
            *) rollback_rc=1 ;;
        esac
    fi
    if [[ ${rollback_rc} -eq 1 ]]; then
        # The swap is done, but the hooks are unguarded: say so, and exit 1.
        warn "Now running DefenseClaw ${back_to}, but its gateway is not up, so agent hooks are not guarded until it is"
        # A start that said why it failed already printed the command that fixes it.
        [[ -n "${START_EXPLAINED:-}" ]] || info "Start it with: defenseclaw-gateway start (its log: ${DEFENSECLAW_HOME}/gateway.log)"
    else
        ok "Now running DefenseClaw ${back_to}."
    fi
    if version_lt "${back_to}" 1.0.0; then
        info "To return to ${current:-1.x}, run: bash ${PREVIOUS}/installer/install.sh --rollback"
    else
        info "Run 'defenseclaw rollback' again to return to ${current:-the other install}."
    fi
    # The swap keeps the install just left, with its data, in previous/.
    if [[ -z "${current}" ]] || version_lt "${back_to}" "${current}"; then
        info "Data written since the upgrade is kept in ${PREVIOUS} and comes back if you roll forward."
    else
        info "Data written while ${current} ran is kept in ${PREVIOUS} and comes back if you roll back again."
    fi
    exit "${rollback_rc}"
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
# The download cache and the Python uv fetches for the venv stay in the data
# dir, so `uninstall --all` leaves nothing of them in ~/.cache or ~/.local.
export UV_CACHE_DIR="${UV_CACHE_DIR:-${DEFENSECLAW_HOME}/.uv/cache}"
export UV_PYTHON_INSTALL_DIR="${UV_PYTHON_INSTALL_DIR:-${DEFENSECLAW_HOME}/.uv/python}"
UV_DIR_NEW=""
UV_INSTALLED=""
[[ -e "${DEFENSECLAW_HOME}/.uv" ]] || UV_DIR_NEW=1
# A uv already in BIN_DIR belongs to the user (or an earlier run) even when
# BIN_DIR is not on this shell's PATH yet: use it, never overwrite it.
if ! has uv && [[ -x "${BIN_DIR}/uv" && ! -d "${BIN_DIR}/uv" ]]; then
    export PATH="${BIN_DIR}:${PATH}"
fi
if ! has uv; then
    info "Installing uv ${UV_VERSION} (Python package manager)"
    install_uv || die "Could not install uv; install it from https://docs.astral.sh/uv/ and retry"
    UV_INSTALLED=1
    export PATH="${BIN_DIR}:${PATH}"
    has uv || die "uv was installed but is not on PATH"
fi

rm -rf "${STAGING}"
mkdir -p "${STAGING}/bin"
# Ctrl+C before the swap: drop what this run staged and fetched (GAP-1901).
trap 'printf "\n"; rm -rf "${STAGING}"; [[ -z "${UV_DIR_NEW}" ]] || rm -rf "${DEFENSECLAW_HOME}/.uv"; [[ -z "${UV_INSTALLED}" ]] || rm -f "${BIN_DIR}/uv" "${BIN_DIR}/uvx" "${BIN_DIR}/defenseclaw-uv.sha256"; err "Cancelled; nothing was changed"; exit 130' INT TERM
ARCHIVE="defenseclaw-${VERSION}-${OS}-${ARCH}.tar.gz"
WHEEL="defenseclaw-${VERSION}-py3-none-any.whl"
REQUIREMENTS="defenseclaw-${VERSION}-requirements.txt"
APP_ZIP="DefenseClawMac-${VERSION}-macos-arm64.zip"

# A copy or download that fails removes what it staged. When the filesystem
# filled up meanwhile (other writers, a free-space figure the preflight could
# not read), say so instead of "Could not get" (GAP-1307).
fetch_failed() {
    local asset="$1" free_kb need_kb="${space_needed_kb:-$((400 * 1024))}"
    rm -rf "${STAGING}"
    free_kb="$(df -Pk "${DEFENSECLAW_HOME}" 2>/dev/null | awk 'NR==2{print $4}')"
    if [[ "${free_kb}" =~ ^[0-9]+$ && "${free_kb}" -lt "${need_kb}" ]]; then
        err "Ran out of disk space next to ${DEFENSECLAW_HOME} while staging ${asset}: the install needs about $((need_kb / 1024)) MB and $((free_kb / 1024)) MB is free"
        die "Free at least $(((need_kb - free_kb + 1023) / 1024)) MB on that filesystem (df -h ${DEFENSECLAW_HOME}), then rerun; nothing was changed"
    fi
    die "Could not get ${asset} for ${VERSION}; nothing was changed"
}

info "Downloading and verifying release assets"
fetch checksums.txt "${STAGING}/checksums.txt" || fetch_failed checksums.txt
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
            --certificate-identity-regexp "${RELEASE_SIGNER}" \
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
elif [[ -z "${LOCAL_DIR}" && "${RELEASE_BASE}" != "${OFFICIAL_RELEASE_BASE}" ]]; then
    die "Releases from ${RELEASE_BASE} are verified by their signature: install cosign 2.0 or later; nothing was changed"
elif [[ -z "${LOCAL_DIR}" ]]; then
    info "cosign 2.0 or later is not installed; downloads are checked against checksums.txt only"
fi
for asset in "${ARCHIVE}" "${WHEEL}" "${REQUIREMENTS}"; do
    fetch "${asset}" "${STAGING}/${asset}" || fetch_failed "${asset}"
    verify "${STAGING}/${asset}"
done
if [[ -n "${APP_PATH}" ]]; then
    fetch "${APP_ZIP}" "${STAGING}/${APP_ZIP}" || fetch_failed "${APP_ZIP}"
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

info "Building the Python environment (a first install can take several minutes)"
make_venv() {
    local venv="$1"
    rm -rf "${venv}"
    uv venv "${venv}" --quiet --python 3.12 2>/dev/null \
        || uv venv "${venv}" --quiet --python '>=3.11,<3.14' \
        || return 1
    # The requirements file is the complete hashed lock, so nothing resolves.
    # --compile-bytecode: uv skips compiling by default, which moves that cost
    # to the first start of the CLI and the scanners.
    uv pip install --quiet --compile-bytecode --python "${venv}/bin/python" --require-hashes --no-deps -r "${STAGING}/${REQUIREMENTS}" \
        && uv pip install --quiet --compile-bytecode --python "${venv}/bin/python" --no-deps "${STAGING}/${WHEEL}"
}
if ! make_venv "${STAGING}/venv"; then
    # Leave nothing of a failed build behind, and name what stays (GAP-1438).
    rm -rf "${STAGING}"
    drop_new_uv
    if [[ -z "${UV_DIR_NEW}" && -d "${DEFENSECLAW_HOME}/.uv" ]]; then
        die "Could not install the DefenseClaw ${VERSION} Python package. Nothing else was changed, but uv's download cache ${DEFENSECLAW_HOME}/.uv ($(du -sm "${DEFENSECLAW_HOME}/.uv" 2>/dev/null | awk '{print $1}') MB) is kept; delete it to free that space"
    fi
    die "Could not install the DefenseClaw ${VERSION} Python package; nothing was changed"
fi
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
    if version_lt "${PREV_VERSION}" 1.0.0 && [[ -f "${DEFENSECLAW_HOME}/audit.db" ]]; then
        # Audit migration 33 (privacy cutover) empties the pre-1.0 history.
        warn "DefenseClaw 1.0 starts a new audit history: the audit events, scan results and findings ${PREV_VERSION} recorded (${DEFENSECLAW_HOME}/audit.db, $(du -sh "${DEFENSECLAW_HOME}/audit.db" 2>/dev/null | awk '{print $1}')) are deleted when DefenseClaw ${VERSION} first opens its audit database"
        info "A copy is kept in ${PREVIOUS}/data/audit.db; 'defenseclaw rollback' brings it back, and later upgrades keep it in ${DEFENSECLAW_HOME}/backups"
    fi
    ask_yes_no "Upgrade DefenseClaw ${PREV_VERSION} → ${VERSION}?" || die "Cancelled; nothing was changed"
fi
if [[ -z "${PREV_VERSION}" ]] && [[ "${YES}" != true ]] && [[ -z "${CONNECTOR}" ]]; then
    pick_connector
fi

WAS_RUNNING=false
RESTORED_NOTE="Your previous install is back."
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
if ! snapshot; then
    undo_snapshot
    restart_old
    rm -rf "${STAGING}"
    drop_new_uv
    die "Could not save the current install; nothing was changed"
fi

if ! swap_in; then
    err "Installing ${VERSION} failed; restoring ${PREV_VERSION:-the previous state}"
    restore_snapshot
    die "DefenseClaw ${VERSION} was not installed. ${RESTORED_NOTE} Log: ${LOG}"
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
        die "DefenseClaw ${VERSION} was not installed. ${RESTORED_NOTE} Log: ${LOG}"
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

# True when the config sets guardrail.enabled to false, as 'uninstall' and
# 'setup guardrail --disable' write it (a direct child of the top-level block).
guardrail_off() {
    local config="${DEFENSECLAW_CONFIG:-${DEFENSECLAW_HOME}/config.yaml}"
    [[ -f "${config}" ]] || return 1
    awk '
        /^guardrail:[ \t]*$/ { block = 1; indent = 0; next }
        block && /^[^ \t#]/ { block = 0 }
        block && /^[ \t]+[^ \t#]/ {
            match($0, /^[ \t]+/)
            if (!indent) indent = RLENGTH
            if (RLENGTH == indent && $0 ~ /^[ \t]+enabled:[ \t]*false[ \t]*(#.*)?\r?$/) off = 1
        }
        END { exit !off }
    ' "${config}"
}

if [[ -z "${PREV_VERSION}" ]]; then
    first_install_extras
elif [[ "${RUN_QUICKSTART}" == true && ! -f "${DEFENSECLAW_HOME}/config.yaml" && -z "${DEFENSECLAW_CONFIG:-}" ]]; then
    # Installed but never set up, so the asked-for quickstart is still the first run.
    first_install_extras
elif [[ "${RUN_QUICKSTART}" == true ]]; then
    QUICKSTART_HINT="defenseclaw quickstart"
    [[ -n "${CONNECTOR}" && "${CONNECTOR}" != "none" ]] && QUICKSTART_HINT+=" --connector ${CONNECTOR}"
    [[ -n "${QUICKSTART_MODE}" ]] && QUICKSTART_HINT+=" --mode ${QUICKSTART_MODE}"
    warn "Skipped --quickstart: DefenseClaw is already configured. To run it now: ${QUICKSTART_HINT}"
fi
rm -rf "${STAGING}"
ensure_path_hint
printf "\n${BOLD}${GREEN}  DefenseClaw ${VERSION} is installed.${NC}\n"
if [[ -n "${PREV_VERSION}" && "${PREV_VERSION}" != "${VERSION}" ]]; then
    printf "  Upgraded from ${PREV_VERSION}. Undo with: ${CYAN}defenseclaw rollback${NC}\n"
    if version_lt "${PREV_VERSION}" 1.0.0 && [[ -f "${PREVIOUS}/data/audit.db" ]]; then
        printf "  The audit history ${PREV_VERSION} recorded is not carried over to 1.0; a copy is in ${PREVIOUS}/data/audit.db\n"
    fi
    if pgrep -f "${VENV}/bin/defenseclaw" >/dev/null 2>&1; then
        warn "Restart the DefenseClaw TUI and any other open DefenseClaw commands; they still run ${PREV_VERSION}"
    fi
fi
if [[ -n "${PREV_VERSION}" && -z "$(gateway_pid || true)" ]] \
    && [[ -f "${DEFENSECLAW_HOME}/config.yaml" || -n "${DEFENSECLAW_CONFIG:-}" ]]; then
    # GAP-1496: it was not running before the upgrade, so it was not started.
    if guardrail_off; then
        # GAP-2481: 'uninstall --binaries' turned the guardrail off and tore the
        # connector hooks down; a gateway start alone does not set them up again.
        warn "Protection is off in the kept config (guardrail.enabled = false), so agent hooks are not guarded"
        printf "  Turn it back on with: ${CYAN}defenseclaw setup guardrail${NC}\n"
    else
        warn "The gateway is not running, so agent hooks are not guarded until it is"
        printf "  Start it with: ${CYAN}defenseclaw-gateway start${NC}\n"
    fi
fi
if [[ -n "${PREV_VERSION}" && "${RUN_QUICKSTART}" != true && ! -f "${DEFENSECLAW_HOME}/config.yaml" && -z "${DEFENSECLAW_CONFIG:-}" ]]; then
    # An earlier install that was never initialized: say how to start, as a
    # fresh install does, with the connector picked back then.
    NEXT_CONNECTOR="${CONNECTOR}"
    if [[ -z "${NEXT_CONNECTOR}" && -f "${DEFENSECLAW_HOME}/picked_connector" ]]; then
        NEXT_CONNECTOR="$(head -n 1 "${DEFENSECLAW_HOME}/picked_connector" | tr -cd 'a-z0-9_-')"
    fi
    if [[ -n "${NEXT_CONNECTOR}" && "${NEXT_CONNECTOR}" != none ]]; then
        printf "  DefenseClaw is not set up yet. Next: ${CYAN}defenseclaw init --connector %s${NC}\n" "${NEXT_CONNECTOR}"
    else
        printf "  DefenseClaw is not set up yet. Next: ${CYAN}defenseclaw init${NC}\n"
    fi
fi
if [[ -n "${APP_RELAUNCH:-}" ]]; then
    open "${APP_PATH}" >/dev/null 2>&1 || true
fi
printf "\n"
if [[ -n "${QUICKSTART_RERUN}" ]]; then
    if [[ "${CONNECTOR}" == hermes ]] && ! PATH="${BIN_DIR}:${PATH}" has hermes; then
        # GAP-2383: the agent itself is missing, so say how to get it.
        err "Quickstart failed (exit ${QUICKSTART_RC}): DefenseClaw ${VERSION} is installed, but Hermes is not installed yet"
        printf "  Install Hermes (https://github.com/NousResearch/hermes-agent), then run:\n    ${CYAN}%s${NC}\n\n" "${QUICKSTART_RERUN}"
    else
        err "Quickstart failed (exit ${QUICKSTART_RC}): DefenseClaw ${VERSION} is installed, but ${CONNECTOR} is not set up yet"
        printf "  Fix what quickstart reported above ('defenseclaw doctor' helps), then run:\n    ${CYAN}%s${NC}\n\n" "${QUICKSTART_RERUN}"
    fi
    exit 4
fi
if [[ "${OPENCLAW_MISSING}" == true ]]; then
    # GAP-1523: OpenClaw is the connector asked for and is not installed.
    warn "OpenClaw is not installed, so it is not guarded yet. Install it as shown above, then run: ${OPENCLAW_NEXT:-defenseclaw setup openclaw}"
    exit 3
fi
if [[ "${OPENCLAW_INSTALLED}" == true ]]; then
    # A new OpenClaw has no model or gateway yet (GAP-1523).
    printf "  Next: set up OpenClaw itself with: ${CYAN}openclaw onboard${NC}\n\n"
fi
exit ${START_RC}

}

# ── Snapshot, swap, restore ──────────────────────────────────────────────────
# Defined outside main() is fine: bash parses the whole file before main runs.

# uv, when it is missing: a pinned release, checked against the digests below
# (from the release's .sha256 files) before anything runs. Bump them together.
readonly UV_VERSION="0.12.13"
uv_sha256() {
    case "$1" in
        uv-aarch64-apple-darwin.tar.gz) echo 7e6ddb9316acc00f2296c82ff4d99977870ee34b2f0ddcae9444d714db9364ed ;;
        uv-x86_64-unknown-linux-musl.tar.gz) echo 4e2bfd0c9007b1032a50e539e965fd0a6037d87ad93ae1580d220a92d4c94098 ;;
        uv-aarch64-unknown-linux-musl.tar.gz) echo f44bc1037a17889fe562fffd2002d4ed108e499fbe68b4f022af244dc7b8244f ;;
    esac
}
install_uv() {
    local target tmp asset
    case "${OS}/${ARCH}" in
        darwin/arm64) target=aarch64-apple-darwin ;;
        linux/amd64) target=x86_64-unknown-linux-musl ;;
        linux/arm64) target=aarch64-unknown-linux-musl ;;
        *) return 1 ;;
    esac
    # Never replace a uv or uvx this installer did not just download.
    [[ -e "${BIN_DIR}/uv" || -e "${BIN_DIR}/uvx" ]] && return 1
    asset="uv-${target}.tar.gz"
    tmp="$(mktemp -d)" || return 1
    if curl -fsSL --retry 3 --proto '=https' --tlsv1.2 -o "${tmp}/${asset}" \
            "https://github.com/astral-sh/uv/releases/download/${UV_VERSION}/${asset}" \
        && [[ "$(sha256_of "${tmp}/${asset}")" == "$(uv_sha256 "${asset}")" ]] \
        && tar -xzf "${tmp}/${asset}" -C "${tmp}" \
        && mkdir -p "${BIN_DIR}" \
        && cp "${tmp}/uv-${target}/uv" "${tmp}/uv-${target}/uvx" "${BIN_DIR}/"; then
        chmod 755 "${BIN_DIR}/uv" "${BIN_DIR}/uvx"
        # `defenseclaw uninstall --binaries` removes the uv this installed
        # while it still matches this record.
        printf '%s  uv\n%s  uvx\n' "$(sha256_of "${BIN_DIR}/uv")" "$(sha256_of "${BIN_DIR}/uvx")" \
            > "${BIN_DIR}/defenseclaw-uv.sha256" || true
        rm -rf "${tmp}"
        return 0
    fi
    rm -rf "${tmp}"
    return 1
}

# A failed install removes what it added for uv: the uv and uvx it
# downloaded, and uv's cache and Python when this run created them (GAP-1438).
drop_new_uv() {
    [[ -z "${UV_DIR_NEW}" ]] || rm -rf "${DEFENSECLAW_HOME}/.uv"
    [[ -z "${UV_INSTALLED}" ]] || rm -f "${BIN_DIR}/uv" "${BIN_DIR}/uvx" "${BIN_DIR}/defenseclaw-uv.sha256"
}

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

# require_free_space refuses before anything is written when the disk cannot
# hold the install: uv's cache, the Python it fetches and the new environment
# (about 1100 MB on a first install, down to 400 MB once the cache holds the
# packages) plus, over an existing install, the rollback copy of the data that
# the swap saves. Runs before the lock and before the gateway is stopped
# (GAP-1249, GAP-1527, GAP-1538).
require_free_space() {
    local cache="${UV_CACHE_DIR:-${DEFENSECLAW_HOME}/.uv/cache}" dir="${DEFENSECLAW_HOME}"
    local free_kb need_kb copy_kb=0 size name biggest="" biggest_kb=0 cache_kb=0
    # An empty or partly filled cache saves only what it holds (GAP-1438).
    if [[ -d "${cache}" ]]; then
        cache_kb="$(du -sk "${cache}" 2>/dev/null | awk '{print $1}')"
    fi
    [[ "${cache_kb}" =~ ^[0-9]+$ ]] || cache_kb=0
    cache_kb=$((cache_kb / 1024 * 1024))
    [[ "${cache_kb}" -le $((700 * 1024)) ]] || cache_kb=$((700 * 1024))
    space_needed_kb=$((1100 * 1024 - cache_kb))
    while [[ ! -d "${dir}" && "${dir}" == */* ]]; do dir="${dir%/*}"; done
    free_kb="$(df -Pk "${dir:-/}" 2>/dev/null | awk 'NR==2{print $4}')"
    [[ "${free_kb}" =~ ^[0-9]+$ ]] || return 0
    # A .staging left by an interrupted run is replaced, so its space counts as free.
    if [[ -d "${STAGING}" ]]; then
        size="$(du -sk "${STAGING}" 2>/dev/null | awk '{print $1}')"
        free_kb=$((free_kb + ${size:-0}))
    fi
    if [[ -d "${VENV}" ]]; then
        while IFS= read -r name; do
            size="$(du -sk "${DEFENSECLAW_HOME}/${name}" 2>/dev/null | awk '{print $1}')"
            size="${size:-0}"
            copy_kb=$((copy_kb + size))
            if [[ "${size}" -gt "${biggest_kb}" ]]; then biggest="${name}" biggest_kb="${size}"; fi
        done < <(data_entries)
        copy_kb=$((copy_kb + 102400))
    fi
    need_kb=$((space_needed_kb + copy_kb))
    [[ "${free_kb}" -lt "${need_kb}" ]] || return 0
    if [[ ${copy_kb} -gt 0 ]]; then
        err "Not enough free disk space next to ${DEFENSECLAW_HOME}: the upgrade needs about $(((need_kb + 1023) / 1024)) MB ($((space_needed_kb / 1024)) MB for the new version and $(((copy_kb + 1023) / 1024)) MB for a rollback copy of your data) and $((free_kb / 1024)) MB is free"
        [[ -z "${biggest}" ]] || err "The largest item is ${DEFENSECLAW_HOME}/${biggest} ($(((biggest_kb + 1023) / 1024)) MB)"
    else
        err "Not enough free disk space next to ${DEFENSECLAW_HOME}: the install needs about $((need_kb / 1024)) MB and $((free_kb / 1024)) MB is free"
    fi
    die "Free at least $(((need_kb - free_kb + 1023) / 1024)) MB on that filesystem (df -h ${dir}), then rerun; nothing was changed"
}

snapshot() {
    local binary link name need have size biggest="" biggest_kb=0
    rm -rf "${SNAP}"
    mkdir -p "${SNAP}/bin" "${SNAP}/data" || return 1
    need=0
    while IFS= read -r name; do
        size="$(du -sk "${DEFENSECLAW_HOME}/${name}" 2>/dev/null | awk '{print $1}')"
        size="${size:-0}"
        need=$((need + size))
        if [[ "${size}" -gt "${biggest_kb}" ]]; then biggest="${name}" biggest_kb="${size}"; fi
    done < <(data_entries)
    have="$(df -Pk "${DEFENSECLAW_HOME}" | awk 'NR==2{print $4}')"
    if [[ -n "${need}" && -n "${have}" && "${have}" -lt $((need + 102400)) ]]; then
        need=$((need + 102400))
        err "Not enough free disk space next to ${DEFENSECLAW_HOME} for a rollback copy: it needs about $(((need + 1023) / 1024)) MB (a copy of the data plus 100 MB) and $((have / 1024)) MB is free"
        if [[ -n "${biggest}" ]]; then
            err "The largest item is ${DEFENSECLAW_HOME}/${biggest} ($(((biggest_kb + 1023) / 1024)) MB)"
        fi
        err "Free at least $(((need - have + 1023) / 1024)) MB on that filesystem (df -h ${DEFENSECLAW_HOME}), or move the largest item elsewhere, then rerun"
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
    # A hold is deleted by renaming it first, so a half-deleted one is never read.
    rm -rf "${slot}.done"
    local restart=false origin
    [[ "$(cat "${slot}/GATEWAY_WAS_RUNNING" 2>/dev/null)" == true ]] && restart=true
    if [[ -f "${slot}/ROLLED_BACK" ]]; then
        # The rollback itself had finished; only renaming its hold was left.
        # START_AFTER is its own decision; previous/ may be half deleted.
        warn "An earlier rollback was interrupted; finishing it"
        [[ "$(cat "${slot}/START_AFTER" 2>/dev/null)" == true ]] && restart=true
        rm -rf "${PREVIOUS}" && mv "${slot}" "${PREVIOUS}"
    elif [[ -d "${slot}" ]]; then
        warn "An earlier rollback was interrupted; restoring the install it started from"
        stop_gateway "${BIN_DIR}/defenseclaw-gateway" || true
        if [[ -f "${slot}/STASHED" ]]; then
            # The live install was fully set aside, so anything live now came
            # from previous/, unless the undo had already returned it (RETURNED).
            if [[ ! -f "${slot}/RETURNED" ]]; then
                return_live_to "${PREVIOUS}" && : > "${slot}/RETURNED"
            fi
            if [[ -f "${slot}/RETURNED" ]] && unstash "${slot}"; then
                # Put back an app the rollback had already moved aside, at the
                # path it came from (none may be there now to detect).
                origin="${APP_PATH:-$(cat "${slot}/APP_ORIGIN" 2>/dev/null || true)}"
                if [[ -d "${slot}/DefenseClawMac.app" && -n "${origin}" ]]; then
                    if [[ -e "${origin}" && ! -e "${PREVIOUS}/DefenseClawMac.app" ]]; then
                        mv "${origin}" "${PREVIOUS}/DefenseClawMac.app" || true
                    fi
                    [[ -e "${origin}" ]] || mv "${slot}/DefenseClawMac.app" "${origin}" || true
                    # The rest of this run updates or rolls back the app it restored.
                    [[ -d "${slot}/DefenseClawMac.app" || -n "${APP_PATH}" ]] || APP_PATH="${origin}"
                fi
                if [[ -d "${slot}/DefenseClawMac.app" ]]; then
                    # Both places are taken (the user reinstalled the app): keep this copy.
                    mkdir -p "${DEFENSECLAW_HOME}/backups" \
                        && mv "${slot}/DefenseClawMac.app" "${DEFENSECLAW_HOME}/backups/DefenseClawMac-$(cat "${slot}/VERSION" 2>/dev/null || echo unknown)-$(date +%Y%m%dT%H%M%S).app" \
                        && warn "Kept the app the rollback had set aside in ${DEFENSECLAW_HOME}/backups"
                fi
                [[ -d "${slot}/DefenseClawMac.app" ]] || drop_hold "${slot}"
            fi
        else
            # Setting it aside stopped part-way; the live binaries were only copied.
            unstash_tree "${slot}" && drop_hold "${slot}"
        fi
    fi
    [[ ! -e "${slot}" ]] || die "Could not recover an interrupted rollback; ${slot} holds the install it set aside (see ${LOG})"
    if [[ "${restart}" == true && -z "$(gateway_pid || true)" ]]; then
        start_gateway || warn_not_started
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
        local args=(migrate)
        [[ -n "${PREV_VERSION}" ]] && args+=(--from-version "${PREV_VERSION}")
        DEFENSECLAW_GATEWAY_BIN="${BIN_DIR}/defenseclaw-gateway" "${VENV}/bin/defenseclaw" "${args[@]}" || return 1
        # The previous version's agent discovery is absent or stale. Refresh
        # it (bounded --version probes, no telemetry) before the gateway
        # starts, so the gateway records each agent's version in the hook
        # contract lock and doctor can check compatibility. Best effort.
        info "Refreshing agent discovery"
        "${VENV}/bin/defenseclaw" agent discover --refresh --no-emit-otel >/dev/null 2>&1 || true
        # The new defenseclaw-acp has a new digest: re-pin it in configured
        # editor entries, which would otherwise fail closed. Best effort.
        if [[ -f "${SNAP}/bin/defenseclaw-acp" ]]; then
            "${VENV}/bin/defenseclaw" acp refresh --from-sha256 "$(sha256_of "${SNAP}/bin/defenseclaw-acp")" || true
        fi
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
    # Only the latest failed install is kept: with a large audit database
    # each copy holds gigabytes, and an earlier one is not used again.
    for failed in "${DEFENSECLAW_HOME}"/.failed-*; do
        if [[ -d "${failed}" && ! -L "${failed}" ]]; then rm -rf "${failed}"; fi
    done
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
    warn "The failed ${VERSION} install was kept in ${failed} ($(du -sh "${failed}" 2>/dev/null | awk '{print $1}')) for troubleshooting"
    info "Your previous install and its data are back; it is safe to remove the copy with: rm -rf '${failed}'"
}

restart_old() {
    if [[ "${WAS_RUNNING}" == true ]]; then
        start_gateway >/dev/null 2>&1 && return 0
        # Say plainly that the gateway that ran before is down now (GAP-1349).
        RESTORED_NOTE="Your previous install is back, but its gateway is not running (see above)."
        warn "The gateway that was running before did not start again, so agent hooks are not guarded until it runs (connectors in fail-closed mode block tool calls)"
        info "Start it with: defenseclaw-gateway start (log: ${DEFENSECLAW_HOME}/gateway.log). On a large audit database its first start can take several minutes"
    fi
}

# A 1.0.0 gateway cannot start on a WAL-mode audit.db whose 5-second startup
# check times out (a large store): SQLite drops and recreates audit.db-wal,
# and 1.0.0 refuses the new file (fixed in 1.0.1). In rollback-journal mode
# it starts, and switches the database back to WAL itself (GAP-1988).
AUDIT_JOURNAL_PY="import sqlite3,sys;c=sqlite3.connect(sys.argv[1],timeout=10);c.execute('pragma journal_mode').fetchone()[0]=='wal' and c.execute('pragma journal_mode=delete').fetchone();c.close()"

reset_audit_journal_mode() {
    local db="${DEFENSECLAW_HOME}/audit.db"
    [[ -f "${db}" && -x "${VENV}/bin/python" ]] || return 0
    "${VENV}/bin/python" -c "${AUDIT_JOURNAL_PY}" "${db}" >/dev/null 2>&1 || true
}

start_gateway() {
    local log="${DEFENSECLAW_HOME}/gateway.log" from=0 rc=0 deadline up=0 version delegate=""
    info "Starting the gateway"
    # A 0.8.x start gives up after 60 seconds and stops the gateway it
    # launched, so one restored on a large audit database is stopped before it
    # is ready or can log why it would stop. Its upgrade-controller mode only
    # launches the gateway; the loop below then waits for it.
    version="$("${BIN_DIR}/defenseclaw-gateway" --version 2>/dev/null | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)"
    if [[ -n "${version}" ]] && version_lt "${version}" 1.0.0; then delegate=1; fi
    if [[ -n "${version}" ]] && version_lt "${version}" 1.0.1; then reset_audit_journal_mode; fi
    [[ -f "${log}" ]] && from="$(wc -c < "${log}" | tr -d ' ')"
    if [[ -n "${delegate}" ]]; then
        PATH="${BIN_DIR}:${PATH}" DEFENSECLAW_UPGRADE_FRESH_PROCESS=1 "${BIN_DIR}/defenseclaw-gateway" start || rc=$?
    else
        PATH="${BIN_DIR}:${PATH}" "${BIN_DIR}/defenseclaw-gateway" start || rc=$?
    fi
    if [[ -n "${delegate}" && ${rc} -eq 0 ]]; then
        # Launched, not yet ready: it is up only once the loop below says so.
        rc=1
        info "Waiting up to 3 minutes for the gateway to finish starting (a large audit database takes a while)"
    else
        [[ ${rc} -eq 0 || ${rc} -eq 3 ]] && return "${rc}"
        explain_start_failure "${log}" "${from}"
        # A gateway still running after its start gave up may yet log why it
        # stops, so wait for it before falling back to generic advice.
        [[ -z "${START_EXPLAINED:-}" && -n "$(gateway_pid || true)" ]] || return "${rc}"
        info "The gateway is still starting (a large audit database takes a while); waiting up to 3 minutes"
    fi
    # Wall-clock: a status probe of a gateway that does not answer takes seconds.
    deadline=$((SECONDS + 180))
    while [[ -z "${START_EXPLAINED:-}" && ${SECONDS} -lt ${deadline} && -n "$(gateway_pid || true)" ]]; do
        sleep 3
        explain_start_failure "${log}" "${from}"
        if [[ -z "${START_EXPLAINED:-}" ]] && "${BIN_DIR}/defenseclaw-gateway" status >/dev/null 2>&1; then
            # Answering twice in a row, without a refusal in between: it is up.
            up=$((up + 1))
            [[ ${up} -lt 2 ]] || { ok "The gateway finished starting"; return 0; }
        else
            up=0
        fi
    done
    [[ -n "${START_EXPLAINED:-}" ]] || explain_start_failure "${log}" "${from}"
    if [[ -z "${START_EXPLAINED:-}" && -n "$(gateway_pid || true)" ]]; then
        warn "The gateway is still starting after 3 minutes; check it with: defenseclaw-gateway status"
        START_EXPLAINED=1
    fi
    return "${rc}"
}

# warn_not_started: the generic advice, unless the start already said why.
warn_not_started() {
    [[ -n "${START_EXPLAINED:-}" ]] || warn "The gateway did not start; run 'defenseclaw-gateway start' and check its log"
}

# explain_start_failure LOG OFFSET: say why the gateway stopped, from what it
# wrote to its log during this start. A restored older release, for example,
# refuses to start when an agent was updated after it recorded its hook lock,
# and its start command only reports a readiness timeout.
explain_start_failure() {
    local log=$1 from=$2 size lines reason conn before after
    [[ -f "${log}" ]] || return 0
    size="$(wc -c < "${log}" | tr -d ' ')"
    [[ "${size}" -ge "${from}" ]] || from=0
    lines="$(tail -c "+$((from + 1))" "${log}" 2>/dev/null | tail -n 400)"
    reason="$(printf '%s\n' "${lines}" | grep 'hook contract drift detected' | tail -n 1)"
    if [[ -n "${reason}" ]]; then
        conn="$(printf '%s' "${reason}" | sed -nE 's/.*connector ([A-Za-z0-9_-]+) hook contract drift detected.*/\1/p')"
        before="$(printf '%s' "${reason}" | sed -nE 's/.*previous version="([^"]*)".*/\1/p')"
        after="$(printf '%s' "${reason}" | sed -nE 's/.*current version="([^"]*)".*/\1/p')"
        warn "The gateway refused to start: ${conn:-a connector}'s agent changed (${before:-?} -> ${after:-?}) after this DefenseClaw recorded its hook contract lock"
        if [[ "${reason}" == *DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT=1* ]]; then
            # restart, not start: a gateway that refused its connector can
            # still be running, and start then only says it is (GAP-0012).
            info "To accept the new agent version and refresh the lock, restart it once with: DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT=1 defenseclaw-gateway restart"
        else
            info "Refresh the lock with: defenseclaw setup ${conn:-<connector>}"
        fi
        START_EXPLAINED=1
        return 0
    fi
    reason="$(printf '%s\n' "${lines}" | grep -E '^Error: |exited with error: ' | tail -n 1 | sed -E 's/^Error: //; s/.*exited with error: //' | cut -c1-300)"
    [[ -z "${reason}" ]] || { warn "The gateway stopped: ${reason}"; info "Its log: ${log}"; START_EXPLAINED=1; }
}

finish_swap() {
    local tmp
    # The new install is live: a run killed from here on must not restore the old one.
    rm -f "${SNAP}/COMPLETE"
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
    # Pre-1.0 installers kept retired binaries in the temp folder they ran
    # with. On macOS that is often /tmp although TMPDIR now names a per-user
    # folder, so look in both. -H follows a symlinked start path such as
    # macOS /tmp -> private/tmp; BSD find otherwise lists nothing under it.
    find -H "${TMPDIR:-/tmp}" /tmp -maxdepth 1 -user "$(id -u)" -name '.defenseclaw-install-custody-*' \
        -exec rm -rf {} + 2>/dev/null || true
    ok "Installed DefenseClaw ${VERSION}"
}

# A rollback parks the data written since the upgrade in previous/, and a 0.x
# install kept there holds the only copy of the audit history 1.0 does not
# carry over (GAP-1360). Keep either when a later upgrade reuses the slot.
keep_rolled_back_data() {
    [[ -d "${PREVIOUS}/data" ]] || return 0
    local kept version label what
    version="$(cat "${PREVIOUS}/VERSION" 2>/dev/null || echo unknown)"
    if [[ -f "${PREVIOUS}/ROLLED_BACK" ]]; then
        label=rolled-back what="the data from before the last rollback"
    elif is_version "${version}" && version_lt "${version}" 1.0.0 && [[ -f "${PREVIOUS}/data/audit.db" ]]; then
        label=audit-history what="the audit history DefenseClaw ${version} recorded"
    else
        return 0
    fi
    kept="${DEFENSECLAW_HOME}/backups/${label}-${version}-$(date +%Y%m%dT%H%M%S)"
    mkdir -p "${DEFENSECLAW_HOME}/backups" && mv "${PREVIOUS}/data" "${kept}" || return 1
    info "Kept ${what} in ${kept} ($(du -sh "${kept}" 2>/dev/null | awk '{print $1}'))"
    info "It is not used again; once you no longer need its audit history, remove it with: rm -rf '${kept}'"
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
    local slot="$1" binary link
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
    unstash_tree "${slot}" || return 1
    restore_external_config "${slot}"
}

# unstash_tree SLOT: move SLOT's data, venv and installer back into place.
# Alone it undoes a stash_live that failed part-way: that one only copied
# the binaries, so the live ones are still in place.
unstash_tree() {
    local slot="$1" name
    for name in "${slot}/data"/* "${slot}/data"/.[!.]* "${slot}/data"/..?*; do
        [[ -e "${name}" || -L "${name}" ]] && { mv "${name}" "${DEFENSECLAW_HOME}/" || return 1; }
    done
    if [[ -d "${slot}/venv" && ! -e "${VENV}" ]]; then mv "${slot}/venv" "${VENV}" || return 1; fi
    if [[ -d "${slot}/installer" && ! -e "${INSTALLER_DIR}" ]]; then mv "${slot}/installer" "${INSTALLER_DIR}" || return 1; fi
}

# return_live_to SLOT: move what unstash brought in from SLOT back into it.
# Only valid while the install unstash replaced is fully set aside elsewhere.
# drop_hold HOLD: delete a rollback hold. The rename makes it vanish at once:
# recovery must never find a half-deleted one and read its markers.
drop_hold() {
    mv "$1" "$1.done" && rm -rf "$1.done"
}

return_live_to() {
    # Never over or into anything already there: that would be the other install.
    local slot="$1" name
    mkdir -p "${slot}/data" || return 1
    while IFS= read -r name; do
        [[ ! -e "${slot}/data/${name}" && ! -L "${slot}/data/${name}" ]] || return 1
        mv "${DEFENSECLAW_HOME}/${name}" "${slot}/data/" || return 1
    done < <(data_entries)
    if [[ -d "${VENV}" ]]; then [[ ! -e "${slot}/venv" ]] && mv "${VENV}" "${slot}/venv" || return 1; fi
    if [[ -d "${INSTALLER_DIR}" ]]; then [[ ! -e "${slot}/installer" ]] && mv "${INSTALLER_DIR}" "${slot}/installer" || return 1; fi
}

swap_with_previous() {
    # Exchange the live install and previous/ by renaming, so a second
    # --rollback rolls forward again. Each half undoes itself on failure.
    # Returns 1 when the current install is back in place, 2 when it could
    # not be put back (the next run of the installer finishes the recovery).
    local hold="${DEFENSECLAW_HOME}/.rollback-hold"
    rm -rf "${hold}"
    # First, so recovery from any later point knows the version and gateway state.
    mkdir -p "${hold}" || return 1
    printf '%s\n' "${current}" > "${hold}/VERSION"
    printf '%s\n' "${was_running}" > "${hold}/GATEWAY_WAS_RUNNING"
    if ! stash_live "${hold}"; then
        if unstash_tree "${hold}"; then
            drop_hold "${hold}"
            err "Could not set the current install aside; nothing was changed"
            return 1
        fi
        err "Could not set the current install aside or put it back; re-run the installer to recover it"
        return 2
    fi
    : > "${hold}/STASHED"
    if ! unstash "${PREVIOUS}"; then
        # unstash only copies previous/bin, so returning the rest restores previous/.
        # RETURNED tells an interrupted run's recovery that previous/ is whole again.
        if return_live_to "${PREVIOUS}" && : > "${hold}/RETURNED" && unstash "${hold}"; then
            drop_hold "${hold}"
            err "Could not restore the previous install; the current one is back in place"
            return 1
        fi
        err "Could not restore the previous install or put the current one back; re-run the installer to recover it"
        return 2
    fi
    if [[ -n "${APP_PATH}" && -d "${PREVIOUS}/DefenseClawMac.app" ]]; then
        printf '%s\n' "${APP_PATH}" > "${hold}/APP_ORIGIN"
        if mv "${APP_PATH}" "${hold}/DefenseClawMac.app"; then
            mv "${PREVIOUS}/DefenseClawMac.app" "${APP_PATH}" \
                || { mv "${hold}/DefenseClawMac.app" "${APP_PATH}"; warn "Could not swap the macOS app back; it stays at the newer version"; }
        else
            warn "Could not swap the macOS app back; it stays at the newer version"
        fi
    fi
    printf '%s\n' "${restart:-${was_running}}" > "${hold}/START_AFTER"
    date +%Y%m%dT%H%M%S > "${hold}/ROLLED_BACK"
    rm -rf "${PREVIOUS}"
    mv "${hold}" "${PREVIOUS}"
}

# A 0.x release does not know the agent-side registrations 1.0 writes (hook
# entries with --event, the OpenCode plugin, the Hermes rendering), so its
# gateway adds its own next to them and runs every hook twice (GAP-1521).
# Remove them with this install's own teardown before the swap; the restored
# gateway registers its own when it starts. active_connector.json is put back,
# so the data kept for a roll forward still names the same connectors. So are
# the connector OTLP tokens teardown revokes: a roll forward that minted new
# ones left an agent exporter still holding the old token rejected, and doctor
# warned about an unattributed OTLP credential (GAP-1925).
remove_connector_registrations_for_legacy() {
    local state="${DEFENSECLAW_HOME}/active_connector.json" gateway="${BIN_DIR}/defenseclaw-gateway" saved name names
    local hooks="${DEFENSECLAW_HOME}/hooks" tokens token
    [[ -f "${state}" && -x "${VENV}/bin/python" && -x "${gateway}" ]] || return 0
    names="$("${VENV}/bin/python" -I - "${state}" <<'PY' 2>/dev/null
import json, re, sys
state = json.load(open(sys.argv[1], encoding="utf-8"))
names = state.get("names") or [state.get("name")]
print(" ".join(n for n in names if isinstance(n, str) and re.fullmatch(r"[a-z0-9_-]+", n) and n != "openclaw"))
PY
)" || return 0
    [[ -n "${names}" ]] || return 0
    saved="$(mktemp)" || return 0
    cp -p "${state}" "${saved}" || { rm -f "${saved}"; return 0; }
    tokens="$(mktemp -d)" || { rm -f "${saved}"; return 0; }
    for token in "${hooks}"/.otlp-*.token; do
        [[ -f "${token}" && ! -L "${token}" ]] && cp -p "${token}" "${tokens}/"
    done
    info "Removing the connector registrations of DefenseClaw ${current}; ${back_to} writes its own when its gateway starts"
    for name in ${names}; do
        "${gateway}" connector teardown --connector "${name}" >>"${LOG}" 2>&1 \
            || warn "Could not remove the ${name} registrations of DefenseClaw ${current}; ${back_to} may run its ${name} hooks twice until you run: defenseclaw setup ${name}"
    done
    cp -p "${saved}" "${state}" || warn "Could not restore ${state}; run 'defenseclaw init' if a roll forward leaves a connector unguarded"
    for token in "${tokens}"/.otlp-*.token; do
        [[ -f "${token}" ]] || continue
        { mkdir -p -m 700 "${hooks}" && cp -p "${token}" "${hooks}/"; } \
            || warn "Could not keep $(basename "${token}"); after a roll forward run 'defenseclaw setup' for that connector"
    done
    rm -rf "${saved}" "${tokens}"
}

# The gateway writes the OpenClaw plugin when it starts; OpenClaw loads it only
# when its own gateway restarts.
restart_openclaw() {
    openclaw_connector_active && has openclaw || return 0
    local out
    if ! out="$(openclaw gateway restart 2>&1)"; then
        warn "Restart the OpenClaw gateway to load the updated plugin: openclaw gateway restart"
        return 0
    fi
    # OpenClaw exits 0 but restarts nothing when no gateway service is
    # installed ("Gateway service disabled"), for example a foreground
    # `openclaw gateway`. Don't claim a restart (GAP-2207, as GAP-1408 in setup).
    if grep -Eqi 'openclaw gateway install|service (is )?(disabled|not (loaded|enabled|installed|registered|found))' <<<"${out}"; then
        warn "No OpenClaw gateway service to restart. Restart the OpenClaw gateway to load the updated plugin: if it runs in a terminal, restart 'openclaw gateway' there"
        return 0
    fi
    ok "OpenClaw gateway restarted"
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
    choice=$(read_tty_line) || choice=""
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
    if [[ "${RUN_QUICKSTART}" == true ]]; then
        if [[ -z "${CONNECTOR}" || "${CONNECTOR}" == none ]]; then
            warn "Quickstart needs a connector; run 'defenseclaw init' when ready"
        else
            local args=(quickstart --non-interactive --yes --connector "${CONNECTOR}")
            [[ -n "${QUICKSTART_MODE}" ]] && args+=(--mode "${QUICKSTART_MODE}")
            local rc=0
            if [[ "${OPENCLAW_MISSING}" == true ]]; then
                # GAP-1798: quickstart cannot set up an agent that is not
                # installed; the summary names it as the step after OpenClaw.
                OPENCLAW_NEXT="defenseclaw ${args[*]}"
            else
                PATH="${BIN_DIR}:${PATH}" "${VENV}/bin/defenseclaw" "${args[@]}" || rc=$?
            fi
            if [[ ${rc} -ne 0 ]]; then
                # The install stays; the summary names the failure and the re-run.
                QUICKSTART_RC=${rc}
                QUICKSTART_RERUN="defenseclaw ${args[*]}"
            fi
        fi
    elif [[ -n "${CONNECTOR}" && "${CONNECTOR}" != none ]]; then
        printf "\n  Next: ${CYAN}defenseclaw init --connector %s${NC}\n" "${CONNECTOR}"
    else
        printf "\n  Next: ${CYAN}defenseclaw init${NC}\n"
    fi
}

ensure_openclaw() {
    local found
    # GAP-1523: a system Node (/usr, /opt/node22) has a root-owned global
    # prefix; a standard user installs into ~/.local, whose bin is BIN_DIR.
    # GAP-1798: every hint names the command this run would use.
    local cmd=(npm install -g)
    if has npm && ! npm_global_prefix_writable; then cmd+=(--prefix "${HOME}/.local"); fi
    cmd+=("openclaw@${OPENCLAW_VERSION}")
    if has openclaw; then
        found="$(openclaw --version 2>/dev/null | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)"
        if [[ -n "${found}" ]] && ! version_lt "${found}" "${OPENCLAW_VERSION}"; then
            ok "OpenClaw ${found} found"; return
        fi
        ask_yes_no "Update OpenClaw ${found:-?} to ${OPENCLAW_VERSION}?" || { warn "Keeping OpenClaw ${found:-?}"; return; }
    else
        ask_yes_no "Install OpenClaw ${OPENCLAW_VERSION}?" || { warn "Skipping OpenClaw; install it later with: ${cmd[*]}"; OPENCLAW_MISSING=true; return; }
    fi
    has npm || { warn "npm is not installed; install Node.js with npm, then run: ${cmd[*]}"; OPENCLAW_MISSING=true; return; }
    info "Installing OpenClaw ${OPENCLAW_VERSION} with npm (this can take a minute)"
    if "${cmd[@]}" --no-fund --no-audit --no-update-notifier --loglevel=error; then
        OPENCLAW_INSTALLED=true
    else
        warn "Could not install OpenClaw; run: ${cmd[*]}"
        PATH="${BIN_DIR}:${PATH}" has openclaw || OPENCLAW_MISSING=true
    fi
}

npm_global_prefix_writable() {
    local prefix dir
    prefix="$(npm prefix -g 2>/dev/null)" || return 0
    [[ -n "${prefix}" ]] || return 0
    for dir in "${prefix}/lib/node_modules" "${prefix}/bin"; do
        [[ -e "${dir}" ]] || dir="${prefix}"
        [[ -w "${dir}" ]] || return 1
    done
    return 0
}

ensure_path_hint() {
    case ":${CALLER_PATH}:" in *":${BIN_DIR}:"*) return ;; esac
    local rc="${HOME}/.profile"
    case "${SHELL:-}" in */zsh) rc="${HOME}/.zshrc" ;; */bash) rc="${HOME}/.bashrc" ;; esac
    printf "\n  Add DefenseClaw to your PATH (then open a new shell):\n"
    printf "    ${CYAN}echo 'export PATH=\"%s:\$PATH\"' >> %s${NC}\n" "${BIN_DIR}" "${rc}"
}

main "$@"
# DefenseClaw POSIX installer complete v2
