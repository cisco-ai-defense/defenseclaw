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
# Permanent interface (never remove or change these): --yes, --version X.Y.Z,
# --local DIR, --rollback. An unknown option stops the installer with exit 2
# before it changes anything, so a typo never installs something other than
# what was asked (GAP-0361). Only the copy that defenseclaw upgrade or
# rollback runs (from a defenseclaw-upgrade-* or defenseclaw-rollback-*
# folder) ignores one with a warning, so an older release's installer
# accepts the flags of a newer client.
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
# A relative DEFENSECLAW_HOME or DEFENSECLAW_CONFIG names a folder from the
# caller's directory, and a quoted "~/..." one (the shell did not expand it)
# names the caller's home. Record the absolute path once, here, so the locks
# this installer takes, the folder hook-data-dir names, the removal notice
# check and the gateway it starts from its own runtime directory all see the
# same one.
for dc_path_var in DEFENSECLAW_HOME DEFENSECLAW_CONFIG; do
    dc_path_value="${!dc_path_var:-}"
    case "${dc_path_value}" in
        ""|/*) ;;
        "~") export "${dc_path_var}=${HOME}" ;;
        "~/"*) export "${dc_path_var}=${HOME}/${dc_path_value#"~/"}" ;;
        *) export "${dc_path_var}=$(pwd -P)/${dc_path_value}" ;;
    esac
done
readonly DEFENSECLAW_HOME="${DEFENSECLAW_HOME:-${HOME}/.defenseclaw}"
export DEFENSECLAW_HOME
# until 1.1: a 0.8.x or 1.0.x OmniGent setup may have used a relative
# config override. Bind it to the caller's directory before the installer
# starts a gateway from its own runtime directory. Nothing is changed in the
# caller's shell; the child gateway and the cleanup reporter see one path.
for retired_config_var in OMNIGENT_CONFIG_HOME OMNIGENT_CONFIG; do
    retired_config_value="${!retired_config_var:-}"
    case "${retired_config_value}" in
        ""|/*|"~"|"~/"*) ;;
        *) export "${retired_config_var}=$(pwd -P)/${retired_config_value}" ;;
    esac
done
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
RUN_BY_UPGRADE=""
case "$(basename "${SELF_TMP}")" in
    defenseclaw-upgrade-*|defenseclaw-rollback-*) RUN_BY_UPGRADE=1 ;;
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
# defenseclaw-sensor-helper is kept on Linux only: it is what `sudo
# defenseclaw-gateway sandbox kernel-feed install` copies into a root service.
readonly MANAGED_BINARIES="defenseclaw-gateway defenseclaw-hook-post defenseclaw-acp defenseclaw-sensor-helper"
# The sandbox kernel feed's unit and its root copy of the helper.
readonly SANDBOX_FEED_UNIT="/etc/systemd/system/defenseclaw-sandbox-feed.service"
readonly SANDBOX_FEED_HELPER="/usr/local/libexec/defenseclaw/defenseclaw-sensor-helper"
# The oldest release that keeps the sandbox setup (the openshell: settings and
# the sandboxes, snapshots and shadows folders) as this one does. A rollback
# carries that setup between two releases from here on (GAP-0483); a release
# that changes how it is kept raises this.
readonly SANDBOX_STATE_SINCE="1.0.1"
# Symlinks in BIN_DIR that point into the venv.
readonly MANAGED_LINKS="defenseclaw skill-scanner mcp-scanner"
# The first line of the defenseclaw script the swap puts in place of the link.
readonly BUSY_SHIM_MARK="# Written by the DefenseClaw installer while it replaces the install"
# Data-dir entries that are install machinery, not user data.
readonly NOT_DATA=".venv .uv previous previous.new .repair .rollback-hold .rollback-hold.done .staging .failed-* installer logs .install.lock backups"
readonly CONNECTOR_CHOICES="codex claudecode zeptoclaw openclaw hermes cursor devin copilot antigravity opencode amp kiro none"

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
# A wrong option or value: exit 2, before anything changed.
usage_error() { err "$*; nothing was changed"; printf "  Run with --help for the options.\n" >&2; exit 2; }
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

# stage_binary NAME: on macOS, sign the verified archive binary in staging ad
# hoc with its stable identifier and check the new signature. Signing changes
# the file, so checksums.txt describes the archive, not the file that runs:
# record the digest of the binary as it will run (GAP-0641).
stage_binary() {
    local file="${STAGING}/bin/$1" archive_sha="" sha=""
    if [[ "${OS}" == darwin ]]; then
        archive_sha="$(sha256_of "${file}")"
        /usr/bin/codesign -f -s - -i "com.cisco.defenseclaw.${1#defenseclaw-}" "${file}" >/dev/null 2>&1 \
            && /usr/bin/codesign --verify --strict "${file}" >/dev/null 2>&1 \
            || die "Could not sign $1 for this Mac"
    fi
    sha="$(sha256_of "${file}")"
    printf '%s  %s\n' "${sha}" "$1" >> "${STAGING}/binaries.sha256" || die "Could not record the digest of $1"
    [[ -z "${archive_sha}" ]] || info "Signed $1 for this Mac: sha256 ${sha} (archive ${archive_sha})"
}

# record_binaries: keep the digests of the binaries that now run in the
# installer folder, which upgrades snapshot and rollbacks restore, and check
# that every installed binary is the one recorded.
record_binaries() {
    local sha name
    cp "${STAGING}/binaries.sha256" "${INSTALLER_DIR}/.binaries.sha256.new" \
        && chmod 600 "${INSTALLER_DIR}/.binaries.sha256.new" \
        && mv -f "${INSTALLER_DIR}/.binaries.sha256.new" "${INSTALLER_DIR}/binaries.sha256" || return 1
    while read -r sha name; do
        [[ "$(sha256_of "${BIN_DIR}/${name}")" == "${sha}" ]] || {
            warn "The installed ${name} is not the binary this install staged"
            return 1
        }
    done < "${INSTALLER_DIR}/binaries.sha256"
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
  --help, -h               Show this help

Exit codes:
  0  Installed        1  Not installed (a previous install is restored)
  2  Not installed: an unknown option or value (nothing was changed)
  3  Installed; a connector needs attention before it is guarded again
  4  Installed; the first-run quickstart failed (re-run it as shown)

Environment:
  DEFENSECLAW_HOME         Data directory (default: ~/.defenseclaw)
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --version=*|--local=*|--connector=*|--quickstart-mode=*)
            # --name=value is the same option as --name value (GAP-0361).
            opt_name="${1%%=*}" opt_value="${1#*=}"
            shift
            set -- "${opt_name}" "${opt_value}" "$@" ;;
    esac
    case "$1" in
        --yes|-y) YES=true ;;
        --version)
            # An empty --version= picked the latest release (GAP-0012).
            [[ $# -ge 2 && -n "$2" ]] || usage_error "--version needs a value such as 1.2.3"
            is_version "${2#v}" || usage_error "--version must look like 1.2.3, got '$2'"
            TARGET_VERSION="${2#v}"; shift ;;
        --local)
            # An empty --local= ran from the current folder (GAP-1336).
            [[ $# -ge 2 && -n "$2" ]] || usage_error "--local needs a directory"
            LOCAL_DIR="$(cd "$2" 2>/dev/null && pwd)" || usage_error "--local: directory not found: $2"
            shift ;;
        --rollback) ROLLBACK=true ;;
        --connector)
            [[ $# -ge 2 ]] || usage_error "--connector needs a value (${CONNECTOR_CHOICES// /, })"
            CONNECTOR="$2"; shift
            is_valid_connector "${CONNECTOR}" || usage_error "Invalid --connector '${CONNECTOR}'. Choices: ${CONNECTOR_CHOICES// /, }"
            PASSTHROUGH+=(--connector "${CONNECTOR}") ;;
        --no-openclaw) NO_OPENCLAW=true; PASSTHROUGH+=(--no-openclaw) ;;
        --quickstart) RUN_QUICKSTART=true; PASSTHROUGH+=(--quickstart) ;;
        --quickstart-mode)
            [[ $# -ge 2 ]] || usage_error "--quickstart-mode needs observe or action"
            QUICKSTART_MODE="$2"; shift
            case "${QUICKSTART_MODE}" in observe|action) ;; *) usage_error "Invalid --quickstart-mode '${QUICKSTART_MODE}': use observe or action" ;; esac
            RUN_QUICKSTART=true; PASSTHROUGH+=(--quickstart-mode "${QUICKSTART_MODE}") ;;
        --sandbox) die "--sandbox was removed with the legacy openshell-sandbox installer. Install without it; to run agents in NVIDIA OpenShell 0.1 sandboxes, run 'defenseclaw sandbox setup' afterwards; to remove an old standalone sandbox first, run 'defenseclaw sandbox legacy-cleanup --dry-run'." ;;
        --help|-h) usage; exit 0 ;;
        *)
            [[ -n "${RUN_BY_UPGRADE}" ]] || usage_error "Unknown option: $1"
            warn "Ignoring unknown option: $1" ;;
    esac
    shift
done
if [[ "${NO_OPENCLAW}" == true ]]; then
    [[ "${CONNECTOR}" != openclaw ]] || die "--no-openclaw cannot be combined with --connector openclaw"
    CONNECTOR="${CONNECTOR:-none}"
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
# The command that runs this install again, for the recovery hints.
if [[ -n "${LOCAL_DIR}" && -f "${LOCAL_DIR}/install.sh" ]]; then
    INSTALL_AGAIN="bash ${LOCAL_DIR}/install.sh --local ${LOCAL_DIR}"
else
    INSTALL_AGAIN="curl -LsSf ${RELEASE_BASE}/releases/download/${VERSION}/install.sh | bash"
fi

[[ "${ROLLBACK}" == true ]] || require_free_space
require_writable_dirs

# ── Lock and log ─────────────────────────────────────────────────────────────

LOCK_HINT="check the free space (df -h ${DEFENSECLAW_HOME%/*}) and that $(id -un) can write there; nothing was changed"
mkdir -p "${DEFENSECLAW_HOME}" "${DEFENSECLAW_HOME}/logs" 2>/dev/null \
    || die "Could not create ${DEFENSECLAW_HOME}/logs: ${LOCK_HINT}"
chmod 700 "${DEFENSECLAW_HOME}" 2>/dev/null || true
# The owner record of every lock this installer takes: its pid, the second
# it took the lock (started, which tells this run's lock from another's) and
# its process identity (proc-start, process_identity). Every hook and
# `defenseclaw doctor` treat a lock as no lock only once its installer is
# gone: its pid names no process, or another process than proc-start names
# (a reused pid; hookexec installLockStale, the one rule). No clock decides
# it: a live install keeps its locks for as long as it runs, however long it
# waits at a prompt or the clock is stepped, and the next run takes over a
# lock whose installer is gone.
LOCK_STARTED="$(date +%s)"
process_identity() {
    # process_identity PID: the identity of process PID as the system keeps
    # it from its creation (hookexec procidentity), which no clock step
    # moves: on Linux "<boot_id> <starttime>" (field 22 of /proc/PID/stat),
    # on macOS its creation second as `LC_ALL=C TZ=UTC ps -o lstart=` prints
    # it, one space apart. Fails when the system does not say.
    local boot stat fields
    if [[ -e /proc/self/stat ]]; then
        boot="$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)" || return 1
        stat="$(cat "/proc/$1/stat" 2>/dev/null)" || return 1
        [[ "${stat}" == *")"* ]] || return 1
        read -r -a fields <<< "${stat##*)}"
        (( ${#fields[@]} >= 20 )) || return 1
        [[ "${fields[19]}" =~ ^[0-9]+$ && "${boot}" =~ ^[0-9a-f-]+$ ]] || return 1
        echo "${boot} ${fields[19]}"
        return 0
    fi
    [[ "$(uname -s 2>/dev/null)" == Darwin && -x /bin/ps ]] || return 1
    read -r -a fields <<< "$(LC_ALL=C TZ=UTC /bin/ps -o lstart= -p "$1" 2>/dev/null)"
    (( ${#fields[@]} == 5 )) || return 1
    echo "${fields[*]}"
}
LOCK_IDENTITY="$(process_identity $$ || true)"
write_lock_owner() {
    # The identity first and the pid last: a lock taken over in place never
    # names this installer's pid beside the identity of the one before it.
    {
        if [[ -n "${LOCK_IDENTITY}" ]]; then
            echo "${LOCK_IDENTITY}" > "$1/proc-start"
        else
            rm -f -- "$1/proc-start"
        fi && echo "${LOCK_STARTED}" > "$1/started" && echo $$ > "$1/pid"
    } 2>/dev/null
}
lock_is_ours() {
    # lock_is_ours LOCK: LOCK still records this installer as its owner (its
    # pid and start time); a lock another run took over is not ours.
    [[ "$(cat "$1/pid" 2>/dev/null || true)" == "$$" \
        && "$(cat "$1/started" 2>/dev/null || true)" == "${LOCK_STARTED}" ]]
}
assert_locks_ours() {
    # Every lock this install holds is still its own before it stops the
    # gateway or swaps a file; one another run took over stops this one.
    local lock
    for lock in "${LOCK_DIR}" ${DATA_LOCK_DIRS[@]+"${DATA_LOCK_DIRS[@]}"}; do
        lock_is_ours "${lock}" \
            || die "The install lock ${lock} is no longer this installer's (another run took it over); nothing more was changed"
    done
}
release_locks() {
    # The EXIT trap: give back every lock that is still this installer's; a
    # lock another run took over stays with that run.
    local lock
    for lock in "${LOCK_DIR}" ${DATA_LOCK_DIRS[@]+"${DATA_LOCK_DIRS[@]}"}; do
        if lock_is_ours "${lock}"; then
            rm -rf "${lock:?}"
        fi
    done
    # A data folder this install made only to hold its lock goes when empty.
    for lock in ${MADE_DATA_DIRS[@]+"${MADE_DATA_DIRS[@]}"}; do
        rmdir -- "${lock:?}" 2>/dev/null || true
    done
}
process_started_epoch() {
    # process_started_epoch PID: the second process PID started, from the
    # system's record of it (Linux: boot time + field 22 of /proc/PID/stat;
    # macOS: ps -o lstart). Fails when the system does not say.
    local stat fields btime hz lstart
    if [[ -e /proc/self/stat ]]; then
        stat="$(cat "/proc/$1/stat" 2>/dev/null)" || return 1
        [[ "${stat}" == *")"* ]] || return 1
        read -r -a fields <<< "${stat##*)}"
        [[ "${fields[19]:-}" =~ ^[0-9]+$ ]] || return 1
        btime="$(awk '$1 == "btime" { print $2; exit }' /proc/stat 2>/dev/null)"
        hz="$(getconf CLK_TCK 2>/dev/null)"
        [[ "${btime}" =~ ^[0-9]+$ && "${hz}" =~ ^[1-9][0-9]*$ ]] || return 1
        echo $(( btime + fields[19] / hz ))
        return 0
    fi
    [[ "$(uname -s 2>/dev/null)" == Darwin && -x /bin/ps ]] || return 1
    read -r -a fields <<< "$(LC_ALL=C TZ=UTC /bin/ps -o lstart= -p "$1" 2>/dev/null)"
    (( ${#fields[@]} == 5 )) || return 1
    lstart="${fields[*]}"
    LC_ALL=C TZ=UTC date -j -f "%a %b %d %T %Y" "${lstart}" +%s 2>/dev/null
}
lock_created_epoch() {
    # lock_created_epoch LOCK: the second the lock folder was made (its birth
    # time), else the second its pid file was written, which every release
    # writes right after it makes the folder. Fails when neither can be read.
    local t
    if [[ "$(uname -s 2>/dev/null)" == Darwin ]]; then
        t="$(stat -f %B -- "$1" 2>/dev/null)" && [[ "${t}" =~ ^[1-9][0-9]*$ ]] && { echo "${t}"; return 0; }
        t="$(stat -f %m -- "$1/pid" 2>/dev/null)" && [[ "${t}" =~ ^[0-9]+$ ]] && { echo "${t}"; return 0; }
        return 1
    fi
    t="$(stat -c %W -- "$1" 2>/dev/null)" && [[ "${t}" =~ ^[1-9][0-9]*$ ]] && { echo "${t}"; return 0; }
    t="$(stat -c %Y -- "$1/pid" 2>/dev/null)" && [[ "${t}" =~ ^[0-9]+$ ]] && { echo "${t}"; return 0; }
    return 1
}
lock_owner_live() {
    # lock_owner_live LOCK HOLDER: the installer HOLDER that wrote LOCK/pid
    # still runs: its pid names a process that is not this one and, when
    # LOCK/proc-start is there, is the process that record names. A lock
    # without that record (1.0.2, 1.0.3) is kept while its pid names a
    # process that started before the lock was made: one that started
    # later got a reused pid, and the lock is stale (GAP-1465, lead decision
    # 2026-10-26 13:58; 2 s for the whole-second readings). A record, an
    # identity or a time that cannot be read keeps the lock.
    local recorded current started created
    [[ -n "$2" && "$2" != "$$" ]] && pid_running "$2" || return 1
    if [[ ! -e "$1/proc-start" && ! -L "$1/proc-start" ]]; then
        started="$(process_started_epoch "$2")" || return 0
        created="$(lock_created_epoch "$1")" || return 0
        (( started <= created + 2 ))
        return
    fi
    recorded="$(lock_record "$1/proc-start")" || return 0
    current="$(process_identity "$2")" || return 0
    [[ "${recorded}" == "${current}" ]]
}
pid_running() {
    # pid_running PID: PID names a process that has not ended. A zombie (an
    # exited process its parent has not reaped) keeps its pid and its start,
    # and kill -0 still reaches it, but it runs nothing: it is gone. When the
    # system does not say, the process runs.
    local stat fields
    kill -0 "$1" 2>/dev/null || return 1
    if [[ -e /proc/self/stat ]]; then
        stat="$(cat "/proc/$1/stat" 2>/dev/null)" || return 0
        [[ "${stat}" == *")"* ]] || return 0
        read -r -a fields <<< "${stat##*)}"
        [[ "${fields[0]:-}" != [ZXx] ]]
        return
    fi
    [[ -x /bin/ps ]] || return 0
    stat="$(LC_ALL=C /bin/ps -o stat= -p "$1" 2>/dev/null)" || return 0
    stat="${stat#"${stat%%[![:space:]]*}"}"
    [[ "${stat}" != Z* ]]
}
lock_claim_live() {
    # lock_claim_live FILE: the run that left the takeover claim FILE in a
    # lock (take_lock, or `defenseclaw doctor --fix`: its pid, then its
    # process identity) still runs. A claim that names no other pid is none;
    # one whose identity cannot be read holds.
    local cpid="" cid="" current
    [[ -f "$1" && ! -L "$1" ]] || return 1
    { IFS= read -r cpid || true; IFS= read -r cid || true; } < "$1" 2>/dev/null || return 1
    cpid="${cpid//[[:space:]]/}"
    [[ "${cpid}" =~ ^[1-9][0-9]{0,9}$ && "${cpid}" != "$$" ]] || return 1
    pid_running "${cpid}" || return 1
    cid="${cid%$'\r'}"
    [[ -n "${cid}" ]] || return 0
    current="$(process_identity "${cpid}")" || return 0
    [[ "${cid}" == "${current}" ]]
}
# How often take_lock looks again, a second apart, while another run's claim
# is in the lock.
LOCK_TAKE_TRIES=10
take_lock() {
    # take_lock LOCK HINT [WHAT]: make LOCK this installer's, or stop. A
    # lock whose installer is gone is taken over in place: the folder stays
    # at its path, so no hook sees a running install without it, and only
    # its owner files change. Takeovers are serialized: a taker first puts
    # its claim in the folder (claim-<pid>-<started>: its pid and process
    # identity, put in place by one rename) and goes on only while no other
    # run's claim there is live; `defenseclaw doctor --fix` claims the same
    # way before it removes a stale lock. A claim made before another
    # taker's check is seen by it, so two takers never both go on; one that
    # sees a live claim takes its own back and looks again. An installer
    # removes no lock it did not take.
    local lock="$1" hint="$2" what="${3:-}" claim="claim-$$-${LOCK_STARTED}" holder entry busy try
    for (( try = 1; try <= LOCK_TAKE_TRIES; try++ )); do
        if ! mkdir "${lock}" 2>/dev/null; then
            [[ -d "${lock}" && ! -L "${lock}" ]] || die "Could not create the install lock ${lock}: ${hint}"
            holder="$(cat "${lock}/pid" 2>/dev/null || true)"
            if lock_owner_live "${lock}" "${holder}"; then
                die "Another DefenseClaw install is running (pid ${holder})${what}"
            fi
        fi
        if ! { printf '%s\n%s\n' "$$" "${LOCK_IDENTITY}" > "${lock}/.${claim}" \
                && mv -f -- "${lock}/.${claim}" "${lock}/${claim}"; } 2>/dev/null; then
            rm -f -- "${lock}/.${claim}" 2>/dev/null || true
            # The lock was given back meanwhile: make it again.
            [[ -d "${lock}" ]] && die "Could not create the install lock ${lock}: ${hint}"
            continue
        fi
        busy=""
        for entry in "${lock}"/claim-*; do
            if [[ "${entry}" != "${lock}/${claim}" ]] && lock_claim_live "${entry}"; then
                busy=1
                break
            fi
        done
        if [[ -z "${busy}" ]]; then
            holder="$(cat "${lock}/pid" 2>/dev/null || true)"
            if lock_owner_live "${lock}" "${holder}"; then
                rm -f -- "${lock}/${claim}"
                die "Another DefenseClaw install is running (pid ${holder})${what}"
            fi
            write_lock_owner "${lock}" && return 0
            rm -rf "${lock:?}"
            die "Could not write the install lock ${lock}/pid: ${hint}"
        fi
        rm -f -- "${lock}/${claim}"
        (( try < LOCK_TAKE_TRIES )) && sleep 1
    done
    die "Another DefenseClaw install or doctor run is taking over the install lock ${lock}; run the installer again once it is done"
}
lock_record() {
    # lock_record FILE: the trimmed text of a small owner record (proc-start).
    local text=""
    [[ -f "$1" && ! -L "$1" ]] || return 1
    (( $(wc -c < "$1") <= 128 )) || return 1
    read -r text < "$1" || [[ -n "${text}" ]] || return 1
    [[ -n "${text}" ]] || return 1
    echo "${text}"
}
take_lock "${LOCK_DIR}" "${LOCK_HINT}"
LOG="${DEFENSECLAW_HOME}/logs/install-$(date +%Y%m%dT%H%M%S).log"
# tee ignores Ctrl+C: it went down with the installer's process group, and the
# cancel message then died on a broken pipe (exit 141, GAP-1901).
exec > >(trap '' INT TERM; exec tee -a "${LOG}") 2>&1
# A run that stops after it staged the release and before the swap (a
# refusal, a failed check, a cancel) leaves nothing it staged or added for uv
# (drop_unswapped_stage, GAP-1120).
# The hooks of a data_dir set apart from DEFENSECLAW_HOME live in that folder
# and look for this lock there: the shell hooks, the OpenCode and Amp plugins
# and hook-outage-mode, which alone lets a per-user outage through. This
# install holds that folder too, until it exits, so a gateway it stops is
# never an outage those hooks let tool calls through in. The folder is the
# one the gateway renders the hooks into, as the runtime itself reads the
# config (defenseclaw-gateway hook-data-dir): a line reader here missed a
# quoted key and every other YAML form of data_dir. It is asked twice: of the
# installed gateway now, before anything may stop it, and of the staged one
# before the swap (an older installed release has no hook-data-dir; its hooks
# do not open an unset outage). DATA_LOCK_DIRS are the locks
# hold_hook_data_dir took; the EXIT trap gives back those still its own.
DATA_LOCK_DIRS=()
MADE_DATA_DIRS=()
trap '[[ -z "${UNSWAPPED_STAGE:-}" ]] || drop_unswapped_stage; release_locks; rm -rf ${SELF_TMP:+"${SELF_TMP}"}' EXIT
trap 'printf "\n"; err "Cancelled."; exit 130' INT TERM

hook_data_dir_of() {
    # hook_data_dir_of BINARY: the folders BINARY's hook-data-dir names, one
    # per line, "" when it names no absolute folder. Returns 2 when BINARY is missing or
    # has no hook-data-dir (an older release), 1 when it cannot read the
    # config (it says why on stderr).
    local binary="$1" help=""
    [[ -x "${binary}" ]] || return 2
    help="$("${binary}" hook-data-dir --help 2>/dev/null)" || return 2
    [[ "${help}" == *"hook-data-dir"* ]] || return 2
    "${binary}" hook-data-dir || return 1
}

hold_hook_data_dir() {
    # hold_hook_data_dir BINARY [required]: hold every data folder BINARY
    # names from the config as well (one per line). A BINARY that cannot read
    # the config stops the install before anything changes; so does one
    # without hook-data-dir when required (the staged gateway of this
    # release always has it).
    local binary="$1" required="${2:-}" answer="" rc=0 data
    answer="$(hook_data_dir_of "${binary}")" || rc=$?
    case ${rc} in
        0) ;;
        2)
            [[ -z "${required}" ]] && return 0
            die "${binary} cannot name the data folder of your configuration; nothing was changed" ;;
        *) die "Could not read the data folder of your configuration (${DEFENSECLAW_CONFIG:-${DEFENSECLAW_HOME}/config.yaml}) with ${binary}, so its hooks could fail open while the gateway is down; fix the file, then run this installer again; nothing was changed" ;;
    esac
    while IFS= read -r data; do
        hold_data_lock "${data}"
    done <<< "${answer}"
}

hold_data_lock() {
    # hold_data_lock DATA: take DATA/.install.lock unless DATA is no folder,
    # is this install's home or is already held, by file identity (device
    # and inode: a link, a bind mount or another spelling is that folder).
    # Another missing DATA holds no hooks yet, but a missing .defenseclaw in
    # a folder that is there (the account's own beside a custom home, which
    # every per-user hook checks) is made first, so its lock is there to
    # find while the gateway is down; the EXIT trap removes it again when it
    # is still empty.
    local data="$1" lock held
    [[ -n "${data}" ]] || return 0
    if [[ "${data##*/}" == .defenseclaw && ! -e "${data}" && ! -L "${data}" && -d "${data%/*}" ]] \
        && mkdir -m 700 -- "${data}" 2>/dev/null; then
        MADE_DATA_DIRS+=("${data}")
    fi
    [[ -d "${data}" ]] || return 0
    data="$(cd -P -- "${data}" 2>/dev/null && pwd -P)" || return 0
    [[ ! "${data}" -ef "${DEFENSECLAW_HOME}" ]] || return 0
    lock="${data%/}/.install.lock"
    for held in ${DATA_LOCK_DIRS[@]+"${DATA_LOCK_DIRS[@]}"}; do
        [[ ! "${held}" -ef "${lock}" && "${held}" != "${lock}" ]] || return 0
    done
    take_lock "${lock}" "check the free space and that $(id -un) can write ${data}; nothing was changed" \
        " for the data folder ${data}"
    DATA_LOCK_DIRS+=("${lock}")
}
hold_hook_data_dir "${BIN_DIR}/defenseclaw-gateway"

# ── Existing install ─────────────────────────────────────────────────────────

is_gateway_process() {
    # After a crash the PID in gateway.pid can belong to an unrelated process.
    # A stopped daemon can remain a zombie until its parent reaps it. kill -0
    # and ps -o comm both still succeed for zombies, but they cannot serve.
    local state
    state="$(ps -p "$1" -o stat= 2>/dev/null)" || return 1
    [[ ! "${state}" =~ ^[[:space:]]*Z ]] || return 1
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

# Older OpenCode and Amp processes retain their plugin in memory. Refuse a
# gateway swap only when the process is the exact entry installed for that
# agent. Unproven candidates are audited and do not block the upgrade.
agent_identity_audit() {
    printf 'audit: live-agent identity unproven for PID %s: %s\n' "$1" "$2" >&2
}

# resolved_agent_path FILE: the file's real path, with no PATH search.
resolved_agent_path() {
    [[ -f "$1" ]] || return 1
    if [[ "${OSTYPE:-}" == linux* ]]; then
        readlink -f -- "$1" 2>/dev/null
    elif [[ "${OSTYPE:-}" == darwin* ]]; then
        /usr/bin/perl -MCwd=realpath -e 'my $p = realpath($ARGV[0]); defined($p) or exit 1; print $p' "$1" 2>/dev/null
    else
        return 1
    fi
}

# npm_config_prefixes prints the prefix each npm config names: the
# environment, the user config (NPM_CONFIG_USERCONFIG, else ~/.npmrc) and
# the global npmrc (NPM_CONFIG_GLOBALCONFIG, else <node prefix>/etc/npmrc).
# npm expands ${VAR} and a leading ~ in a value, so this does too (GAP-1761).
npm_config_prefixes() {
    local file value name node expanded
    local -a files
    printf '%s\n' "${NPM_CONFIG_PREFIX:-${npm_config_prefix:-}}"
    files=("${NPM_CONFIG_USERCONFIG:-${npm_config_userconfig:-${HOME}/.npmrc}}" "${HOME}/.npmrc")
    if [[ -n "${NPM_CONFIG_GLOBALCONFIG:-${npm_config_globalconfig:-}}" ]]; then
        files+=("${NPM_CONFIG_GLOBALCONFIG:-${npm_config_globalconfig:-}}")
    elif node="$(command -v node 2>/dev/null)" && [[ "${node}" == /* ]]; then
        node="$(resolved_agent_path "${node}" 2>/dev/null || printf '%s' "${node}")"
        files+=("${node%/bin/node}/etc/npmrc")
    fi
    for file in "${files[@]}"; do
        [[ -f "${file}" ]] || continue
        value="$(sed -n 's/^[[:space:]]*prefix[[:space:]]*=[[:space:]]*//p' "${file}" 2>/dev/null | tail -n 1)" || value=""
        value="${value%"${value##*[![:space:]]}"}"
        value="${value%\"}"; value="${value#\"}"
        expanded=0
        while (( expanded++ < 8 )); do
            [[ "${value}" =~ \$\{([A-Za-z_][A-Za-z0-9_]*)\} ]] || break
            name="${BASH_REMATCH[1]}"
            value="${value//\$\{${name}\}/${!name:-}}"
        done
        printf '%s\n' "${value/#\~/${HOME}}"
    done
}

# The installer's entry evidence: native fixed locations and npm/Bun
# launcher symlinks to their exact entry: the Node script, or the native
# bin/opencode.exe that current opencode-ai links (GAP-1356). The links are
# looked for in the usual prefixes, npm's configured prefix and each PATH
# folder. A folder name, manifest or plain command on PATH is not an entry
# record: only a launcher link to the package's own entry is.
installed_agent_programs() {
    local agent name path target base link prefix seen=":"
    local -a bases folders
    for agent in OpenCode:opencode Amp:amp; do
        name="${agent#*:}"
        path="${HOME}/.${name}/bin/${name}"
        target="$(resolved_agent_path "${path}")" || continue
        printf '%s\t%s\n' "${agent%%:*}" "${target}"
    done
    bases=("${HOME}/.npm-global/bin" "${HOME}/.local/bin" "${HOME}/.bun/bin" /usr/local/bin /opt/homebrew/bin)
    while IFS= read -r prefix; do
        prefix="${prefix/#\~/${HOME}}"
        [[ "${prefix}" != /* ]] || bases+=("${prefix%/}/bin")
    done < <(npm_config_prefixes)
    IFS=: read -r -a folders <<< "${PATH:-}"
    for base in ${folders[@]+"${folders[@]}"}; do [[ "${base}" != /* ]] || bases+=("${base%/}"); done
    for base in "${bases[@]}"; do
        [[ "${seen}" != *":${base}:"* ]] || continue
        seen+="${base}:"
        for agent in OpenCode:opencode Amp:amp; do
            name="${agent#*:}"
            link="${base}/${name}"
            [[ -L "${link}" ]] || continue
            target="$(resolved_agent_path "${link}")" || continue
            case "${agent}:${target}" in
                OpenCode:*/node_modules/opencode-ai/bin/opencode | OpenCode:*/node_modules/opencode-ai/bin/opencode.exe | \
                    Amp:*/node_modules/@sourcegraph/amp/dist/main.js)
                    printf '%s\t%s\n' "${agent%%:*}" "${target}" ;;
            esac
        done
    done
}

# npm also puts its launcher beside the Node runtime selected by nvm, fnm,
# asdf, mise or a system prefix. Only that launcher's exact target is evidence.
runtime_agent_programs() {
    local program="${1% (deleted)}" agent name base link target
    case "${program##*/}" in node | nodejs) ;; *) return 0 ;; esac
    base="${program%/*}"
    for agent in OpenCode:opencode Amp:amp; do
        name="${agent#*:}"
        link="${base}/${name}"
        [[ -L "${link}" ]] || continue
        target="$(resolved_agent_path "${link}")" || continue
        case "${agent}:${target}" in
            OpenCode:*/node_modules/opencode-ai/bin/opencode | OpenCode:*/node_modules/opencode-ai/bin/opencode.exe | \
                Amp:*/node_modules/@sourcegraph/amp/dist/main.js)
                printf '%s\t%s\n' "${agent%%:*}" "${target}" ;;
        esac
    done
}

# An npm prefix that no config the installer can read names
# (NPM_CONFIG_USERCONFIG or NPM_CONFIG_PREFIX set only in the agent's own
# shell, npm --prefix): the running entry's own path names it,
# <prefix>/lib/node_modules/<package>/... For Node it is the script argument.
# Only the launcher npm put in <prefix>/bin, resolving to exactly that entry,
# is evidence, as for a configured prefix (GAP-1761).
entry_prefix_agent_programs() {
    local pid="$1" entry="${2% (deleted)}" word agent prefix link target
    local -a argv=()
    case "${entry##*/}" in
        node | nodejs)
            while IFS= read -r -d '' word; do
                argv+=("${word}")
                [[ ${#argv[@]} -ge 2 ]] && break
            done < <(process_argv "${pid}" 2>/dev/null)
            [[ ${#argv[@]} -ge 2 && "${argv[1]}" == /* ]] || return 0
            entry="$(resolved_agent_path "${argv[1]}")" || return 0
            ;;
    esac
    case "${entry}" in
        */lib/node_modules/opencode-ai/bin/opencode | */lib/node_modules/opencode-ai/bin/opencode.exe)
            agent=OpenCode:opencode; prefix="${entry%/lib/node_modules/opencode-ai/bin/*}" ;;
        */lib/node_modules/@sourcegraph/amp/dist/main.js)
            agent=Amp:amp; prefix="${entry%/lib/node_modules/@sourcegraph/amp/dist/main.js}" ;;
        *) return 0 ;;
    esac
    link="${prefix}/bin/${agent#*:}"
    [[ -L "${link}" ]] || return 0
    target="$(resolved_agent_path "${link}")" || return 0
    [[ "${target}" == "${entry}" ]] && printf '%s\t%s\n' "${agent%%:*}" "${target}"
    return 0
}

# One proc_pidpath call per PID in one interpreter on macOS. An absent old
# venv or an unreadable process yields an empty path; never fall back to lsof.
process_programs() {
    local pid program python rows
    if [[ "${OSTYPE:-}" == linux* ]]; then
        while read -r pid; do
            [[ "${pid}" =~ ^[0-9]+$ ]] || continue
            program="$(readlink "/proc/${pid}/exe" 2>/dev/null)" || program=""
            printf '%s\t%s\n' "${pid}" "${program}"
        done <<< "$1"
        return 0
    fi
    [[ "${OSTYPE:-}" == darwin* ]] || return 0
    python="${VENV:-${HOME}/.defenseclaw/.venv}/bin/python"
    if [[ ! -x "${python}" ]]; then
        while read -r pid; do [[ "${pid}" =~ ^[0-9]+$ ]] && printf '%s\t\n' "${pid}"; done <<< "$1"
        return 0
    fi
    rows="$("${python}" -I -c '
import ctypes, sys
lib = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
path_for = lib.proc_pidpath
path_for.argtypes = (ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32)
path_for.restype = ctypes.c_int
for line in sys.stdin:
    pid = line.strip()
    if not pid.isdecimal():
        continue
    buf = ctypes.create_string_buffer(4096)
    size = path_for(int(pid), buf, len(buf))
    path = buf.value.decode("utf-8", "surrogateescape") if size > 0 else ""
    print(pid + "\t" + path)
' <<< "$1" 2>/dev/null)" || {
        while read -r pid; do [[ "${pid}" =~ ^[0-9]+$ ]] && printf '%s\t\n' "${pid}"; done <<< "$1"
        return 0
    }
    printf '%s\n' "${rows}"
}

# process_argv PID: kernel argument boundaries, never the flattened ps text.
process_argv() {
    if [[ "${OSTYPE:-}" == linux* ]]; then
        cat "/proc/$1/cmdline" 2>/dev/null
        return
    fi
    [[ "${OSTYPE:-}" == darwin* && -x /usr/bin/perl ]] || return 1
    /usr/bin/perl -e '
        my $mib = pack("i3", 1, 49, $ARGV[0]); my $len = pack("Q", 0);
        syscall(202, $mib, 3, 0, $len, 0, 0) == 0 or exit 1;
        my $buf = "\0" x unpack("Q", $len);
        syscall(202, $mib, 3, $buf, $len, 0, 0) == 0 or exit 1;
        $buf = substr($buf, 0, unpack("Q", $len));
        my $argc = unpack("i", $buf);
        my @words = split(/\0/, substr($buf, 4), -1);
        shift @words;
        shift @words while @words && $words[0] eq "";
        $argc = @words if $argc > @words;
        print map { "$_\0" } @words[0 .. $argc - 1];
    ' "$1"
}

# A relative Node entry is resolved from the process's own cwd on Linux.
# macOS has no bounded cwd lookup here, so such an entry remains unproven.
process_cwd() {
    [[ "${OSTYPE:-}" == linux* ]] || return 1
    readlink "/proc/$1/cwd" 2>/dev/null
}

# agent_of PROGRAM INSTALLED PID WORD...: only an installed binary, or Node
# running that installed entry as its immediate script argument, counts.
# Options cannot be mistaken for a script: a command with Node flags is
# unproven and skipped rather than guessed from a list of option names.
agent_of() {
    local program="$1" installed="$2" pid="$3" agent path script cwd
    shift 3
    program="${program% (deleted)}"
    while IFS=$'\t' read -r agent path; do
        [[ -n "${path}" ]] && { [[ "${program}" == "${path}" ]] || [[ "${program}" -ef "${path}" ]]; } &&
            { printf '%s' "${agent}"; return 0; }
    done <<< "${installed}"
    case "${program##*/}" in node | nodejs) ;; *) return 0 ;; esac
    [[ $# -ge 2 && -n "$2" ]] || { agent_identity_audit "${pid}" 'Node script argument unavailable'; return 0; }
    [[ "$2" != -* ]] || { agent_identity_audit "${pid}" 'Node entry hidden by options'; return 0; }
    script="$2"
    if [[ "${script}" != /* ]]; then
        cwd="$(process_cwd "${pid}")" || { agent_identity_audit "${pid}" 'relative Node script cwd unreadable'; return 0; }
        script="${cwd%/}/${script}"
    fi
    script="$(resolved_agent_path "${script}")" || { agent_identity_audit "${pid}" 'Node script unreadable'; return 0; }
    while IFS=$'\t' read -r agent path; do
        [[ -n "${path}" && "${script}" == "${path}" ]] && { printf '%s' "${agent}"; return 0; }
    done <<< "${installed}"
    return 0
}

loaded_plugin_agents() {
    local pids installed rows runtime prefixed pid program agent word fresh
    local -a argv
    installed="$(installed_agent_programs)"
    pids="$(ps -u "$(id -u)" -o pid= 2>/dev/null)" || { [[ -z "${installed}" ]] || agent_identity_audit 0 'process list unreadable'; return 0; }
    rows="$(process_programs "${pids}")"
    runtime="$(while IFS=$'\t' read -r pid program; do runtime_agent_programs "${program}"; done <<< "${rows}")"
    [[ -z "${runtime}" ]] || installed+="${installed:+$'\n'}${runtime}"
    prefixed="$(while IFS=$'\t' read -r pid program; do [[ -z "${program}" ]] || entry_prefix_agent_programs "${pid}" "${program}"; done <<< "${rows}")"
    [[ -z "${prefixed}" ]] || installed+="${installed:+$'\n'}${prefixed}"
    [[ -n "${installed}" ]] || return 0
    while IFS=$'\t' read -r pid program; do
        [[ "${pid}" =~ ^[0-9]+$ ]] || continue
        if [[ -z "${program}" ]]; then
            kill -0 "${pid}" 2>/dev/null || agent_identity_audit "${pid}" 'process vanished during lookup'
            continue
        fi
        argv=()
        word="${program% (deleted)}"
        case "${word##*/}" in
            node | nodejs)
                while IFS= read -r -d '' word; do
                    argv+=("${word}")
                    [[ ${#argv[@]} -ge 2 ]] && break
                done < <(process_argv "${pid}" 2>/dev/null)
                [[ ${#argv[@]} -gt 0 ]] || { agent_identity_audit "${pid}" 'arguments unreadable'; continue; }
                ;;
        esac
        agent="$(agent_of "${program}" "${installed}" "${pid}" ${argv[@]+"${argv[@]}"})"
        [[ -n "${agent}" ]] || continue
        if [[ "${OSTYPE:-}" == linux* ]]; then
            fresh="$(readlink "/proc/${pid}/exe" 2>/dev/null)" || fresh=""
            if [[ "${fresh}" != "${program}" ]] || { [[ "${program}" != *' (deleted)' ]] && [[ ! "/proc/${pid}/exe" -ef "${program}" ]]; }; then
                agent_identity_audit "${pid}" 'executable changed during lookup'
                continue
            fi
        fi
        printf '%s (PID %s)\n' "${agent}" "${pid}"
    done <<< "${rows}"
}

assert_no_loaded_plugin_agents() {
    local agents
    agents="$(loaded_plugin_agents)"
    [[ -z "$agents" ]] || die "Close OpenCode and Amp completely before installing or upgrading DefenseClaw, then run this installer again; gateway still running: ${agents//$'\n'/, }"
}

stop_gateway() {
    # stop_gateway BINARY: stop the running gateway, preferring its own binary.
    # The stop is the install's, not the operator's: the gateway.stopped
    # marker `defenseclaw-gateway stop` writes is taken away again unless the
    # operator's was already there. A hook that runs while the install holds
    # .install.lock then reports a restart, not an operator stop; the hooks of
    # 1.0.2 and earlier read only that marker (GAP-0140). The lock keeps every
    # hook from starting the gateway meanwhile.
    local binary="$1" pid waited=0 marker="${DEFENSECLAW_HOME}/gateway.stopped" operator_stop=false
    pid="$(gateway_pid || true)"
    [[ -n "${pid}" ]] || return 0
    [[ -e "${marker}" || -L "${marker}" ]] && operator_stop=true
    if [[ -x "${binary}" ]]; then
        "${binary}" stop >/dev/null 2>&1 || true
    fi
    [[ "${operator_stop}" == true ]] || rm -f "${marker:?}"
    while [[ -n "$(gateway_pid || true)" && ${waited} -lt 30 ]]; do
        sleep 1; waited=$((waited + 1))
        [[ ${waited} -eq 15 ]] && kill "${pid}" 2>/dev/null || true
        # A gateway still shutting down at 25s is killed, as install.ps1
        # does: one whose hook writer waits on the fail-mode hold
        # (hold_hook_fail_modes) cannot finish its own shutdown.
        [[ ${waited} -eq 25 ]] && kill -KILL "${pid}" 2>/dev/null || true
    done
    [[ -z "$(gateway_pid || true)" ]]
}

hook_fail_mode_refresh_probe() {
    # 0: the staged gateway has 'connector refresh-fail-modes'. 1: an older
    # one (a downgrade), which prints the connector help for an unknown
    # subcommand and sets its own modes when it starts. 2: any other answer
    # (an error, no output): the hooks cannot be shown safe.
    local help="" rc=0
    help="$("${STAGING}/bin/defenseclaw-gateway" connector refresh-fail-modes --help 2>&1)" || rc=$?
    [[ ${rc} -eq 0 && "${help}" == *"connector refresh-fail-modes"* ]] && return 0
    [[ ${rc} -eq 0 && "${help}" == *"defenseclaw-gateway connector [command]"* ]] && return 1
    warn "The new gateway did not answer 'connector refresh-fail-modes --help' (exit ${rc})"
    return 2
}

refresh_hook_fail_modes() {
    # Set the installed hooks' outage fail modes (hooks/.hookcfg, its flat
    # records and the open a connector script bakes) from the config with the
    # staged gateway: an earlier release may have recorded or baked open for a
    # mode nobody set, which its hooks follow while the gateway is down for
    # the swap. An open the config sets stays open, from a DEFENSECLAW_CONFIG
    # outside the data directory too. Used when no gateway runs; a running
    # one gets hold_hook_fail_modes.
    local probe=0
    hook_fail_mode_refresh_probe || probe=$?
    case ${probe} in
        0) "${STAGING}/bin/defenseclaw-gateway" connector refresh-fail-modes ;;
        1) return 0 ;;
        *) return 1 ;;
    esac
}

HOLD_PID=""
HOLD_LOG=""
hold_hook_fail_modes() {
    # hold_hook_fail_modes PID: refresh_hook_fail_modes for the running
    # gateway PID, which is about to stop. The staged gateway refreshes, holds
    # the lock every release's hook writer takes until PID has exited, and
    # refreshes again: the old gateway may render its hooks again while it
    # runs or shuts down, and they would follow that open while it is down.
    # Returns once the first refresh is written and the lock held;
    # finish_hook_fail_mode_hold waits for the rest.
    local probe=0 waited=0
    hook_fail_mode_refresh_probe || probe=$?
    case ${probe} in
        0) ;;
        1) return 0 ;;
        *) return 1 ;;
    esac
    HOLD_LOG="${STAGING}/refresh-fail-modes.log"
    : >"${HOLD_LOG}"
    "${STAGING}/bin/defenseclaw-gateway" connector refresh-fail-modes \
        --hold-timeout 10m --hold-until-exit "$1" >"${HOLD_LOG}" 2>&1 &
    HOLD_PID=$!
    while ! grep -q "Holding the hook fail modes" "${HOLD_LOG}" 2>/dev/null; do
        if ! kill -0 "${HOLD_PID}" 2>/dev/null; then
            finish_hook_fail_mode_hold || true
            return 1
        fi
        if [[ ${waited} -ge 600 ]]; then
            warn "The new gateway did not set the hooks' fail modes within a minute"
            end_hook_fail_mode_hold
            return 1
        fi
        sleep 0.1
        waited=$((waited + 1))
    done
}

finish_hook_fail_mode_hold() {
    # Wait for the hold, which ends once the gateway it holds for has exited,
    # and show what it said.
    [[ -n "${HOLD_PID}" ]] || return 0
    local rc=0
    wait "${HOLD_PID}" || rc=$?
    HOLD_PID=""
    if [[ ${rc} -eq 0 ]]; then
        grep -v "Holding the hook fail modes" "${HOLD_LOG}" || true
    else
        cat "${HOLD_LOG}" >&2 || true
    fi
    return ${rc}
}

end_hook_fail_mode_hold() {
    # Let go of the hold early: the gateway did not stop.
    [[ -n "${HOLD_PID}" ]] || return 0
    kill "${HOLD_PID}" 2>/dev/null || true
    wait "${HOLD_PID}" 2>/dev/null || true
    HOLD_PID=""
}

warn_running_sandboxes() {
    # A running sandbox's hooks fail closed while the gateway restarts, so its
    # agent's tool calls are refused until the gateway is back. Name them
    # before the question, not only in the session's end summary (GAP-0352).
    # With a version: a rollback to that release, which cannot take over the
    # sandbox setup, so they stay refused until the user rolls forward.
    local gateway="${BIN_DIR}/defenseclaw-gateway" names stranded="${1:-}"
    local one="while the gateway restarts (usually under a minute) its hooks fail closed, so its agent's tool calls are refused until the gateway is back"
    local many="while the gateway restarts (usually under a minute) their hooks fail closed, so their agents' tool calls are refused until the gateway is back"
    if [[ -n "${stranded}" ]]; then
        local again="defenseclaw rollback"
        if is_version "${stranded}" && version_lt "${stranded}" 1.0.0; then
            again="bash ${PREVIOUS}/installer/install.sh --rollback"
        fi
        one="DefenseClaw ${stranded} cannot take over its sandbox setup, so its hooks fail closed and its agent's tool calls are refused until you run '${again}' again"
        many="DefenseClaw ${stranded} cannot take over their sandbox setup, so their hooks fail closed and their agents' tool calls are refused until you run '${again}' again"
    fi
    [[ -x "${gateway}" && -x "${VENV}/bin/python" && -n "$(gateway_pid || true)" ]] || return 0
    names="$("${VENV}/bin/python" -I - "${gateway}" <<'PY' 2>/dev/null
import json, re, subprocess, sys
try:
    out = subprocess.run([sys.argv[1], "sandbox", "list", "--output", "json"], capture_output=True, text=True, timeout=10).stdout
    rows = json.loads(out or "{}").get("sandboxes") or []
except Exception:
    rows = []
print(" ".join(sorted(
    r["name"] for r in rows
    if isinstance(r, dict) and r.get("phase") == "ready"
    and isinstance(r.get("name"), str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,62}", r["name"])
)))
PY
)" || return 0
    # The validated names are space-separated for the count and message.
    # shellcheck disable=SC2086
    set -- ${names}
    case $# in
        0) ;;
        1) warn "Sandbox $1 is running: ${one}" ;;
        *) warn "$# sandboxes are running ($(printf '%s, ' "$@" | sed 's/, $//')): ${many}" ;;
    esac
}

# refuse_legacy_sandboxes PREVIOUS: an upgrade from DefenseClaw 1.0.0 to
# 1.0.3 refuses, and changes nothing, while that release's gateway runs a
# sandbox that may hold compute (GAP-0901). Each such session keeps the
# supervisor it started with, an OpenShell release whose network broker can
# let connections bypass sandbox policy (NVIDIA/OpenShell#4494), and the new
# gateway can only report it unprotected: DefenseClaw stops no sandbox for
# its user, who saves the work and ends it first. The phases are those the
# package preinstall counts (legacy-sandbox-guard.sh dc_guard_holds). A
# gateway that is not running, or that cannot list sandboxes (sandboxes off),
# has none to name.
refuse_legacy_sandboxes() {
    local prev="${1:-}" gateway="${BIN_DIR}/defenseclaw-gateway" held name phase
    is_version "${prev}" && ! version_lt "${prev}" 1.0.0 && version_lt "${prev}" 1.0.4 || return 0
    ! is_version "${VERSION}" || ! version_lt "${VERSION}" 1.0.4 || return 0
    [[ -x "${gateway}" && -x "${VENV}/bin/python" && -n "$(gateway_pid || true)" ]] || return 0
    held="$("${VENV}/bin/python" -I - "${gateway}" <<'PY' 2>/dev/null
import json, re, subprocess, sys
try:
    out = subprocess.run([sys.argv[1], "sandbox", "list", "--output", "json"], capture_output=True, text=True, timeout=10).stdout
    rows = json.loads(out or "{}").get("sandboxes") or []
except Exception:
    rows = []
for r in rows:
    if not isinstance(r, dict) or not isinstance(r.get("name"), str):
        continue
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,62}", r["name"]):
        continue
    phase = r.get("phase") if isinstance(r.get("phase"), str) else ""
    driver = r.get("driver") if isinstance(r.get("driver"), str) and r.get("driver") else "docker"
    reason = r.get("phase_reason") if isinstance(r.get("phase_reason"), str) else ""
    if phase in ("stopped", "deleting", "deleted", "missing"):
        continue
    if phase == "completed" and driver == "docker":
        continue
    if phase == "error" and (driver == "docker" or reason.startswith("ProcessExited")):
        continue
    print(r["name"] + " " + (phase if re.fullmatch(r"[a-z_]{1,32}", phase) else "unknown"))
PY
)" || return 0
    [[ -n "${held}" ]] || return 0
    err "Sandboxes of DefenseClaw ${prev} are running; nothing was changed. Their sessions keep the network broker of the OpenShell release they started with, which can let connections bypass sandbox policy, and DefenseClaw ${VERSION} cannot contain it: it would only report them unprotected and run no new sandbox until they are gone. DefenseClaw stops no sandbox for you. End each one, then run this upgrade again:"
    while read -r name phase; do
        [[ -n "${name}" ]] || continue
        case "${phase}" in
            completed|error) printf '    %s (%s MicroVM, which OpenShell does not stop): defenseclaw sandbox delete %s (it deletes the sandbox with its work)\n' "${name}" "${phase}" "${name}" >&2 ;;
            *) printf '    %s (%s): save the work you need, then defenseclaw sandbox stop %s\n' "${name}" "${phase}" "${name}" >&2 ;;
        esac
    done <<<"${held}"
    exit 1
}

# other_build_installed: the installed gateway reports another build of this
# version (its commit or build date) than the staged one (GAP-1063). An
# installed gateway that does not answer is repaired, as before. Sets
# INSTALLED_BUILD and STAGED_BUILD to the commit each one names.
other_build_installed() {
    local installed staged
    installed="$("${BIN_DIR}/defenseclaw-gateway" --version 2>/dev/null)" || return 1
    staged="$("${STAGING}/bin/defenseclaw-gateway" --version 2>/dev/null)" || return 1
    [[ "${installed}" == *"${VERSION}"* && "${installed}" != "${staged}" ]] || return 1
    INSTALLED_BUILD="$(sed -n 's/.*(commit=\([^,)]*\).*/commit \1/p' <<<"${installed}" | head -1)"
    STAGED_BUILD="$(sed -n 's/.*(commit=\([^,)]*\).*/commit \1/p' <<<"${staged}" | head -1)"
    INSTALLED_BUILD="${INSTALLED_BUILD:-${installed}}" STAGED_BUILD="${STAGED_BUILD:-${staged}}"
}

# sandbox_state_carries V1 V2: both releases keep the sandbox setup as this one does.
sandbox_state_carries() {
    is_version "$1" && is_version "$2" \
        && ! version_lt "$1" "${SANDBOX_STATE_SINCE}" && ! version_lt "$2" "${SANDBOX_STATE_SINCE}"
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
    # Sandboxes keep running across the swap, and the data it brings back has
    # none of the setup made for them since (GAP-0483): it comes along.
    stranded=""
    sandbox_state_carries "${current}" "${back_to}" || stranded="${back_to}"
    warn_running_sandboxes "${stranded}"
    ask_yes_no "${question}" || die "Rollback cancelled; nothing was changed"
    # GAP-1388: a 0.x release cannot start on a damaged audit store, so check
    # the saved data before anything of this install changes.
    AUDIT_DAMAGED=""
    if version_lt "${back_to}" 1.0.0; then check_rollback_data; fi
    was_running=false
    [[ -n "$(gateway_pid || true)" ]] && was_running=true
    # The swap overwrites previous/GATEWAY_WAS_RUNNING with this install's state.
    saved_was_running="$(cat "${PREVIOUS}/GATEWAY_WAS_RUNNING" 2>/dev/null || true)"
    restart="${was_running}"
    [[ "${saved_was_running}" == true ]] && restart=true
    assert_locks_ours
    assert_no_loaded_plugin_agents
    stop_gateway "${BIN_DIR}/defenseclaw-gateway" || die "The gateway did not stop; nothing was changed"
    if [[ -n "${current}" ]] && version_lt "${back_to}" 1.0.0 && ! version_lt "${current}" 1.0.0; then
        remove_connector_registrations_for_legacy
    elif [[ -z "${current}" ]] || ! version_lt "${current}" "${back_to}"; then
        convert_hooks_for_rollback
    fi
    swapped=0
    swap_with_previous || swapped=$?
    if [[ "${swapped}" -ne 0 ]]; then
        # 1: the swap undid itself, so this install is back and may run again.
        # Its start also writes the connector registrations removed above.
        if [[ "${swapped}" -eq 1 && ( "${was_running}" == true || -n "${LEGACY_TORN_DOWN:-}" ) ]]; then
            start_gateway || true
        fi
        die "Rollback failed part-way; see ${LOG}"
    fi
    # GAP-0009: a connector set up after the upgrade is not configured in the
    # install now back, whose data has no hook script for it: its agent ran a
    # hook that no longer exists (Claude Code blocked every prompt). The
    # newer gateway of the two knows the entries; only DefenseClaw's go.
    if ! version_lt "${back_to}" 1.0.0; then
        prune_orphaned_hooks "${BIN_DIR}/defenseclaw-gateway" "${PREVIOUS}/bin/defenseclaw-gateway"
    fi
    # GAP-0483: the install now back had sandboxes off and none of the
    # running sandboxes' hook bindings, so their hooks failed closed as
    # "gateway unreachable" here and after the next upgrade. The newer
    # gateway of the two copies the setup; previous/ keeps its own.
    if [[ -z "${stranded}" ]]; then
        if version_lt "${back_to}" "${current}"; then
            carry_sandbox_state "${PREVIOUS}" always "${PREVIOUS}/bin/defenseclaw-gateway" "${BIN_DIR}/defenseclaw-gateway"
        else
            carry_sandbox_state "${PREVIOUS}" always "${BIN_DIR}/defenseclaw-gateway" "${PREVIOUS}/bin/defenseclaw-gateway"
        fi
    fi
    rollback_rc=0
    QUARANTINED=""
    if [[ -n "${AUDIT_DAMAGED}" ]] && ! quarantine_rolled_back_audit; then
        undo_rollback "The damaged audit store of DefenseClaw ${back_to} could not be moved aside"
    fi
    if [[ "${restart}" == true ]]; then
        start_gateway || rollback_rc=$?
        case "${rollback_rc}" in
            0) restart_openclaw ;;
            3) warn "A connector needs attention before it is guarded again (see the gateway output above)"; restart_openclaw ;;
            *) rollback_rc=1 ;;
        esac
    fi
    # A rollback is done only once its gateway runs: one that does not start
    # is undone for a 1.x release as for a 0.x one, which has no rollback
    # command and writes its own connector registrations only once it runs
    # (GAP-0486, the Windows twin). undo_rollback exits 1.
    if [[ ${rollback_rc} -eq 1 ]]; then
        undo_rollback "The gateway of DefenseClaw ${back_to} did not start"
    fi
    ok "Now running DefenseClaw ${back_to}."
    forward="defenseclaw rollback"
    if version_lt "${back_to}" 1.0.0; then
        forward="bash ${PREVIOUS}/installer/install.sh --rollback"
        info "To return to ${current:-1.x}, run: ${forward}"
    else
        info "Run '${forward}' again to return to ${current:-the other install}."
    fi
    # The swap keeps the install just left, with its data, in previous/.
    # Each install shows only its own audit window, so say how to read the
    # other one (GAP-0126). The newer build's gateway reads either log.
    if [[ -z "${current}" ]] || version_lt "${back_to}" "${current}"; then
        info "Data written since the upgrade is kept in ${PREVIOUS}; '${forward}' again brings it back (a new 'defenseclaw upgrade' starts from the data you have now and keeps that copy in ${DEFENSECLAW_HOME}/backups)."
        [[ -f "${PREVIOUS}/data/audit.db" && -x "${PREVIOUS}/bin/defenseclaw-gateway" ]] \
            && info "Its audit events: ${PREVIOUS}/bin/defenseclaw-gateway audit export --db ${PREVIOUS}/data/audit.db"
    else
        info "Data written while ${current} ran is kept in ${PREVIOUS} and comes back if you roll back again."
        [[ -f "${PREVIOUS}/data/audit.db" ]] \
            && info "Its audit events: defenseclaw-gateway audit export --db ${PREVIOUS}/data/audit.db"
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

# drop_unswapped_stage: a run that stops before the swap removes the release
# it staged and fetched, and the uv files it added (GAP-1901, GAP-1120).
drop_unswapped_stage() {
    rm -rf "${STAGING:?}"
    [[ -z "${UV_DIR_NEW}" ]] || rm -rf "${DEFENSECLAW_HOME:?}/.uv"
    [[ -z "${UV_INSTALLED}" ]] || rm -f "${BIN_DIR}/uv" "${BIN_DIR}/uvx" "${BIN_DIR}/defenseclaw-uv.sha256"
}
rm -rf "${STAGING}"
mkdir -p "${STAGING}/bin"
UNSWAPPED_STAGE=1
# Ctrl+C before the swap: drop what this run staged and fetched (GAP-1901).
trap 'printf "\n"; drop_unswapped_stage; err "Cancelled; nothing was changed"; exit 130' INT TERM
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

# --local copies the assets, so it says so instead of "Downloading" (GAP-0190).
if [[ -n "${LOCAL_DIR}" ]]; then
    info "Verifying the release assets in ${LOCAL_DIR}"
else
    info "Downloading and verifying release assets"
fi
fetch checksums.txt "${STAGING}/checksums.txt" || fetch_failed checksums.txt
checksum_ok() {
    local file="$1" name expected
    name="${2:-$(basename "${file}")}"
    expected="$(awk -v n="${name}" '$2==n||$2==("*" n){print $1}' "${STAGING}/checksums.txt")"
    [[ -n "${expected}" && "$(sha256_of "${file}")" == "${expected}" ]]
}
verify() {
    if ! checksum_ok "$@"; then
        local asset
        asset="$(basename "$1")"
        rm -rf "${STAGING}" || die "${asset} does not match checksums.txt; could not remove staged assets at ${STAGING}; installed files were not changed"
        die "${asset} does not match checksums.txt; staged assets were removed; nothing was changed"
    fi
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
[[ -f "${STAGING}/bin/defenseclaw-hook-post" ]] || die "${ARCHIVE} has no defenseclaw-hook-post"
# The sensor helper serves only the Linux sandbox kernel feed.
[[ "${OS}" == linux ]] || rm -f "${STAGING}/bin/defenseclaw-sensor-helper"
for binary in ${MANAGED_BINARIES}; do
    [[ -f "${STAGING}/bin/${binary}" ]] || continue
    chmod 755 "${STAGING}/bin/${binary}"
    stage_binary "${binary}"
done
"${STAGING}/bin/defenseclaw-gateway" --version 2>/dev/null | grep -qF "${VERSION}" \
    || die "The gateway in ${ARCHIVE} does not report version ${VERSION}"
"${STAGING}/bin/defenseclaw-hook-post" --version 2>/dev/null | grep -qF "${VERSION}" \
    || die "The hook transport in ${ARCHIVE} does not report version ${VERSION}"

# When another account's process holds this account's API port, the upgrade
# only fails at the gateway restart, after the build, the migration and the
# swap. The staged gateway (a release that has the check) names it first
# (GAP-0130). A gateway that was not running is not restarted, so it is not checked.
if [[ -n "${PREV_VERSION}" && -n "$(gateway_pid || true)" ]] \
    && "${STAGING}/bin/defenseclaw-gateway" check-api-port --help >/dev/null 2>&1; then
    if ! port_problem="$("${STAGING}/bin/defenseclaw-gateway" check-api-port 2>&1)"; then
        rm -rf "${STAGING}"
        drop_new_uv
        die "${port_problem#Error: }; nothing was changed"
    fi
fi

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
# Hold the data_dir the new gateway reads from the config (see
# hold_hook_data_dir) before the swap stops or replaces anything.
hold_hook_data_dir "${STAGING}/bin/defenseclaw-gateway" required

# ── Swap ─────────────────────────────────────────────────────────────────────

# A same-version run over the installed build is a repair: previous/ stays
# the rollback copy. Another build of this version (a release candidate the
# next one replaces) is replaced as an upgrade is: the replaced build becomes
# the rollback copy, and this says so before the swap (GAP-1063).
REPAIR=false
if [[ -n "${PREV_VERSION}" && "${PREV_VERSION}" == "${VERSION}" ]] && ! other_build_installed; then
    REPAIR=true
fi
refuse_legacy_sandboxes "${PREV_VERSION}"
warn_running_sandboxes
if [[ "${REPAIR}" == true ]]; then
    ask_yes_no "Reinstall DefenseClaw ${VERSION}?" || die "Cancelled; nothing was changed"
elif [[ "${PREV_VERSION}" == "${VERSION}" ]]; then
    info "The installed DefenseClaw ${VERSION} is another build (${INSTALLED_BUILD}) than this one (${STAGED_BUILD}); it is kept in ${PREVIOUS}, so 'defenseclaw rollback' returns to it"
    ask_yes_no "Replace the installed build of DefenseClaw ${VERSION}?" || die "Cancelled; nothing was changed"
elif [[ -n "${PREV_VERSION}" ]]; then
    if version_lt "${PREV_VERSION}" 1.0.0 && [[ -f "${DEFENSECLAW_HOME}/audit.db" ]]; then
        # Audit migration 33 (privacy cutover) empties the pre-1.0 history.
        warn "DefenseClaw 1.0 starts a new audit history: the audit events, scan results and findings ${PREV_VERSION} recorded (${DEFENSECLAW_HOME}/audit.db, $(du -sh "${DEFENSECLAW_HOME}/audit.db" 2>/dev/null | awk '{print $1}')) are deleted when DefenseClaw ${VERSION} first opens its audit database"
        info "A copy is kept in ${PREVIOUS}/data/audit.db; 'defenseclaw rollback' brings it back, and later upgrades keep it in ${DEFENSECLAW_HOME}/backups"
    fi
    if version_lt "${VERSION}" "${PREV_VERSION}"; then
        # An older release over a newer one is a downgrade: ask with no as the
        # answer, and say so even with --yes (GAP-0287).
        [[ "${YES}" == true ]] && warn "Downgrading DefenseClaw ${PREV_VERSION} → ${VERSION} (--yes)"
        ask_yes_no "Downgrade DefenseClaw ${PREV_VERSION} → ${VERSION}? (an older release; 'defenseclaw rollback' undoes it)" n \
            || die "Cancelled; nothing was changed"
    else
        ask_yes_no "Upgrade DefenseClaw ${PREV_VERSION} → ${VERSION}?" || die "Cancelled; nothing was changed"
    fi
fi
if [[ -z "${PREV_VERSION}" ]] && [[ "${YES}" != true ]] && [[ -z "${CONNECTOR}" ]]; then
    pick_connector
fi

assert_locks_ours
assert_no_loaded_plugin_agents
WAS_RUNNING=false
RESTORED_NOTE="Your previous install is back."
OLD_GATEWAY_PID="$(gateway_pid || true)"
[[ -n "${OLD_GATEWAY_PID}" ]] && WAS_RUNNING=true
if [[ "${WAS_RUNNING}" == true ]]; then
    hold_hook_fail_modes "${OLD_GATEWAY_PID}" \
        || die "Could not set the hooks' fail modes from your config, so they could fail open while the gateway is down; nothing was changed (see above)"
    info "Stopping the gateway"
    if ! stop_gateway "${BIN_DIR}/defenseclaw-gateway"; then
        end_hook_fail_mode_hold
        die "The running gateway did not stop; nothing was changed"
    fi
    # The hold refreshes again once the gateway has exited.
    if ! finish_hook_fail_mode_hold; then
        restart_old
        rm -rf "${STAGING}"
        drop_new_uv
        die "Could not set the hooks' fail modes from your config, so they could fail open while the gateway is down. ${RESTORED_NOTE}"
    fi
else
    refresh_hook_fail_modes \
        || die "Could not set the hooks' fail modes from your config, so they could fail open while the gateway is down; nothing was changed (see above)"
fi

if [[ "${REPAIR}" == true ]]; then
    SNAP="${DEFENSECLAW_HOME}/.repair"
else
    SNAP="${DEFENSECLAW_HOME}/previous.new"
fi
# From here the swap owns the staged release: its undo removes it (drop_staging).
UNSWAPPED_STAGE=""
trap 'warn "Interrupted; finishing or undoing the swap before exiting"' INT TERM
trap '' HUP PIPE
assert_locks_ours
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
    drop_staging
    die "DefenseClaw ${VERSION} was not installed. ${RESTORED_NOTE} Log: ${LOG}"
fi
START_RC=0
if [[ "${WAS_RUNNING}" == true && ! -f "${DEFENSECLAW_HOME}/config.yaml" && -z "${DEFENSECLAW_CONFIG:-}" ]]; then
    # 0.x gateways ran on defaults without a config; 1.x needs one.
    WAS_RUNNING=false
    warn "The gateway was running without a configuration; run 'defenseclaw init' to set it up"
fi
if [[ "${WAS_RUNNING}" == true ]]; then
    # An older setup can remove working hooks after the same refresh error.
    # Interrupted recovery must preserve this refusal too.
    : > "${SNAP}/GATEWAY_RESTART_UNPROVEN"
    set +e
    start_gateway
    START_RC=$?
    set -e
    if [[ ${START_RC} -ne 0 && ${START_RC} -ne 3 ]]; then
        err "The ${VERSION} gateway did not become healthy; restoring ${PREV_VERSION:-the previous state}"
        stop_gateway "${BIN_DIR}/defenseclaw-gateway" || true
        restore_snapshot
        drop_staging
        die "DefenseClaw ${VERSION} was not installed. ${RESTORED_NOTE} Log: ${LOG}"
    fi
    rm -f "${SNAP}/GATEWAY_RESTART_UNPROVEN"
fi
finish_swap
# until 1.1: an upgrade or repair removes what an older setup wrote for
# OpenHands and OmniGent, whether or not its gateway was running before it.
[[ -z "${PREV_VERSION}" ]] || finish_retired_connector_cleanup
report_retired_connector_leftovers
if [[ -n "${PREV_VERSION}" && "${WAS_RUNNING}" != true ]] && ! reconcile_stopped_connectors; then
    START_RC=3
fi
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
outage_open_notice() {
    # An upgrade from 1.0.2 or 1.0.3 of a config that saves no hook fail
    # mode: gateway outages now run with a warning in the default and
    # permissive tiers (owner decision 2026-10-23), which those releases
    # blocked. Said once, after the upgrade (GAP-1885).
    [[ -x "${VENV}/bin/python" ]] || return 0
    # DEFENSECLAW_HOME is readonly and already exported: a prefix assignment
    # of it is an error (GAP-0016).
    "${VENV}/bin/python" -I - <<'PY' 2>/dev/null || true
# GAP-1885: "notice" when an active per-user connector whose hook fail mode
# this config does not save (for it, or globally) now lets a gateway outage
# run (the default and permissive tiers); 1.0.2 and 1.0.3 closed it. A mode
# saved for one connector says nothing about another one.
try:
    from defenseclaw import config as dc_config
    cfg = dc_config.load()
    guard = cfg.guardrail
    names = list(cfg.active_connectors())
    if guard.enabled and names and not cfg.managed_outside_secure_client() and not guard.secure_client_hook_fail_modes():
        saved = bool(getattr(guard, "_hook_fail_mode_saved", False) and str(guard.hook_fail_mode or "").strip())
        for name in names:
            override = guard._connector_override(name)
            if override is not None and str(override.hook_fail_mode or "").strip():
                continue
            if not saved and guard.effective_hook_fail_mode(name) == "open":
                print("notice")
                break
except Exception:
    pass
PY
}
printf "\n${BOLD}${GREEN}  DefenseClaw ${VERSION} is installed.${NC}\n"
if [[ -n "${PREV_VERSION}" && "${REPAIR}" != true ]]; then
    changed="Upgraded from ${PREV_VERSION}"
    version_lt "${VERSION}" "${PREV_VERSION}" && changed="Downgraded from ${PREV_VERSION}"
    [[ "${PREV_VERSION}" == "${VERSION}" ]] && changed="Replaced the other build of ${VERSION}"
    printf "  ${changed}. Undo with: ${CYAN}defenseclaw rollback${NC}\n"
    if version_lt "${PREV_VERSION}" 1.0.4 && version_lt "${PREV_VERSION}" "${VERSION}" && [[ "$(outage_open_notice)" == notice ]]; then
        printf '  %s\n' 'Gateway outages now let calls run with a warning (the default and permissive policies). Run `defenseclaw guardrail fail-mode closed` to keep blocking them.'
    fi
    if version_lt "${PREV_VERSION}" 1.0.0 && [[ -f "${PREVIOUS}/data/audit.db" ]]; then
        printf "  The audit history ${PREV_VERSION} recorded is not carried over to 1.0; a copy is in ${PREVIOUS}/data/audit.db\n"
    fi
    if pgrep -f "${VENV}/bin/defenseclaw" >/dev/null 2>&1; then
        warn "Restart the DefenseClaw TUI and any other open DefenseClaw commands; they still run ${PREV_VERSION}"
    fi
fi
# The sandbox kernel feed is a root copy of the helper that an upgrade as this
# user cannot replace: say how to bring it to this release.
if [[ "${OS}" == linux && -f "${SANDBOX_FEED_UNIT}" && -x "${BIN_DIR}/defenseclaw-sensor-helper" ]]; then
    FEED_VERSION="$("${SANDBOX_FEED_HELPER}" --version 2>/dev/null | sed -n 's/.* version \([^ ]*\).*/\1/p')"
    if [[ "${FEED_VERSION}" != "${VERSION}" ]]; then
        warn "The sandbox kernel feed runs ${FEED_VERSION:-an unknown version}, not ${VERSION}; update it with: sudo ${BIN_DIR}/defenseclaw-gateway sandbox kernel-feed install"
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
        # GAP-0384: when another process holds its API port, that start fails too.
        if port_problem="$("${BIN_DIR}/defenseclaw-gateway" check-api-port --installed 2>&1)"; then
            printf "  Start it with: ${CYAN}defenseclaw-gateway start${NC}\n"
        else
            info "${port_problem#Error: }"
        fi
    fi
fi
if [[ -n "${PREV_VERSION}" && "${RUN_QUICKSTART}" != true && ! -f "${DEFENSECLAW_HOME}/config.yaml" && -z "${DEFENSECLAW_CONFIG:-}" ]]; then
    # An earlier install that was never initialized: say how to start, as a
    # fresh install does. The connector an earlier install recorded is not
    # named: it may be the codex picked with no terminal to ask on (GAP-0568).
    if [[ -n "${CONNECTOR}" && "${CONNECTOR}" != none ]]; then
        printf "  DefenseClaw is not set up yet. Next: ${CYAN}defenseclaw init --connector %s${NC}\n" "${CONNECTOR}"
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

# drop_staging: an install that was undone leaves only the .failed-<time>
# copy it names. The staged release and the uv files this run added went
# unmentioned next to it: about 1.2 GB after a rolled-back upgrade (GAP-0388).
drop_staging() {
    rm -rf "${STAGING}" || true
    drop_new_uv || true
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

# name_removable names what DefenseClaw itself keeps that can go to make room:
# the copy a failed install kept and the data earlier upgrades kept.
name_removable() {
    local item size what
    for item in "${DEFENSECLAW_HOME}"/.failed-* "${DEFENSECLAW_HOME}/backups"; do
        [[ -d "${item}" && ! -L "${item}" ]] || continue
        size="$(du -sk "${item}" 2>/dev/null | awk '{print int(($1 + 1023) / 1024)}')"
        case "${item}" in
            */backups) what="what earlier upgrades kept (old audit history, a replaced app)" ;;
            *) what="the copy a failed install kept for troubleshooting" ;;
        esac
        info "You can remove ${item} (${size:-?} MB), ${what}: rm -rf '${item}'"
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
        # A 1 MB audit.db is no answer to a 462 MB shortfall (GAP-0389).
        if [[ -n "${biggest}" && $((biggest_kb * 10)) -ge $((need_kb - free_kb)) ]]; then
            err "The largest item is ${DEFENSECLAW_HOME}/${biggest} ($(((biggest_kb + 1023) / 1024)) MB)"
        fi
    else
        err "Not enough free disk space next to ${DEFENSECLAW_HOME}: the install needs about $((need_kb / 1024)) MB and $((free_kb / 1024)) MB is free"
    fi
    name_removable
    die "Free at least $(((need_kb - free_kb + 1023) / 1024)) MB on that filesystem (df -h ${dir}), then rerun; nothing was changed"
}

# require_writable_dirs refuses before anything is written, the gateway
# stopped or the lock taken, when a folder the install replaces files in
# cannot be written: an upgrade stopped the gateway, then failed to copy the
# binaries and to put the old ones back (GAP-0381), and a first install only
# said it could not install uv (GAP-0420). A folder that does not exist yet is
# checked where it would be created.
require_writable_dirs() {
    local dir probe owner
    for dir in "${BIN_DIR}" "${DEFENSECLAW_HOME}" "${VENV}" "${PREVIOUS}" "${INSTALLER_DIR}"; do
        probe="${dir}"
        while [[ ! -e "${probe}" && ! -L "${probe}" && "${probe}" == */* ]]; do probe="${probe%/*}"; done
        [[ -n "${probe}" ]] || probe=/
        [[ -d "${probe}" && -w "${probe}" && -x "${probe}" ]] && continue
        owner="$(stat -c '%U, mode %a' "${probe}" 2>/dev/null || stat -f '%Su, mode %Lp' "${probe}" 2>/dev/null || true)"
        err "${probe} is not writable by $(id -un)${owner:+ (owner ${owner})}, and the install replaces files there"
        die "Make it writable (chmod u+w '${probe}', or sudo chown -R $(id -un) '${probe}' when another account owns it), then rerun; nothing was changed"
    done
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
    write_busy_shim
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
            # A restore that could not finish keeps the slot: never install over it.
            [[ ! -e "${slot}" ]] || die "Could not finish putting back the install an earlier run replaced; ${slot} holds it (see above)"
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
            unstash_tree "${slot}" && restore_links "${slot}" && drop_hold "${slot}"
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
    restore_links "${SNAP}"
    rm -rf "${SNAP}"
}

# write_busy_shim: during the swap the defenseclaw link points into a venv
# that is being moved, so a command typed meanwhile, or after the run was
# killed, failed with "command not found" (GAP-0391). This script stands in
# for it: it says an install is running, or how to finish one that stopped.
# The new link, or restore_links, replaces it.
write_busy_shim() {
    local shim="${BIN_DIR}/.defenseclaw.busy"
    mkdir -p "${BIN_DIR}" 2>/dev/null || return 0
    if cat > "${shim}" 2>/dev/null <<EOF
#!/bin/sh
${BUSY_SHIM_MARK} (pid $$).
if kill -0 $$ 2>/dev/null; then
    echo "defenseclaw: a DefenseClaw install is running (pid $$); run the command again when it has finished" >&2
else
    echo "defenseclaw: a DefenseClaw install (pid $$) stopped before it finished; run the installer again to finish or undo it: ${INSTALL_AGAIN:-the install command}" >&2
fi
exit 1
EOF
    then
        chmod 755 "${shim}" && mv -f "${shim}" "${BIN_DIR}/defenseclaw" && return 0
    fi
    rm -f "${shim}"
    return 0
}

# restore_links SLOT: put back the CLI links SLOT saved, over the busy shim.
restore_links() {
    local link
    for link in ${MANAGED_LINKS}; do
        if [[ -L "$1/bin/${link}" ]]; then
            rm -f "${BIN_DIR:?}/${link}" && cp -P "$1/bin/${link}" "${BIN_DIR}/${link}" || true
        elif [[ -f "${BIN_DIR}/${link}" && ! -L "${BIN_DIR}/${link}" ]] \
            && [[ "$(head -n 2 "${BIN_DIR}/${link}" 2>/dev/null)" == *"${BUSY_SHIM_MARK}"* ]]; then
            rm -f "${BIN_DIR:?}/${link}"
        fi
    done
    return 0
}

# private_bin_dir: drop group and other write from BIN_DIR and its parent when
# this account owns them. DefenseClaw refuses to run a gateway from a folder
# another account could change, and a user-private-group umask (002, the
# Debian and Ubuntu default) leaves ~/.local/bin group-writable when another
# installer created it: install and init succeeded, then every later command
# refused, naming one folder per run.
private_bin_dir() {
    local dir mode
    for dir in "${BIN_DIR%/*}" "${BIN_DIR}"; do
        [[ -d "${dir}" && ! -L "${dir}" && -O "${dir}" ]] || continue
        mode="$(stat -c %a "${dir}" 2>/dev/null || stat -f %Lp "${dir}" 2>/dev/null)" || continue
        [[ "${mode}" =~ ^[0-7]+$ ]] && (( 8#${mode} & 8#022 )) || continue
        chmod go-w "${dir}" && info "Removed group and other write access from ${dir}: the gateway does not run from a folder other accounts can change"
    done
    return 0
}

fleet_config_enabled() {
    local config="${DEFENSECLAW_CONFIG:-${DEFENSECLAW_HOME}/config.yaml}"
    [[ -f "${config}" ]] || return 1
    "${VENV}/bin/python" -I - "${config}" <<'PY'
import sys
import yaml

try:
    with open(sys.argv[1], encoding="utf-8") as stream:
        config = yaml.safe_load(stream)
    enabled = isinstance(config, dict) and isinstance(config.get("fleet"), dict) and config["fleet"].get("enabled") is True
except (OSError, yaml.YAMLError):
    enabled = False
sys.exit(0 if enabled else 1)
PY
}

swap_in() {
    local binary link target
    info "Installing DefenseClaw ${VERSION}"
    make_venv "${VENV}" || return 1
    # Fleet is opt-in. A core install never requires or installs its compiler;
    # an enabled fleet gets the matching version inside the rollback snapshot.
    if fleet_config_enabled; then
        [[ -f "${STAGING}/bin/edge-connector/tools/policy_compiler.py" ]] || {
            warn "Fleet is enabled but this release has no Fleet policy compiler"
            return 1
        }
        mkdir -p "${INSTALLER_DIR}" || return 1
        cp "${STAGING}/bin/edge-connector/tools/policy_compiler.py" \
            "${INSTALLER_DIR}/.policy_compiler.py.new" \
            && chmod 600 "${INSTALLER_DIR}/.policy_compiler.py.new" \
            && mv -f "${INSTALLER_DIR}/.policy_compiler.py.new" \
                "${INSTALLER_DIR}/policy_compiler.py" || return 1
    fi
    mkdir -p "${BIN_DIR}" || return 1
    private_bin_dir
    for binary in ${MANAGED_BINARIES}; do
        [[ -f "${STAGING}/bin/${binary}" ]] || continue
        cp -p "${STAGING}/bin/${binary}" "${BIN_DIR}/.${binary}.new" \
            && mv -f "${BIN_DIR}/.${binary}.new" "${BIN_DIR}/${binary}" || return 1
    done
    # Older installers do not know the hook transport's binary name when a
    # rollback later rolls forward. Their swap preserves installer/ as one
    # directory, so keep a version-matched recovery copy there.
    mkdir -p "${INSTALLER_DIR}" \
        && cp -p "${STAGING}/bin/defenseclaw-hook-post" "${INSTALLER_DIR}/.defenseclaw-hook-post.new" \
        && chmod 700 "${INSTALLER_DIR}/.defenseclaw-hook-post.new" \
        && mv -f "${INSTALLER_DIR}/.defenseclaw-hook-post.new" "${INSTALLER_DIR}/defenseclaw-hook-post" \
        && record_binaries || return 1
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
        note_retired_connectors
        local args=(migrate)
        [[ -n "${PREV_VERSION}" ]] && args+=(--from-version "${PREV_VERSION}")
        DEFENSECLAW_GATEWAY_BIN="${BIN_DIR}/defenseclaw-gateway" "${VENV}/bin/defenseclaw" "${args[@]}" || return 1
        # GAP-0483: a rollback by an earlier release left the sandbox setup
        # made after its upgrade only in previous/, which this upgrade parks
        # in backups/; bring it back unless this install has one of its own.
        local rolled
        rolled="$(cat "${PREVIOUS}/VERSION" 2>/dev/null || true)"
        if [[ -f "${PREVIOUS}/ROLLED_BACK" ]] && sandbox_state_carries "${rolled}" "${VERSION}" && ! version_lt "${VERSION}" "${rolled}"; then
            carry_sandbox_state "${PREVIOUS}" if-unset "${BIN_DIR}/defenseclaw-gateway"
        fi
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
        # A rollback by an earlier release left hook entries of a connector
        # this install does not configure (GAP-0009). Best effort.
        prune_orphaned_hooks "${BIN_DIR}/defenseclaw-gateway"
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
    local failed="" binary link name dest kept=true restored=true moved free_mb keep_stopped=false
    [[ ! -e "${SNAP}/GATEWAY_RESTART_UNPROVEN" ]] || keep_stopped=true
    # A restore that stops part-way (a full disk) keeps the snapshot, and the
    # next run finishes it from what this one recorded there: FAILED_DIR names
    # the folder that keeps the failed install, VENV_BACK and DATA_ASIDE mark
    # the steps that are done. Running a done step again set the data it had
    # put back aside as the failed install and put nothing back, so
    # config.yaml, .env and the policies were left only in .failed-<time> and
    # the upgrade started from no configuration (GAP-0624).
    [[ -f "${SNAP}/FAILED_DIR" ]] && failed="$(cat "${SNAP}/FAILED_DIR" 2>/dev/null || true)"
    if [[ -z "${failed}" || ! -d "${failed}/data" ]]; then
        # Only the latest failed install is kept: with a large audit database
        # each copy holds gigabytes, and an earlier one is not used again.
        for failed in "${DEFENSECLAW_HOME}"/.failed-*; do
            if [[ -d "${failed}" && ! -L "${failed}" ]]; then rm -rf "${failed}" || true; fi
        done
        failed="${DEFENSECLAW_HOME}/.failed-$(date +%Y%m%dT%H%M%S)"
        # Putting the snapshot back only renames; keeping the failed install needs
        # a new folder. On a full disk that mkdir failed and, under set -e, ended
        # the restore before it began: no CLI, no gateway, no word (GAP-0375).
        # Then the failed install is deleted instead, which also frees space.
        mkdir -p "${failed}/data" 2>/dev/null || { kept=false; rm -rf "${failed}" 2>/dev/null || true; }
        [[ "${kept}" != true ]] || printf '%s\n' "${failed}" > "${SNAP}/FAILED_DIR" 2>/dev/null || true
    fi
    if [[ ! -f "${SNAP}/VENV_BACK" ]]; then
        moved=true
        # Record that the snapshot contains an old venv before moving either
        # side. If the final marker cannot be written (or the process stops),
        # the missing snapshot venv then means the live one is already restored.
        if [[ -d "${SNAP}/venv" ]]; then
            : > "${SNAP}/VENV_RESTORING" 2>/dev/null || moved=false
        fi
        if [[ "${moved}" == true && -f "${SNAP}/VENV_RESTORING" && ! -d "${SNAP}/venv" ]]; then
            [[ -d "${VENV}" ]] || moved=false
        elif [[ "${moved}" == true ]]; then
            if [[ -d "${VENV}" ]]; then
                { [[ "${kept}" == true ]] && mv "${VENV}" "${failed}/venv"; } || rm -rf "${VENV}" || moved=false
            fi
            if [[ "${moved}" == true && -d "${SNAP}/venv" ]]; then mv "${SNAP}/venv" "${VENV}" || moved=false; fi
        fi
        if [[ "${moved}" == true ]]; then
            : > "${SNAP}/VENV_BACK" 2>/dev/null || restored=false
        else
            restored=false
        fi
    fi
    for binary in ${MANAGED_BINARIES}; do
        if [[ -f "${SNAP}/bin/${binary}" ]]; then
            { cp -p "${SNAP}/bin/${binary}" "${BIN_DIR}/.${binary}.old" && mv -f "${BIN_DIR}/.${binary}.old" "${BIN_DIR}/${binary}"; } \
                || { rm -f "${BIN_DIR}/.${binary}.old"; restored=false; }
        else
            rm -f "${BIN_DIR:?}/${binary}" || restored=false
        fi
    done
    for link in ${MANAGED_LINKS}; do
        rm -f "${BIN_DIR:?}/${link}" || restored=false
        if [[ -L "${SNAP}/bin/${link}" ]]; then cp -P "${SNAP}/bin/${link}" "${BIN_DIR}/${link}" || restored=false; fi
    done
    # INSTALLER_BACK marks the installer as put back, as VENV_BACK does the
    # venv: a second run deleted the installer the first had restored (GAP-0922).
    if [[ ! -f "${SNAP}/INSTALLER_BACK" ]]; then
        moved=true
        if [[ -d "${SNAP}/installer" ]]; then
            : > "${SNAP}/INSTALLER_RESTORING" 2>/dev/null || moved=false
        fi
        if [[ "${moved}" == true && ! ( -f "${SNAP}/INSTALLER_RESTORING" && ! -d "${SNAP}/installer" ) ]]; then
            rm -rf "${INSTALLER_DIR}" || moved=false
            if [[ "${moved}" == true && -d "${SNAP}/installer" ]]; then mv "${SNAP}/installer" "${INSTALLER_DIR}" || moved=false; fi
        fi
        if [[ "${moved}" == true ]]; then : > "${SNAP}/INSTALLER_BACK" 2>/dev/null || restored=false; else restored=false; fi
    fi
    if [[ ! -f "${SNAP}/DATA_ASIDE" ]]; then
        moved=true
        while IFS= read -r name; do
            { [[ "${kept}" == true ]] && mv "${DEFENSECLAW_HOME}/${name}" "${failed}/data/" 2>/dev/null; } \
                || rm -rf "${DEFENSECLAW_HOME:?}/${name}" || moved=false
        done < <(data_entries)
        if [[ "${moved}" == true ]]; then : > "${SNAP}/DATA_ASIDE" 2>/dev/null || true; else restored=false; fi
    fi
    # The saved data goes back only over a data folder the failed install has
    # left; a name made since an interrupted restore goes aside first.
    if [[ -f "${SNAP}/DATA_ASIDE" ]]; then
        for name in "${SNAP}/data"/* "${SNAP}/data"/.[!.]* "${SNAP}/data"/..?*; do
            [[ -e "${name}" || -L "${name}" ]] || continue
            dest="${DEFENSECLAW_HOME}/${name##*/}"
            if [[ -e "${dest}" || -L "${dest}" ]]; then
                { [[ "${kept}" == true ]] && mv "${dest}" "${failed}/data/${name##*/}.after-restore"; } \
                    || rm -rf "${dest}" || { restored=false; continue; }
            fi
            mv "${name}" "${DEFENSECLAW_HOME}/" || restored=false
        done
    else
        restored=false
    fi
    if [[ -n "${APP_PATH}" && -d "${SNAP}/DefenseClawMac.app" ]]; then
        { rm -rf "${APP_PATH}" && mv "${SNAP}/DefenseClawMac.app" "${APP_PATH}"; } || restored=false
    fi
    restore_external_config "${SNAP}" || restored=false
    if [[ "${restored}" != true ]]; then
        # The snapshot stays (with COMPLETE), so the next run puts the rest back first.
        free_mb="$(df -Pk "${DEFENSECLAW_HOME}" 2>/dev/null | awk 'NR==2{print int($4/1024)}')"
        RESTORED_NOTE="Your previous install is NOT back yet: ${SNAP} still holds it."
        err "Could not put ${PREV_VERSION:-the previous install} back completely (see the errors above); ${free_mb:-?} MB is free next to ${DEFENSECLAW_HOME}"
        err "Free some space on that filesystem (df -h ${DEFENSECLAW_HOME}), then run the install command again (${INSTALL_AGAIN:-the same command}): it puts the previous install back before anything else"
        return 0
    fi
    rm -rf "${SNAP}" || true
    restart_old "${keep_stopped}"
    if [[ "${kept}" == true ]]; then
        warn "The failed ${VERSION} install was kept in ${failed} ($(du -sh "${failed}" 2>/dev/null | awk '{print $1}')) for troubleshooting"
        info "Your previous install and its data are back; it is safe to remove the copy with: rm -rf '${failed}'"
    else
        warn "There was no room to keep the failed ${VERSION} install for troubleshooting, so it was deleted"
        info "Your previous install and its data are back"
    fi
}

restart_old() {
    if [[ "${1:-false}" == true ]]; then
        local gateway_command
        printf -v gateway_command '%q' "${BIN_DIR}/defenseclaw-gateway"
        RESTORED_NOTE="Your previous install is back, with its gateway kept stopped to preserve its hook registration."
        warn "${RESTORED_NOTE}"
        info "Resolve the startup error (close the agent if its settings are in use), then run: ${gateway_command} start"
        return 0
    fi
    if [[ "${WAS_RUNNING}" == true ]]; then
        local rc=0
        start_gateway >/dev/null 2>&1 || rc=$?
        [[ ${rc} -ne 0 ]] || return 0
        if [[ ${rc} -eq 3 ]]; then
            # It runs, but does not guard every connector (GAP-0878).
            RESTORED_NOTE="Your previous install is back and its gateway runs, but a connector needs attention before it is guarded again."
            warn "${RESTORED_NOTE}"
            info "See which with: defenseclaw doctor"
            return 0
        fi
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
    local log="${DEFENSECLAW_HOME}/gateway.log" from=0 rc=0 deadline up=0 version delegate="" every=""
    # Each start explains only itself: the explanation of a failed new
    # gateway skipped the wait for the restored one, which was then
    # reported as not running while it came up (GAP-1241).
    START_EXPLAINED=""
    info "Starting the gateway"
    # A 0.8.x start gives up after 60 seconds and stops the gateway it
    # launched, so one restored on a large audit database is stopped before it
    # is ready or can log why it would stop. Its upgrade-controller mode only
    # launches the gateway; the loop below then waits for it.
    version="$("${BIN_DIR}/defenseclaw-gateway" --version 2>/dev/null | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)"
    if [[ -n "${version}" ]] && version_lt "${version}" 1.0.0; then delegate=1; fi
    if [[ -n "${version}" ]] && version_lt "${version}" 1.0.1; then reset_audit_journal_mode; fi
    [[ -f "${log}" ]] && from="$(wc -c < "${log}" | tr -d ' ')"
    # GAP-0878: a gateway that has --require-every-connector exits 3, not 0,
    # when its boot left a configured connector unguarded. An older one (a
    # restored or rolled-back install) refuses the flag, so ask it first.
    if [[ -z "${delegate}" ]] && "${BIN_DIR}/defenseclaw-gateway" start --require-every-connector --help >/dev/null 2>&1; then
        every=--require-every-connector
    fi
    if [[ -n "${delegate}" ]]; then
        PATH="${BIN_DIR}:${PATH}" DEFENSECLAW_UPGRADE_FRESH_PROCESS=1 "${BIN_DIR}/defenseclaw-gateway" start || rc=$?
    else
        PATH="${BIN_DIR}:${PATH}" "${BIN_DIR}/defenseclaw-gateway" start ${every:+"${every}"} || rc=$?
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
            if [[ ${up} -ge 2 ]]; then
                ok "The gateway finished starting"
                # Its start gave up before it could check the connectors.
                [[ -z "${every}" ]] || PATH="${BIN_DIR}:${PATH}" "${BIN_DIR}/defenseclaw-gateway" start "${every}" >/dev/null || return 3
                return 0
            fi
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
            START_DRIFT=1
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
    record_saved_installer
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

# until 1.1: the gateway removes what an older setup wrote for OpenHands and
# OmniGent when it starts, but an upgrade of a stopped gateway does not start
# it. When something of theirs is still here, run that teardown now. It never
# fails and blocks nothing (DefenseClaw no longer guards them); what it cannot
# remove is listed as information below. Without a config nothing was set up.
finish_retired_connector_cleanup() {
    local gateway="${BIN_DIR}/defenseclaw-gateway" name
    [[ -f "${DEFENSECLAW_HOME}/config.yaml" || -n "${DEFENSECLAW_CONFIG:-}" ]] || return 0
    [[ -x "${gateway}" ]] || return 0
    "${VENV}/bin/python" -I -c 'import sys
from defenseclaw.removed_connectors import leftovers
sys.exit(0 if leftovers(sys.argv[1]) else 1)' "${DEFENSECLAW_HOME}" 2>>"${LOG}" || return 0
    for name in openhands omnigent; do
        "${gateway}" connector teardown --connector "${name}" --data-dir "${DEFENSECLAW_HOME}" >>"${LOG}" 2>&1 || true
    done
}

# record_saved_installer: the SHA-256 of the saved installer, which
# 'defenseclaw rollback' checks before it runs that file (GAP-1067). It is
# kept with the data, in receipts/ (a DefenseClaw security-state folder the
# tamper rule watches), so it moves with the install it belongs to on every
# swap.
record_saved_installer() {
    local record="${DEFENSECLAW_HOME}/receipts/installer.sha256"
    rm -f "${record}"
    [[ -f "${INSTALLER_DIR}/install.sh" ]] || return 0
    mkdir -p "${DEFENSECLAW_HOME}/receipts" \
        && printf '%s  install.sh\n' "$(sha256_of "${INSTALLER_DIR}/install.sh")" > "${record}.new" \
        && mv -f "${record}.new" "${record}" \
        || warn "Could not record the digest of the saved installer, so 'defenseclaw rollback' will not run it; record it again with: defenseclaw upgrade --version ${VERSION} --yes"
}

# A gateway that was not running before an upgrade or repair is not started,
# so nothing rendered this release's hooks: a connector kept the hook an
# earlier release wrote (a 1.0.3 Hermes hook cannot answer this release's
# execution probe) and the install exited 0 with it unprotected. The new
# gateway puts every connector the config guards on its current hook and
# reads each back; one it cannot is named with the cause, and the install
# exits 3. Without a config nothing was set up. An older gateway (a
# downgrade) has no --every-connector and renders its hooks when it starts.
reconcile_stopped_connectors() {
    local gateway="${BIN_DIR}/defenseclaw-gateway" out rc=0 why
    [[ -f "${DEFENSECLAW_HOME}/config.yaml" || -n "${DEFENSECLAW_CONFIG:-}" ]] || return 0
    if [[ ! -x "${gateway}" ]]; then
        err "DefenseClaw ${VERSION} could not put the connectors on their current hooks: ${gateway} is missing"
        return 1
    fi
    "${gateway}" connector reconcile --every-connector --help >/dev/null 2>&1 || return 0
    out="$(DEFENSECLAW_CONFIG="${DEFENSECLAW_CONFIG:-${DEFENSECLAW_HOME}/config.yaml}" \
        "${gateway}" connector reconcile --every-connector --data-dir "${DEFENSECLAW_HOME}" 2>&1)" || rc=$?
    printf '%s\n' "${out}" >>"${LOG}"
    [[ ${rc} -ne 0 ]] || return 0
    why="$(printf '%s\n' "${out}" | sed -n 's/^Error: //p' | tail -n 1)"
    err "DefenseClaw ${VERSION} could not put every connector on its current hook while the gateway is stopped: ${why:-exit ${rc}, see ${LOG}}"
    return 1
}

# until 1.1: whether an older setup of OpenHands or OmniGent is here, asked
# before the migration and the new gateway's first start remove it, so the
# one removal notice is printed after the upgrade (GAP-1892).
RETIRED_CONNECTORS_FOUND=0
note_retired_connectors() {
    [[ -n "${PREV_VERSION:-}" ]] || return 0
    if "${VENV}/bin/python" -I -c 'import sys
from defenseclaw.removed_connectors import found
sys.exit(0 if found(sys.argv[1]) else 1)' "${DEFENSECLAW_HOME}" 2>>"${LOG}"; then
        RETIRED_CONNECTORS_FOUND=1
    fi
    return 0
}

# until 1.1: the one removal notice when an older setup of OpenHands or
# OmniGent was here, then what their teardown could not remove; the
# gateway's daemon log is not the installer's output.
report_retired_connector_leftovers() {
    local notes
    if ! notes="$("${VENV}/bin/python" -I - "${DEFENSECLAW_HOME}" "${RETIRED_CONNECTORS_FOUND:-0}" <<'PY'
import sys
from defenseclaw.removed_connectors import installer_lines

for line in installer_lines(sys.argv[1], sys.argv[2] == "1"):
    print(line)
PY
)"; then
        warn "Could not check removed connector leftovers; run 'defenseclaw status' for manual cleanup steps"
        return 0
    fi
    [[ -z "${notes}" ]] || printf '\n%s\n' "${notes}"
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
    write_busy_shim
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
            restore_links "${hold}"
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

# GAP-1388: check_rollback_data runs SQLite's integrity check on each database
# in previous/data before a rollback to 0.x, which has no recovery for a
# damaged audit store, and prints the damaged ones. Nothing is written beside
# them: opening a store that has a -wal or -journal, even read-only, writes
# there, so such a store is checked on a copy. install.ps1 runs the same code.
ROLLBACK_DB_CHECK_PY='import os, shutil, sqlite3, sys, tempfile
from pathlib import Path


def damaged(path):
    logs = [suffix for suffix in ("-wal", "-journal") if os.path.exists(path + suffix)]
    with tempfile.TemporaryDirectory() as tmp:
        uri = Path(os.path.abspath(path)).as_uri() + "?immutable=1"
        if logs:
            copy = os.path.join(tmp, "check.db")
            for suffix in ["", *logs]:
                shutil.copyfile(path + suffix, copy + suffix)
            uri = Path(copy).as_uri()
        try:
            conn = sqlite3.connect(uri, uri=True)
            try:
                result = conn.execute("pragma integrity_check(1)").fetchone()[0]
            finally:
                conn.close()
        except sqlite3.DatabaseError as exc:
            result = str(exc)
            if "malformed" not in result and "not a database" not in result:
                return False
    if result != "ok":
        print(path + ": " + " ".join(result.split()), file=sys.stderr)
    return result != "ok"


for path in sys.argv[1:]:
    try:
        bad = os.path.isfile(path) and not os.path.islink(path) and damaged(path)
    except OSError:
        bad = False
    if bad:
        print(path)
'

check_rollback_data() {
    local python="${VENV}/bin/python" db
    [[ -x "${python}" && -d "${PREVIOUS}/data" ]] || return 0
    while IFS= read -r db; do
        if [[ "${db}" == "${PREVIOUS}/data/audit.db" ]]; then
            AUDIT_DAMAGED=1
        elif [[ -n "${db}" ]]; then
            warn "The saved database ${db} of DefenseClaw ${back_to} failed SQLite's integrity check; ${back_to} may not start with it (see ${LOG})"
        fi
    done < <("${python}" -I -c "${ROLLBACK_DB_CHECK_PY}" "${PREVIOUS}"/data/*.db 2>>"${LOG}" || true)
}

# move_audit_store FROM TO: move an SQLite store with its -wal, -shm and
# -journal as one unit. A move that fails (or would replace a file) puts back
# what moved and returns 1, so a store is never separated from its WAL (SQLite
# would drop the WAL's transactions; GAP-1397, rel-1-0-2:GAP-0491).
move_audit_store() {
    local from=$1 to=$2 suffix moved_suffixes=()
    for suffix in "" -wal -shm -journal; do
        [[ -e "${from}${suffix}" ]] || continue
        if [[ ! -e "${to}${suffix}" ]] && mv "${from}${suffix}" "${to}${suffix}"; then
            moved_suffixes=("${suffix}" ${moved_suffixes[@]+"${moved_suffixes[@]}"})
            continue
        fi
        for suffix in ${moved_suffixes[@]+"${moved_suffixes[@]}"}; do
            mv "${to}${suffix}" "${from}${suffix}" || warn "Could not move ${to}${suffix} back to ${from}${suffix}"
        done
        return 1
    done
}

# quarantine_rolled_back_audit: after the swap, move the damaged audit store
# aside under the name the 1.0 gateway and doctor use (audit.db.corrupt-<UTC
# time>), so the restored release starts on a new one.
quarantine_rolled_back_audit() {
    local db="${DEFENSECLAW_HOME}/audit.db" moved
    [[ -f "${db}" ]] || return 0
    moved="${db}.corrupt-$(date -u +%Y%m%dT%H%M%SZ)"
    [[ ! -e "${moved}" ]] || moved="${moved}-$$"
    move_audit_store "${db}" "${moved}" || return 1
    QUARANTINED="${moved}"
    warn "The saved ${back_to} audit store failed SQLite's integrity check; it was kept as ${moved} and ${back_to} starts on a new audit store (its block/allow entries are not carried over; check them with defenseclaw mcp, skill, plugin and tool list)"
}

# undo_rollback REASON: put back the install the rollback replaced, and exit 1
# (GAP-1388). The restored 0.x gateway is not running, and the connector
# registrations of this install were removed for it: agents would be unguarded.
undo_rollback() {
    local left="${current}" undone=0 kept fresh audit="${PREVIOUS}/data/audit.db"
    warn "$1, so the rollback is being undone"
    stop_gateway "${BIN_DIR}/defenseclaw-gateway" || true
    # The same swap the other way: previous/ holds the install just left.
    current="${back_to}" was_running=false restart=true
    swap_with_previous || undone=$?
    current="${left}"
    if [[ ${undone} -ne 0 ]]; then
        err "DefenseClaw ${back_to} is installed, but its gateway is not running, so agent hooks are not guarded"
        [[ ${undone} -ne 1 ]] || info "To return to ${current:-1.x}, run: bash ${PREVIOUS}/installer/install.sh --rollback"
        exit 1
    fi
    # previous/ is again the install this rollback started from, as it was.
    rm -f "${PREVIOUS}/ROLLED_BACK" "${PREVIOUS}/START_AFTER"
    printf '%s\n' "${saved_was_running:-false}" > "${PREVIOUS}/GATEWAY_WAS_RUNNING"
    kept="${PREVIOUS}/data/$(basename "${QUARANTINED:-none}")"
    if [[ -n "${QUARANTINED}" && -f "${kept}" ]]; then
        # GAP-1398: the failed start of ${back_to} made a new, empty audit.db
        # here, which a later rollback then used without a word. It goes
        # aside, and the saved store goes back with its WAL (each as one unit,
        # rel-1-0-2:GAP-0492), so that rollback checks it again.
        if [[ -e "${audit}" ]]; then
            fresh="${audit}.failed-start-$(date -u +%Y%m%dT%H%M%SZ)"
            [[ ! -e "${fresh}" ]] || fresh="${fresh}-$$"
            move_audit_store "${audit}" "${fresh}" || warn "Could not move aside the new audit store the failed start of ${back_to} made"
        fi
        if [[ ! -e "${audit}" ]]; then
            move_audit_store "${kept}" "${audit}" || warn "Could not put back the saved ${back_to} audit store"
        fi
        if [[ -e "${kept}" ]]; then
            warn "The saved ${back_to} audit store is still ${kept}; before 'defenseclaw rollback' again, move it and its -wal and -shm files to ${audit}"
        fi
    fi
    if start_gateway; then
        ok "DefenseClaw ${current:-1.x} is back, with its gateway and agent hooks"
    else
        warn_not_started
        warn "DefenseClaw ${current:-1.x} is back, but it registers its agent hooks again only once its gateway runs"
    fi
    # Paths in the older release's errors above now hold this install's files.
    info "The files of DefenseClaw ${back_to} are in ${PREVIOUS}/data again; fix them there (paths above under ${DEFENSECLAW_HOME} named them)"
    if [[ -n "${START_DRIFT:-}" ]]; then
        info "To roll back anyway and accept the new agent version, run: DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT=1 defenseclaw rollback"
    else
        info "Fix the cause above, then run 'defenseclaw rollback' again (log: ${LOG})"
    fi
    exit 1
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
# A hook entry this install wrote in a shape the older release does not
# recognise (a Claude Code hook script path quoted for a home with a space,
# GAP-1284) outlived that release's uninstall. This install's gateway rewrites
# those entries in the shape the older release removes; rolling forward runs
# setup, which writes the current shape again.
convert_hooks_for_rollback() {
    local gateway="${BIN_DIR}/defenseclaw-gateway"
    [[ -x "${gateway}" ]] || return 0
    "${gateway}" connector prepare-rollback --data-dir "${DEFENSECLAW_HOME}" 2>>"${LOG}" \
        || warn "Could not rewrite the agent hook entries of DefenseClaw ${current:-?} in the form ${back_to} reads (see ${LOG}); after the rollback, 'defenseclaw uninstall' may leave those DefenseClaw entries in the agent settings, such as ~/.claude/settings.json; remove them by hand"
}

# prune_orphaned_hooks GATEWAY...: with the first GATEWAY that has the
# command, remove the DefenseClaw hook entries of every connector the live
# install does not configure (GAP-0009). Only DefenseClaw-owned entries go;
# it says which.
prune_orphaned_hooks() {
    local gateway
    for gateway in "$@"; do
        # An older gateway prints the connector help for an unknown subcommand.
        [[ -x "${gateway}" ]] && "${gateway}" connector prune-orphans --help 2>/dev/null | grep "connector prune-orphans" >/dev/null || continue
        "${gateway}" connector prune-orphans --data-dir "${DEFENSECLAW_HOME}" 2>>"${LOG}" \
            || warn "Could not remove the DefenseClaw hook entries of connectors that are not configured (see ${LOG}); 'defenseclaw doctor' lists them"
        return 0
    done
    return 0
}

# carry_sandbox_state SLOT MODE GATEWAY...: copy the sandbox setup (the
# openshell: settings and the sandboxes, snapshots and shadows folders) of the
# install in SLOT (previous/) into the live one, with the first GATEWAY that
# has the command. Sandboxes keep running across a swap; the install a
# rollback brought back had sandboxes off and none of their hook bindings, so
# every hook of a running sandbox failed closed until the user set sandboxes
# up again, also after the next upgrade (GAP-0483). MODE if-unset leaves an
# install that has a sandbox setup of its own. SLOT keeps its copy, for a roll
# forward by an installer that carries nothing. Best effort.
carry_sandbox_state() {
    local slot="$1" mode="$2" gateway out from_config
    shift 2
    case "${DEFENSECLAW_CONFIG:-}" in
        "") from_config="${slot}/data/config.yaml" ;;
        "${DEFENSECLAW_HOME}"/*) from_config="${slot}/data/${DEFENSECLAW_CONFIG#"${DEFENSECLAW_HOME}"/}" ;;
        *) from_config="${slot}/external-config.yaml" ;;
    esac
    [[ -d "${slot}/data" && -f "${from_config}" ]] || return 0
    local args=(sandbox carry-state --from-data "${slot}/data" --from-config "${from_config}"
        --data-dir "${DEFENSECLAW_HOME}" --config "${DEFENSECLAW_CONFIG:-${DEFENSECLAW_HOME}/config.yaml}")
    [[ "${mode}" != if-unset ]] || args+=(--only-if-unset)
    for gateway in "$@"; do
        # An older gateway prints the sandbox help for an unknown subcommand.
        [[ -x "${gateway}" ]] || continue
        "${gateway}" sandbox carry-state --help 2>/dev/null | grep "sandbox carry-state" >/dev/null || continue
        if out="$("${gateway}" "${args[@]}" 2>>"${LOG}")"; then
            [[ -z "${out}" ]] || info "${out}"
        else
            warn "Could not keep the sandbox setup of the install just replaced (see ${LOG}); a sandbox still running from it stays blocked until you return to that install ('defenseclaw rollback') or delete the sandbox and run it again"
        fi
        return 0
    done
    return 0
}

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
    # A rollback that fails from here on starts this install's gateway again,
    # which writes them back from active_connector.json.
    LEGACY_TORN_DOWN=1
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

# connector_choice ANSWER: the connector a list number or a name selects.
connector_choice() {
    local answer index=1 name
    answer="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')"
    for name in ${CONNECTOR_CHOICES}; do
        if [[ "${answer}" == "${index}" || "${answer}" == "${name}" ]]; then
            printf '%s' "${name}"
            return 0
        fi
        index=$((index + 1))
    done
    return 1
}

pick_connector() {
    step "Pick an agent to guard"
    local index=1 name choice tries=0
    for name in ${CONNECTOR_CHOICES}; do
        printf "    ${BOLD}%2d)${NC} %s\n" "${index}" "${name}"
        index=$((index + 1))
    done
    index=$((index - 1))
    # An answer that is neither a number on the list nor a name is asked
    # again, never replaced with another agent (GAP-0333).
    while :; do
        printf "  Choice (number or name) [default none]: " >&2
        # Enter, or no terminal to answer on: no agent. A default never picks
        # one the machine may not have; 'defenseclaw init' finds the installed
        # agents (GAP-0568).
        choice=$(read_tty_line) || choice=""
        CONNECTOR="$(connector_choice "${choice:-none}")" && break
        tries=$((tries + 1))
        if [[ ${tries} -ge 3 ]]; then
            rm -rf "${STAGING}"
            drop_new_uv
            usage_error "No agent picked ('${choice}' is not on the list). Run the installer again and pick one, or pass --connector NAME"
        fi
        warn "'${choice}' is not on the list: type a number from 1 to ${index} or an agent name such as claudecode"
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
            local args=(quickstart --connector "${CONNECTOR}")
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
    local quoted_bin="${BIN_DIR//\\/\\\\}" quoted_rc
    quoted_bin="${quoted_bin//\"/\\\"}"
    quoted_bin="${quoted_bin//\$/\\\$}"
    quoted_bin="${quoted_bin//\`/\\\`}"
    quoted_rc="${rc//\'/\'\\\'\'}"
    printf "\n  Add DefenseClaw to your PATH (then open a new shell):\n"
    printf "    ${CYAN}echo 'export PATH=\"%s:\$PATH\"' >> '%s'${NC}\n" "${quoted_bin}" "${quoted_rc}"
}

main "$@"
# DefenseClaw POSIX installer complete v2
