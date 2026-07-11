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
# DefenseClaw Installer
#
# Installs DefenseClaw from pre-built release artifacts.
# No Go, Node.js, or git required — only Python and uv.
#
#   # From GitHub release:
#   VERSION=0.8.4
#   INSTALL_URL="https://raw.githubusercontent.com/cisco-ai-defense/defenseclaw/${VERSION}/scripts/install.sh"
#   curl -LsSf "$INSTALL_URL" | VERSION="$VERSION" bash
#
#   # From local dist/ directory (for testing):
#   ./scripts/install.sh --local ./dist
#
#   # Pick a specific agent connector at install time:
#   curl ... | bash -s -- --connector codex          # Codex (no OpenClaw install)
#   curl ... | bash -s -- --connector openclaw       # OpenClaw + plugin/runtime
#   curl ... | bash -s -- --no-openclaw              # Skip OpenClaw entirely
#
# Options:
#   --connector <name>  Pick agent connector (see --help for choices)
#   --no-openclaw       Skip OpenClaw install (alias for --connector none when used alone)
#   --local <dir>       Install from a local dist directory instead of downloading
#   --yes, -y           Skip confirmation prompts (for CI/automation)
#   --help, -h          Show help
#
set -euo pipefail

# Installation material includes credentials, device keys, policy state, and a
# private Python environment. Do not let an operator's permissive login umask
# make newly-created DefenseClaw directories or transient files group/world
# accessible; explicit wider modes are still applied where intentionally needed.
umask 077

# Entire script wrapped in main() so bash parses everything before executing.
# Critical for curl|sh safety — prevents partial execution on network drops.
main() {

# ── Configuration ─────────────────────────────────────────────────────────────

readonly DEFENSECLAW_HOME="${DEFENSECLAW_HOME:-${HOME}/.defenseclaw}"
readonly DEFENSECLAW_VENV="${DEFENSECLAW_HOME}/.venv"
readonly INSTALL_DIR="${HOME}/.local/bin"
readonly REPO="cisco-ai-defense/defenseclaw"
readonly OPENCLAW_VERSION="2026.3.24"
VERIFIED_CHECKSUM=""

# Supported connectors. Keep in sync with cli/defenseclaw/connector_paths.py
# KNOWN_CONNECTORS. The "none" pseudo-value means "lay binaries only — pick
# a connector later with `defenseclaw init --connector ...`".
readonly CONNECTOR_CHOICES=(codex claudecode zeptoclaw openclaw hermes cursor windsurf geminicli copilot openhands antigravity opencode omnigent none)

# ── Terminal Formatting ───────────────────────────────────────────────────────

if [[ -t 1 ]] || [[ "${FORCE_COLOR:-}" == "1" ]]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
    BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'
    DIM='\033[2m'; NC='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; BLUE=''; CYAN=''; BOLD=''; DIM=''; NC=''
fi

# ── Logging ───────────────────────────────────────────────────────────────────

info()  { printf "${BLUE}  ▸${NC} %s\n" "$*"; }
ok()    { printf "${GREEN}  ✓${NC} %s\n" "$*"; }
warn()  { printf "${YELLOW}  !${NC} %s\n" "$*"; }
err()   { printf "${RED}  ✗${NC} %s\n" "$*" >&2; }
step()  { printf "\n${BOLD}${CYAN}─── %s${NC}\n" "$*"; }

die() { err "$@"; exit 1; }

# ── Utilities ─────────────────────────────────────────────────────────────────

has() { command -v "$1" &>/dev/null; }

# Return a device/inode pair without following a symlink. The two stat forms
# cover BSD/macOS and GNU/Linux respectively. Identity checks keep failure
# cleanup from removing a path that another process substituted mid-install.
path_identity() {
    local value="" platform_name="${OS:-}"
    if [[ -z "${platform_name}" ]]; then
        platform_name="$(uname -s 2>/dev/null | tr '[:upper:]' '[:lower:]')"
    fi
    case "${platform_name}" in
        linux) value="$(stat -c '%d:%i' "$1" 2>/dev/null || true)" ;;
        darwin) value="$(stat -f '%d:%i' "$1" 2>/dev/null || true)" ;;
        *) return 1 ;;
    esac
    [[ "${value}" =~ ^[0-9]+:[0-9]+$ ]] || return 1
    printf '%s\n' "${value}"
}

path_has_identity() {
    local path="$1" expected="$2" allow_symlink="${3:-false}" actual
    [[ -n "${expected}" ]] || return 1
    [[ "${allow_symlink}" == true || ! -L "${path}" ]] || return 1
    actual="$(path_identity "${path}")" || return 1
    [[ "${actual}" == "${expected}" ]]
}

cleanup_install_attempt() {
    local status=$?
    set +e

    if [[ "${INSTALL_SUCCEEDED:-false}" != true ]]; then
        if [[ -n "${CLI_PUBLISHED_ID:-}" ]]; then
            if [[ "${MODERN_RELEASE:-false}" == true \
                && -n "${PUBLISH_HELPER:-}" && -f "${PUBLISH_HELPER}" ]]; then
                "${POLICY_PYTHON}" "${PUBLISH_HELPER}" unlink-exact \
                    "${INSTALL_DIR}/defenseclaw" \
                    "${CLI_PUBLISHED_ID%%:*}" "${CLI_PUBLISHED_ID#*:}" || true
            elif path_has_identity \
                "${INSTALL_DIR}/defenseclaw" "${CLI_PUBLISHED_ID}" true; then
                rm -f "${INSTALL_DIR}/defenseclaw"
            fi
        fi
        if [[ -n "${GATEWAY_ROLLBACK_TOKEN:-}" \
            && -n "${PUBLISH_HELPER:-}" && -f "${PUBLISH_HELPER}" ]]; then
            "${POLICY_PYTHON}" "${PUBLISH_HELPER}" rollback-token \
                "${GATEWAY_ROLLBACK_TOKEN}" || true
        fi
        if [[ -n "${GATEWAY_PUBLISHED_ID:-}" ]] \
            && path_has_identity \
                "${INSTALL_DIR}/defenseclaw-gateway" \
                "${GATEWAY_PUBLISHED_ID}"; then
            rm -f "${INSTALL_DIR}/defenseclaw-gateway"
        fi
        if [[ -n "${GATEWAY_ACTIVATION:-}" ]] \
            && path_has_identity \
                "${GATEWAY_ACTIVATION}" "${GATEWAY_ACTIVATION_ID:-}"; then
            rm -f "${GATEWAY_ACTIVATION}"
        fi
        if [[ -n "${VENV_CLAIM_ID:-}" ]]; then
            if [[ "${MODERN_RELEASE:-false}" == true \
                && -n "${PUBLISH_HELPER:-}" && -f "${PUBLISH_HELPER}" ]]; then
                "${POLICY_PYTHON}" "${PUBLISH_HELPER}" remove-tree-exact \
                    "${DEFENSECLAW_VENV}" \
                    "${VENV_CLAIM_ID%%:*}" "${VENV_CLAIM_ID#*:}" || true
            elif path_has_identity "${DEFENSECLAW_VENV}" "${VENV_CLAIM_ID}"; then
                rm -rf "${DEFENSECLAW_VENV}"
            fi
        fi
        if [[ -n "${CONNECTOR_MARKER_ROLLBACK_TOKEN:-}" \
            && -n "${PUBLISH_HELPER:-}" && -f "${PUBLISH_HELPER}" ]]; then
            "${POLICY_PYTHON}" "${PUBLISH_HELPER}" rollback-token \
                "${CONNECTOR_MARKER_ROLLBACK_TOKEN}" || true
        elif [[ -n "${CONNECTOR_MARKER_ID:-}" ]]; then
            if [[ "${MODERN_RELEASE:-false}" == true \
                && -n "${PUBLISH_HELPER:-}" && -f "${PUBLISH_HELPER}" ]]; then
                "${POLICY_PYTHON}" "${PUBLISH_HELPER}" unlink-exact \
                    "${DEFENSECLAW_HOME}/picked_connector" \
                    "${CONNECTOR_MARKER_ID%%:*}" \
                    "${CONNECTOR_MARKER_ID#*:}" || true
            elif path_has_identity \
                "${DEFENSECLAW_HOME}/picked_connector" \
                "${CONNECTOR_MARKER_ID}"; then
                rm -f "${DEFENSECLAW_HOME}/picked_connector"
            fi
        fi
        if [[ -n "${PICKED_CONNECTOR_ACTIVATION:-}" ]] \
            && path_has_identity \
                "${PICKED_CONNECTOR_ACTIVATION}" \
                "${PICKED_CONNECTOR_ACTIVATION_ID:-}"; then
            rm -f "${PICKED_CONNECTOR_ACTIVATION}"
        fi
        if [[ -n "${PLUGIN_CLAIM_ID:-}" ]]; then
            if [[ "${MODERN_RELEASE:-false}" == true \
                && -n "${PUBLISH_HELPER:-}" && -f "${PUBLISH_HELPER}" ]]; then
                "${POLICY_PYTHON}" "${PUBLISH_HELPER}" remove-tree-exact \
                    "${DEFENSECLAW_HOME}/extensions/defenseclaw" \
                    "${PLUGIN_CLAIM_ID%%:*}" "${PLUGIN_CLAIM_ID#*:}" || true
            elif path_has_identity \
                "${DEFENSECLAW_HOME}/extensions/defenseclaw" \
                "${PLUGIN_CLAIM_ID}"; then
                rm -rf "${DEFENSECLAW_HOME}/extensions/defenseclaw"
            fi
        fi
        if [[ -n "${EXTENSIONS_CLAIM_ID:-}" ]]; then
            if [[ "${MODERN_RELEASE:-false}" == true \
                && -n "${PUBLISH_HELPER:-}" && -f "${PUBLISH_HELPER}" ]]; then
                "${POLICY_PYTHON}" "${PUBLISH_HELPER}" rmdir-exact \
                    "${DEFENSECLAW_HOME}/extensions" \
                    "${EXTENSIONS_CLAIM_ID%%:*}" \
                    "${EXTENSIONS_CLAIM_ID#*:}" || true
            elif path_has_identity \
                "${DEFENSECLAW_HOME}/extensions" "${EXTENSIONS_CLAIM_ID}"; then
                rmdir "${DEFENSECLAW_HOME}/extensions" 2>/dev/null || true
            fi
        fi
        if [[ -n "${HOME_CLAIM_ID:-}" ]]; then
            if [[ "${MODERN_RELEASE:-false}" == true \
                && -n "${PUBLISH_HELPER:-}" && -f "${PUBLISH_HELPER}" ]]; then
                "${POLICY_PYTHON}" "${PUBLISH_HELPER}" rmdir-exact \
                    "${DEFENSECLAW_HOME}" \
                    "${HOME_CLAIM_ID%%:*}" "${HOME_CLAIM_ID#*:}" || true
            elif path_has_identity "${DEFENSECLAW_HOME}" "${HOME_CLAIM_ID}"; then
                rmdir "${DEFENSECLAW_HOME}" 2>/dev/null || true
            fi
        fi
        if [[ -n "${INSTALL_DIR_CLAIM_ID:-}" ]]; then
            if [[ "${MODERN_RELEASE:-false}" == true \
                && -n "${PUBLISH_HELPER:-}" && -f "${PUBLISH_HELPER}" ]]; then
                "${POLICY_PYTHON}" "${PUBLISH_HELPER}" rmdir-exact \
                    "${INSTALL_DIR}" \
                    "${INSTALL_DIR_CLAIM_ID%%:*}" "${INSTALL_DIR_CLAIM_ID#*:}" || true
            elif path_has_identity "${INSTALL_DIR}" "${INSTALL_DIR_CLAIM_ID}"; then
                rmdir "${INSTALL_DIR}" 2>/dev/null || true
            fi
        fi
        if [[ -n "${LOCAL_BIN_PARENT_CLAIM_ID:-}" ]]; then
            local bin_parent
            bin_parent="$(dirname "${INSTALL_DIR}")"
            if [[ "${MODERN_RELEASE:-false}" == true \
                && -n "${PUBLISH_HELPER:-}" && -f "${PUBLISH_HELPER}" ]]; then
                "${POLICY_PYTHON}" "${PUBLISH_HELPER}" rmdir-exact \
                    "${bin_parent}" \
                    "${LOCAL_BIN_PARENT_CLAIM_ID%%:*}" \
                    "${LOCAL_BIN_PARENT_CLAIM_ID#*:}" || true
            elif path_has_identity "${bin_parent}" "${LOCAL_BIN_PARENT_CLAIM_ID}"; then
                rmdir "${bin_parent}" 2>/dev/null || true
            fi
        fi
    fi

    if [[ -n "${POLICY_DIR:-}" && -n "${POLICY_DIR_ID:-}" ]]; then
        if [[ "${MODERN_RELEASE:-false}" == true \
            && -n "${PUBLISH_HELPER:-}" && -f "${PUBLISH_HELPER}" ]]; then
            "${POLICY_PYTHON}" "${PUBLISH_HELPER}" remove-tree-exact \
                "${POLICY_DIR}" \
                "${POLICY_DIR_ID%%:*}" "${POLICY_DIR_ID#*:}" || true
        elif path_has_identity "${POLICY_DIR}" "${POLICY_DIR_ID}"; then
            rm -rf "${POLICY_DIR}"
        fi
    fi
    return "${status}"
}

claim_fresh_install_home() {
    local home_parent
    home_parent="$(dirname "${DEFENSECLAW_HOME}")"
    if [[ "${MODERN_RELEASE:-false}" == true ]]; then
        "${POLICY_PYTHON}" "${PUBLISH_HELPER}" ensure-real-directory "${home_parent}" \
            || die "Could not bind the fresh-install home parent"
        HOME_CLAIM_ID="$(
            "${POLICY_PYTHON}" "${PUBLISH_HELPER}" fresh-directory "${DEFENSECLAW_HOME}"
        )" || die "A DefenseClaw home appeared during installation; it was preserved and no payload was activated"
        VENV_CLAIM_ID="$(
            "${POLICY_PYTHON}" "${PUBLISH_HELPER}" fresh-directory "${DEFENSECLAW_VENV}"
        )" || die "A DefenseClaw environment appeared during installation; it was preserved and no payload was activated"
    else
        mkdir -p "${home_parent}"
        if ! mkdir "${DEFENSECLAW_HOME}"; then
            die "A DefenseClaw home appeared during installation; it was preserved and no payload was activated"
        fi
        HOME_CLAIM_ID="$(path_identity "${DEFENSECLAW_HOME}")" \
            || die "Could not bind the new DefenseClaw home identity"
        if ! mkdir "${DEFENSECLAW_VENV}"; then
            die "A DefenseClaw environment appeared during installation; it was preserved and no payload was activated"
        fi
        VENV_CLAIM_ID="$(path_identity "${DEFENSECLAW_VENV}")" \
            || die "Could not bind the new DefenseClaw environment identity"
    fi
    [[ "${HOME_CLAIM_ID}" =~ ^[0-9]+:[0-9]+$ \
       && "${VENV_CLAIM_ID}" =~ ^[0-9]+:[0-9]+$ ]] \
        || die "Fresh-install directory custody returned an invalid identity"

    claim_fresh_install_bin_dir
}

claim_fresh_install_bin_dir() {
    local bin_parent
    bin_parent="$(dirname "${INSTALL_DIR}")"

    if [[ -e "${bin_parent}" || -L "${bin_parent}" ]]; then
        if [[ "${MODERN_RELEASE:-false}" == true ]]; then
            "${POLICY_PYTHON}" "${PUBLISH_HELPER}" ensure-real-directory "${bin_parent}" \
                || die "Could not bind the fresh-install binary parent"
        else
            [[ -d "${bin_parent}" && ! -L "${bin_parent}" ]] \
                || die "Fresh-install binary parent is not a real directory"
        fi
    elif [[ "${MODERN_RELEASE:-false}" == true ]]; then
        LOCAL_BIN_PARENT_CLAIM_ID="$(
            "${POLICY_PYTHON}" "${PUBLISH_HELPER}" fresh-directory "${bin_parent}"
        )" || die "A fresh-install binary parent appeared concurrently and was preserved"
    else
        mkdir "${bin_parent}" \
            || die "A fresh-install binary parent appeared concurrently and was preserved"
        LOCAL_BIN_PARENT_CLAIM_ID="$(path_identity "${bin_parent}")" \
            || die "Could not bind the fresh-install binary parent identity"
    fi

    if [[ -e "${INSTALL_DIR}" || -L "${INSTALL_DIR}" ]]; then
        if [[ "${MODERN_RELEASE:-false}" == true ]]; then
            "${POLICY_PYTHON}" "${PUBLISH_HELPER}" ensure-real-directory "${INSTALL_DIR}" \
                || die "Could not bind the fresh-install binary directory"
        else
            [[ -d "${INSTALL_DIR}" && ! -L "${INSTALL_DIR}" ]] \
                || die "Fresh-install binary directory is not a real directory"
        fi
    elif [[ "${MODERN_RELEASE:-false}" == true ]]; then
        INSTALL_DIR_CLAIM_ID="$(
            "${POLICY_PYTHON}" "${PUBLISH_HELPER}" fresh-directory "${INSTALL_DIR}"
        )" || die "A fresh-install binary directory appeared concurrently and was preserved"
    else
        mkdir "${INSTALL_DIR}" \
            || die "A fresh-install binary directory appeared concurrently and was preserved"
        INSTALL_DIR_CLAIM_ID="$(path_identity "${INSTALL_DIR}")" \
            || die "Could not bind the fresh-install binary directory identity"
    fi

    [[ -z "${LOCAL_BIN_PARENT_CLAIM_ID}" \
        || "${LOCAL_BIN_PARENT_CLAIM_ID}" =~ ^[0-9]+:[0-9]+$ ]] \
        || die "Fresh-install binary parent custody returned an invalid identity"
    [[ -z "${INSTALL_DIR_CLAIM_ID}" \
        || "${INSTALL_DIR_CLAIM_ID}" =~ ^[0-9]+:[0-9]+$ ]] \
        || die "Fresh-install binary directory custody returned an invalid identity"
}

complete_install_attempt() {
    if [[ -n "${CONNECTOR_MARKER_ROLLBACK_TOKEN:-}" ]]; then
        "${POLICY_PYTHON}" "${PUBLISH_HELPER}" commit-token \
            "${CONNECTOR_MARKER_ROLLBACK_TOKEN}" \
            || die "Could not close connector marker rollback custody"
        CONNECTOR_MARKER_ROLLBACK_TOKEN=""
    fi
    if [[ -n "${GATEWAY_ROLLBACK_TOKEN:-}" ]]; then
        "${POLICY_PYTHON}" "${PUBLISH_HELPER}" commit-token \
            "${GATEWAY_ROLLBACK_TOKEN}" \
            || die "Could not close fresh gateway rollback custody"
        GATEWAY_ROLLBACK_TOKEN=""
    fi
    if [[ -n "${GATEWAY_ACTIVATION:-}" ]] \
        && path_has_identity \
            "${GATEWAY_ACTIVATION}" "${GATEWAY_ACTIVATION_ID:-}"; then
        rm -f "${GATEWAY_ACTIVATION}"
    fi
    GATEWAY_ACTIVATION=""
    GATEWAY_PRECLAIM_ID=""
    GATEWAY_ACTIVATION_ID=""
    GATEWAY_PUBLISHED_ID=""
    if [[ -n "${PICKED_CONNECTOR_ACTIVATION:-}" ]] \
        && path_has_identity \
            "${PICKED_CONNECTOR_ACTIVATION}" \
            "${PICKED_CONNECTOR_ACTIVATION_ID:-}"; then
        rm -f "${PICKED_CONNECTOR_ACTIVATION}"
    fi
    PICKED_CONNECTOR_ACTIVATION=""
    PICKED_CONNECTOR_ACTIVATION_ID=""
    INSTALL_SUCCEEDED=true
}

version_gte() {
    printf '%s\n%s' "$2" "$1" | sort -V -C
}

extract_version() {
    local input="${1:-}"
    local ver
    ver="$(echo "${input}" | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | awk 'NR==1' || true)"
    echo "${ver:-0.0.0}"
}

ask_yes_no() {
    local prompt="$1" default="${2:-y}"
    if [[ "${YES_MODE}" == true ]]; then
        return 0
    fi
    if [[ "$default" == "y" ]]; then
        prompt="$prompt [Y/n]"
    else
        prompt="$prompt [y/N]"
    fi
    local yn
    printf "  %s " "$prompt" >&2
    read -r yn < /dev/tty 2>/dev/null || yn="$default"
    yn="${yn:-$default}"
    [[ "$yn" =~ ^[Yy]$ ]]
}

wait_for_enter() {
    local prompt="${1:-Press Enter to continue...}"
    if [[ "${YES_MODE}" == true ]]; then
        return 0
    fi
    printf "\n  %s " "$prompt" >&2
    read -r < /dev/tty 2>/dev/null || true
}

detect_shell_rc() {
    case "${SHELL:-/bin/bash}" in
        */zsh)  echo "${HOME}/.zshrc" ;;
        */bash) echo "${HOME}/.bashrc" ;;
        *)      echo "${HOME}/.profile" ;;
    esac
}

# is_valid_connector NAME — returns 0 if NAME is in CONNECTOR_CHOICES.
is_valid_connector() {
    local n="$1" v
    for v in "${CONNECTOR_CHOICES[@]}"; do
        [[ "$v" == "$n" ]] && return 0
    done
    return 1
}

is_hook_connector() {
    local n="$1"
    is_valid_connector "$n" || return 1
    [[ "$n" != "openclaw" && "$n" != "none" ]]
}

connector_display_name() {
    case "$1" in
        codex) echo "Codex" ;;
        claudecode) echo "Claude Code" ;;
        zeptoclaw) echo "ZeptoClaw" ;;
        openclaw) echo "OpenClaw" ;;
        hermes) echo "Hermes Agent" ;;
        cursor) echo "Cursor" ;;
        windsurf) echo "Windsurf" ;;
        geminicli) echo "Gemini CLI" ;;
        copilot) echo "GitHub Copilot CLI" ;;
        openhands) echo "OpenHands" ;;
        antigravity) echo "Antigravity" ;;
        opencode) echo "OpenCode" ;;
        omnigent) echo "OmniGent" ;;
        *) echo "$1" ;;
    esac
}

connector_menu_hint() {
    case "$1" in
        codex) echo "patch ~/.codex/config.toml + hooks (no OpenClaw)" ;;
        claudecode) echo "patch ~/.claude/settings.json hooks (no OpenClaw)" ;;
        zeptoclaw) echo "patch ~/.zeptoclaw/config.json (no OpenClaw)" ;;
        openclaw) echo "install OpenClaw runtime + DefenseClaw plugin" ;;
        none) echo "install gateway/CLI only; pick later" ;;
        *) printf "configure %s hooks\n" "$(connector_display_name "$1")" ;;
    esac
}

# pick_connector_interactive — prompt the user to pick a connector when
# none was passed on the command line and we are not in --yes mode.
# Sets global CONNECTOR. Non-interactive installs intentionally choose
# "none" unless --connector is explicit: --yes should lay down binaries
# and hand the operator to `defenseclaw init`, not assume OpenClaw.
pick_connector_interactive() {
    if [[ -n "${CONNECTOR}" ]]; then
        return
    fi
    if [[ "${YES_MODE}" == true ]]; then
        CONNECTOR="none"
        return
    fi

    step "Pick agent connector"
    info "DefenseClaw can guard several agent frameworks. Pick one to integrate now;"
    info "you can switch later with 'defenseclaw init --connector <name>'."
    echo ""
    local i=1
    for v in "${CONNECTOR_CHOICES[@]}"; do
        printf "    ${BOLD}%d)${NC} %-11s — %s\n" "$i" "$v" "$(connector_menu_hint "$v")"
        i=$((i + 1))
    done
    echo ""

    local default_idx=1   # codex
    local choice
    printf "  Choice [1-%d, default %d=codex]: " "${#CONNECTOR_CHOICES[@]}" "${default_idx}" >&2
    read -r choice < /dev/tty 2>/dev/null || choice=""
    choice="${choice:-${default_idx}}"
    if ! [[ "${choice}" =~ ^[0-9]+$ ]] || (( choice < 1 || choice > ${#CONNECTOR_CHOICES[@]} )); then
        warn "Invalid choice '${choice}', defaulting to codex"
        CONNECTOR="codex"
    else
        CONNECTOR="${CONNECTOR_CHOICES[$((choice - 1))]}"
    fi
    ok "Picked connector: ${CONNECTOR}"
}

# record_picked_connector — write the picked connector name to
# <DEFENSECLAW_HOME>/picked_connector so the CLI's `defenseclaw setup`
# can default to it without re-prompting. The file is informational
# only — the gateway's authoritative connector state lives in
# active_connector.json after a successful Setup. We write it as text
# (no JSON) to keep the file shell-readable for diagnostics.
record_picked_connector() {
    if [[ -z "${CONNECTOR}" ]] || [[ "${CONNECTOR}" == "none" ]]; then
        return
    fi
    local destination="${DEFENSECLAW_HOME}/picked_connector"
    if [[ "${MODERN_RELEASE:-false}" == true ]]; then
        local source
        source="$(mktemp "${POLICY_DIR}/picked-connector.XXXXXX")" \
            || die "Could not allocate private connector marker custody"
        printf "%s\n" "${CONNECTOR}" > "${source}" \
            || die "Could not stage the selected connector marker"
        CONNECTOR_MARKER_ROLLBACK_TOKEN="$(
            "${POLICY_PYTHON}" "${PUBLISH_HELPER}" fresh-regular \
                "${source}" "${destination}" --retain-token
        )" || die "A connector marker appeared during installation; it was preserved"
        [[ -n "${CONNECTOR_MARKER_ROLLBACK_TOKEN}" ]] \
            || die "Connector marker publication did not return rollback custody"
        local retained_stages=(
            "${DEFENSECLAW_HOME}"/.picked_connector.source-install-*
        )
        [[ ${#retained_stages[@]} -eq 1 ]] \
            || die "Connector marker rollback custody could not be bound"
        local observed_marker_id retained_stage_id
        observed_marker_id="$(path_identity "${destination}")" \
            || die "Could not bind the selected connector marker identity"
        retained_stage_id="$(path_identity "${retained_stages[0]}")" \
            || die "Could not bind retained connector marker custody"
        [[ "${observed_marker_id}" == "${retained_stage_id}" ]] \
            || die "Connector marker rollback custody changed during publication"
        CONNECTOR_MARKER_ID="${observed_marker_id}"
    else
        PICKED_CONNECTOR_ACTIVATION="$(
            mktemp "${DEFENSECLAW_HOME}/.picked-connector.install.XXXXXX"
        )" || die "Could not allocate connector marker activation custody"
        PICKED_CONNECTOR_ACTIVATION_ID="$(
            path_identity "${PICKED_CONNECTOR_ACTIVATION}"
        )" || die "Could not bind connector marker activation custody"
        printf "%s\n" "${CONNECTOR}" > "${PICKED_CONNECTOR_ACTIVATION}" \
            || die "Could not stage the selected connector marker"
        if ! ln "${PICKED_CONNECTOR_ACTIVATION}" "${destination}"; then
            die "A connector marker appeared during installation; it was preserved"
        fi
        local observed_marker_id
        observed_marker_id="$(path_identity "${destination}")" \
            || die "Could not bind the selected connector marker identity"
        [[ "${observed_marker_id}" == "${PICKED_CONNECTOR_ACTIVATION_ID}" ]] \
            || die "Connector marker activation identity changed during publication"
        CONNECTOR_MARKER_ID="${observed_marker_id}"
    fi
}

# ── Interrupt handler ─────────────────────────────────────────────────────────

trap 'printf "\n"; err "Installation cancelled."; exit 130' INT TERM

# ── Platform Detection ────────────────────────────────────────────────────────

detect_platform() {
    step "Detecting platform"

    OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
    ARCH="$(uname -m)"

    case "${ARCH}" in
        x86_64|amd64)  ARCH_NORM="amd64" ;;
        aarch64|arm64) ARCH_NORM="arm64" ;;
        *) die "Unsupported architecture: ${ARCH}" ;;
    esac

    case "${OS}" in
        darwin) OS_NAME="macOS" ;;
        linux)  OS_NAME="Linux" ;;
        *)      die "Unsupported OS: ${OS}" ;;
    esac

    ok "${OS_NAME} (${ARCH_NORM})"
}

# ── Dependency: uv ────────────────────────────────────────────────────────────

ensure_uv() {
    step "Checking uv"

    if has uv; then
        ok "uv $(extract_version "$(uv --version)") found"
        return
    fi

    info "Installing uv..."
    curl -LsSf https://astral.sh/uv/install.sh | sh 2>/dev/null || {
        warn "uv installer returned an error"
    }

    export PATH="${HOME}/.local/bin:${HOME}/.cargo/bin:${PATH}"

    if has uv; then
        ok "uv $(extract_version "$(uv --version)") installed"
    else
        die "Failed to install uv. Install manually: https://docs.astral.sh/uv/"
    fi
}

# ── Dependency: Python ────────────────────────────────────────────────────────

ensure_python() {
    step "Checking Python"

    for cmd in python3.12 python3.11 python3.13 python3.10 python3; do
        if has "$cmd"; then
            local ver
            ver="$(extract_version "$("$cmd" --version 2>&1)")"
            if version_gte "$ver" "3.10"; then
                PYTHON_VERSION="$ver"
                POLICY_PYTHON="$(command -v "$cmd")"
                ok "Python ${ver}"
                return
            fi
        fi
    done

    local uv_py
    uv_py="$(uv python find 3.12 2>/dev/null || true)"
    if [[ -n "$uv_py" ]] && [[ -x "$uv_py" ]]; then
        PYTHON_VERSION="$(extract_version "$("$uv_py" --version 2>&1)")"
        POLICY_PYTHON="$uv_py"
        ok "Python ${PYTHON_VERSION} (managed by uv)"
        return
    fi

    info "Installing Python 3.12 via uv..."
    uv python install 3.12 || die "Failed to install Python via uv."
    POLICY_PYTHON="$(uv python find 3.12 2>/dev/null)"
    [[ -n "${POLICY_PYTHON}" && -x "${POLICY_PYTHON}" ]] \
        || die "uv installed Python 3.12 but its interpreter could not be resolved"
    PYTHON_VERSION="$(extract_version "$("${POLICY_PYTHON}" --version 2>&1)")"
    ok "Python ${PYTHON_VERSION} installed"
}

# ── Resolve dist artifacts ────────────────────────────────────────────────────

resolve_version() {
    if [[ -n "${LOCAL_DIR}" ]]; then
        return
    fi

    step "Resolving latest version"

    if [[ -n "${VERSION:-}" ]]; then
        RELEASE_VERSION="${VERSION}"
        ok "Using specified version: ${RELEASE_VERSION}"
        return
    fi

    RELEASE_VERSION=$(curl -sSf "https://api.github.com/repos/${REPO}/releases/latest" \
        | grep -oE '"tag_name": *"[^"]+"' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+') \
        || die "Failed to fetch latest release. Use --local <dir> for local installs."

    [[ -n "${RELEASE_VERSION}" ]] \
        || die "Could not parse release version. Use VERSION=x.y.z or --local <dir>."

    ok "Latest release: ${RELEASE_VERSION}"
}

sha256_file() {
    if has sha256sum; then
        sha256sum "$1" | awk '{print $1}'
    elif has shasum; then
        shasum -a 256 "$1" | awk '{print $1}'
    else
        die "sha256sum or shasum is required to authenticate release artifacts"
    fi
}

load_release_policy() {
    step "Authenticating release policy"
    [[ -n "${POLICY_PYTHON:-}" && -x "${POLICY_PYTHON}" ]] \
        || die "A supported Python interpreter is required to validate the signed release artifact policy"
    POLICY_DIR="$(mktemp -d)"
    POLICY_DIR_ID="$(path_identity "${POLICY_DIR}")" \
        || die "Could not bind the release-policy staging directory identity"

    local manifest_path="${POLICY_DIR}/upgrade-manifest.json"
    CHECKSUMS_FILE="${POLICY_DIR}/checksums.txt"
    if [[ -n "${LOCAL_DIR}" ]]; then
        [[ -f "${LOCAL_DIR}/upgrade-manifest.json" && -f "${LOCAL_DIR}/checksums.txt" ]] \
            || die "Local installs require upgrade-manifest.json and checksums.txt"
        cp "${LOCAL_DIR}/upgrade-manifest.json" "${manifest_path}"
        cp "${LOCAL_DIR}/checksums.txt" "${CHECKSUMS_FILE}"
        RELEASE_VERSION="$("${POLICY_PYTHON}" - "${manifest_path}" <<'PY'
import json, re, sys
value = json.load(open(sys.argv[1], encoding="utf-8")).get("release_version")
if not isinstance(value, str) or re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", value) is None:
    raise SystemExit("local upgrade manifest has no canonical release_version")
print(value)
PY
)"
        if [[ -n "${VERSION:-}" && "${VERSION}" != "${RELEASE_VERSION}" ]]; then
            die "Local manifest release ${RELEASE_VERSION} does not match VERSION=${VERSION}"
        fi
    else
        fetch_artifact "$(artifact_path "checksums.txt")" "${CHECKSUMS_FILE}"
        fetch_artifact "$(artifact_path "upgrade-manifest.json")" "${manifest_path}"
    fi

    MODERN_RELEASE=false
    if version_gte "${RELEASE_VERSION}" "0.8.4"; then
        MODERN_RELEASE=true
        has cosign || die "cosign is required to authenticate DefenseClaw ${RELEASE_VERSION} before installation"
        local signature="${POLICY_DIR}/checksums.txt.sig"
        local certificate="${POLICY_DIR}/checksums.txt.pem"
        if [[ -n "${LOCAL_DIR}" ]]; then
            [[ -f "${LOCAL_DIR}/checksums.txt.sig" && -f "${LOCAL_DIR}/checksums.txt.pem" ]] \
                || die "Local schema-2 installs require checksums.txt.sig and checksums.txt.pem"
            cp "${LOCAL_DIR}/checksums.txt.sig" "${signature}"
            cp "${LOCAL_DIR}/checksums.txt.pem" "${certificate}"
        else
            fetch_artifact "$(artifact_path "checksums.txt.sig")" "${signature}"
            fetch_artifact "$(artifact_path "checksums.txt.pem")" "${certificate}"
        fi
        cosign verify-blob \
            --certificate "${certificate}" \
            --signature "${signature}" \
            --certificate-identity "https://github.com/${REPO}/.github/workflows/release.yaml@refs/heads/main" \
            --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
            "${CHECKSUMS_FILE}" >/dev/null \
            || die "Sigstore verification failed; no DefenseClaw payload was activated"
    fi

    local manifest_expected manifest_actual
    manifest_expected="$(awk '$2 == "upgrade-manifest.json" {print $1; exit}' "${CHECKSUMS_FILE}")"
    [[ "${manifest_expected}" =~ ^[0-9A-Fa-f]{64}$ ]] \
        || die "checksums.txt does not authenticate upgrade-manifest.json"
    manifest_actual="$(sha256_file "${manifest_path}")"
    [[ "${manifest_actual}" == "${manifest_expected}" ]] \
        || die "upgrade-manifest.json checksum mismatch"

    local policy_fields
    policy_fields="$(
        "${POLICY_PYTHON}" - "${manifest_path}" "${RELEASE_VERSION}" "${OS}" "${ARCH_NORM}" <<'PY'
import json
from pathlib import Path
import sys

path, expected_version, os_name, arch = sys.argv[1:]
manifest = json.loads(Path(path).read_text(encoding="utf-8"))
version = manifest.get("release_version")
if version != expected_version:
    raise SystemExit("release manifest version mismatch")
key = tuple(map(int, version.split(".")))
schema = manifest.get("schema_version")
if key >= (0, 8, 4):
    expected_gateways = {}
    for platform_name in ("darwin", "linux", "windows"):
        expected_gateways[platform_name] = {
            platform_arch: f"defenseclaw_{version}_protocol2_{platform_name}_{platform_arch}.dcgateway"
            for platform_arch in ("amd64", "arm64")
        }
    expected_wheel = f"defenseclaw-{version}-2-py3-none-any.dcwheel"
    expected_artifacts = {"wheel": expected_wheel, "gateways": expected_gateways}
    if schema != 2 or manifest.get("release_artifacts") != expected_artifacts:
        raise SystemExit("schema-2 release_artifacts policy is missing or invalid")
    gateway = manifest["release_artifacts"]["gateways"][os_name][arch]
    wheel = manifest["release_artifacts"]["wheel"]
else:
    if schema != 1 or "release_artifacts" in manifest:
        raise SystemExit("legacy release manifest policy is invalid")
    gateway = f"defenseclaw_{version}_{os_name}_{arch}.tar.gz"
    wheel = f"defenseclaw-{version}-py3-none-any.whl"
print(version, schema, gateway, wheel)
PY
    )" || die "Release policy validation failed"
    read -r POLICY_RELEASE POLICY_SCHEMA GATEWAY_ARTIFACT WHEEL_ARTIFACT <<<"${policy_fields}"
    [[ "${POLICY_RELEASE}" == "${RELEASE_VERSION}" ]] || die "Release policy validation failed"

    if [[ "${MODERN_RELEASE}" == true ]]; then
        local gateway_protected="${POLICY_DIR}/${GATEWAY_ARTIFACT}"
        local wheel_protected="${POLICY_DIR}/${WHEEL_ARTIFACT}"
        fetch_artifact "$(artifact_path "${GATEWAY_ARTIFACT}")" "${gateway_protected}"
        fetch_artifact "$(artifact_path "${WHEEL_ARTIFACT}")" "${wheel_protected}"
        verify_checksum "${gateway_protected}" "${GATEWAY_ARTIFACT}"
        local gateway_outer_sha256="${VERIFIED_CHECKSUM}"
        verify_checksum "${wheel_protected}" "${WHEEL_ARTIFACT}"
        local wheel_outer_sha256="${VERIFIED_CHECKSUM}"

        # Published payloads are custom envelopes, not merely renamed wheels or
        # archives: suffix sniffing or renaming must not bypass the resolver.
        # Only this authenticated private directory receives the unwrapped
        # bytes under conventional suffixes, using no-follow/exclusive opens.
        GATEWAY_STAGED="${POLICY_DIR}/defenseclaw-gateway-authenticated.tar.gz"
        WHEEL_STAGED="${POLICY_DIR}/defenseclaw-${RELEASE_VERSION}-py3-none-any.whl"
        "${POLICY_PYTHON}" - \
            "${gateway_protected}" "${GATEWAY_STAGED}" "${gateway_outer_sha256}" \
            "${wheel_protected}" "${WHEEL_STAGED}" "${wheel_outer_sha256}" <<'PY'
import hashlib
import os
from pathlib import Path
import re
import stat
import sys

MAGIC = b"DEFENSECLAW-PROTECTED-ARTIFACT-V1\n"
XOR_TRANSLATION = bytes(value ^ 0xA5 for value in range(256))
arguments = sys.argv[1:]
for source_value, destination_value, expected_outer_sha256 in zip(
    arguments[::3], arguments[1::3], arguments[2::3], strict=True
):
    expected_outer_sha256 = expected_outer_sha256.lower()
    if re.fullmatch(r"[0-9a-f]{64}", expected_outer_sha256) is None:
        raise SystemExit("protected release asset lacks an authenticated outer digest")
    source = Path(source_value)
    destination = Path(destination_value)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    source_fd = os.open(source, os.O_RDONLY | os.O_CLOEXEC | nofollow)
    destination_fd = -1
    payload_digest = hashlib.sha256()
    outer_digest = hashlib.sha256()
    try:
        info = os.fstat(source_fd)
        if not stat.S_ISREG(info.st_mode):
            raise SystemExit(f"protected release asset is not a regular file: {source.name}")
        destination_fd = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | nofollow,
            0o600,
        )
        with os.fdopen(source_fd, "rb", closefd=False) as input_stream, os.fdopen(
            destination_fd, "wb", closefd=False
        ) as output_stream:
            observed_magic = input_stream.read(len(MAGIC))
            if observed_magic != MAGIC:
                raise SystemExit(f"protected release envelope magic is invalid: {source.name}")
            outer_digest.update(observed_magic)
            payload_size = 0
            while encoded_chunk := input_stream.read(1024 * 1024):
                outer_digest.update(encoded_chunk)
                chunk = encoded_chunk.translate(XOR_TRANSLATION)
                payload_size += len(chunk)
                payload_digest.update(chunk)
                output_stream.write(chunk)
            if payload_size == 0:
                raise SystemExit(f"protected release envelope is empty: {source.name}")
            if outer_digest.hexdigest() != expected_outer_sha256:
                raise SystemExit(
                    f"protected release asset changed after checksum authentication: {source.name}"
                )
            output_stream.flush()
            os.fsync(destination_fd)
    except BaseException:
        try:
            destination.unlink()
        except FileNotFoundError:
            pass
        raise
    finally:
        os.close(source_fd)
        if destination_fd >= 0:
            os.close(destination_fd)

    materialized_digest = hashlib.sha256()
    verified_fd = os.open(destination, os.O_RDONLY | os.O_CLOEXEC | nofollow)
    try:
        with os.fdopen(verified_fd, "rb", closefd=False) as verified_stream:
            for chunk in iter(lambda: verified_stream.read(1024 * 1024), b""):
                materialized_digest.update(chunk)
    finally:
        os.close(verified_fd)
    if payload_digest.digest() != materialized_digest.digest():
        raise SystemExit(f"private materialization changed protected payload bytes: {source.name}")
    directory_fd = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
PY
        GATEWAY_STAGED_BINARY="${POLICY_DIR}/defenseclaw"
        PUBLISH_HELPER="${POLICY_DIR}/install_publish.py"
        "${POLICY_PYTHON}" - \
            "${GATEWAY_STAGED}" "${WHEEL_STAGED}" \
            "${GATEWAY_STAGED_BINARY}" "${PUBLISH_HELPER}" <<'PY'
import os
import stat
import sys
import tarfile
import zipfile

gateway, wheel, output, helper_output = sys.argv[1:]
with tarfile.open(gateway, "r:gz") as archive:
    matches = [member for member in archive.getmembers() if member.isfile() and member.name == "defenseclaw"]
    if len(matches) != 1:
        raise SystemExit("protected gateway archive lacks its exact runtime binary")
    if not 0 < matches[0].size <= 512 * 1024 * 1024:
        raise SystemExit("protected gateway runtime is outside its size bound")
    stream = archive.extractfile(matches[0])
    if stream is None:
        raise SystemExit("protected gateway runtime could not be read")
    with open(output, "xb") as handle:
        handle.write(stream.read())
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(output, 0o700)
with zipfile.ZipFile(wheel) as archive:
    if not any(name.endswith(".dist-info/METADATA") for name in archive.namelist()):
        raise SystemExit("protected wheel lacks package metadata")
    helper_name = "defenseclaw/install_publish.py"
    helpers = [info for info in archive.infolist() if info.filename == helper_name]
    if len(helpers) != 1:
        raise SystemExit("protected wheel lacks its exact install publisher")
    helper = helpers[0]
    mode = helper.external_attr >> 16
    if (
        helper.is_dir()
        or helper.flag_bits & 0x1
        or not 0 < helper.file_size <= 512 * 1024
        or (mode and stat.S_ISLNK(mode))
    ):
        raise SystemExit("protected wheel install publisher is unsafe")
    with archive.open(helper) as source, open(helper_output, "xb") as destination:
        destination.write(source.read())
        destination.flush()
        os.fsync(destination.fileno())
    os.chmod(helper_output, 0o500)
directory_fd = os.open(os.path.dirname(output), os.O_RDONLY | os.O_DIRECTORY)
try:
    os.fsync(directory_fd)
finally:
    os.close(directory_fd)
PY
    fi
    ok "Release policy and protected artifacts verified (${RELEASE_VERSION})"
}

# Find artifact in local dir or construct download URL
artifact_path() {
    local name="$1"
    if [[ -n "${LOCAL_DIR}" ]]; then
        local match
        match="$(ls "${LOCAL_DIR}"/${name} 2>/dev/null | head -1 || true)"
        if [[ -z "${match}" ]]; then
            die "Artifact not found: ${LOCAL_DIR}/${name}"
        fi
        echo "${match}"
    else
        echo "https://github.com/${REPO}/releases/download/${RELEASE_VERSION}/${name}"
    fi
}

# Copy from local or download from URL
fetch_artifact() {
    local source="$1" dest="$2"
    if [[ -n "${LOCAL_DIR}" ]]; then
        cp "${source}" "${dest}"
    else
        curl -sSfL "${source}" -o "${dest}" \
            || die "Failed to download: ${source}"
    fi
}

# Download and verify checksums.txt, then validate a file against it.
# Skipped for --local installs (assumes the user built locally).
verify_checksum() {
    local file="$1" filename="$2"
    VERIFIED_CHECKSUM=""
    if [[ -n "${LOCAL_DIR}" && "${MODERN_RELEASE:-false}" != true ]]; then
        return 0
    fi
    if [[ -z "${CHECKSUMS_FILE:-}" ]]; then
        local checksums_url
        checksums_url="$(artifact_path "checksums.txt")"
        CHECKSUMS_FILE="$(mktemp)"
        curl -sSfL "${checksums_url}" -o "${CHECKSUMS_FILE}" \
            || { warn "Could not download checksums.txt — skipping verification"; return 0; }
    fi
    local expected actual
    expected="$(awk -v f="${filename}" '$2 == f {print $1; exit}' "${CHECKSUMS_FILE}")"
    if [[ -z "${expected}" ]]; then
        if [[ "${MODERN_RELEASE:-false}" == true ]]; then
            die "Signed checksums do not cover required artifact ${filename}"
        fi
        warn "No checksum entry for ${filename} — skipping verification"
        return 0
    fi
    actual="$(sha256_file "${file}")"
    if [[ "${expected}" != "${actual}" ]]; then
        die "Checksum mismatch for ${filename}: expected ${expected}, got ${actual}"
    fi
    VERIFIED_CHECKSUM="${actual}"
}

# ── Install: Gateway binary ──────────────────────────────────────────────────

install_gateway() {
    step "Installing gateway"

    if [[ "${MODERN_RELEASE:-false}" == true ]]; then
        "${POLICY_PYTHON}" "${PUBLISH_HELPER}" ensure-real-directory "${INSTALL_DIR}" \
            || die "Could not bind the fresh-install binary directory"
    else
        mkdir -p "${INSTALL_DIR}"
    fi
    local gateway_source=""
    local extraction_dir=""

    if [[ "${MODERN_RELEASE:-false}" == true ]]; then
        gateway_source="${GATEWAY_STAGED_BINARY}"
    elif [[ -n "${LOCAL_DIR}" ]]; then
        local artifact
        artifact="$(artifact_path "defenseclaw-gateway-${OS}-${ARCH_NORM}")"
        gateway_source="${artifact}"
    else
        local url
        local tarball_name="defenseclaw_${RELEASE_VERSION}_${OS}_${ARCH_NORM}.tar.gz"
        url="$(artifact_path "${tarball_name}")"
        extraction_dir="$(mktemp -d)"
        fetch_artifact "${url}" "${extraction_dir}/gateway.tar.gz"
        verify_checksum "${extraction_dir}/gateway.tar.gz" "${tarball_name}"
        tar -xzf "${extraction_dir}/gateway.tar.gz" -C "${extraction_dir}"
        gateway_source="${extraction_dir}/defenseclaw"
    fi

    if [[ "${MODERN_RELEASE:-false}" == true ]]; then
        if [[ "${OS}" == "darwin" ]]; then
            /usr/bin/codesign -f -s - -i com.cisco.defenseclaw.gateway \
                "${gateway_source}" >/dev/null 2>&1 \
                || die "Could not normalize the macOS gateway signature; installation was not activated"
        fi
        GATEWAY_ROLLBACK_TOKEN="$(
            "${POLICY_PYTHON}" "${PUBLISH_HELPER}" fresh-regular \
                "${gateway_source}" "${INSTALL_DIR}/defenseclaw-gateway" \
                --retain-token
        )" || die "A DefenseClaw gateway appeared during installation; it was preserved and this installation was not activated"
        [[ -n "${GATEWAY_ROLLBACK_TOKEN}" ]] \
            || die "Fresh gateway publication did not return rollback custody"
    else
        local activation
        activation="$(mktemp "${INSTALL_DIR}/.defenseclaw-gateway.install.XXXXXX")" \
            || die "Could not allocate a gateway activation file"
        GATEWAY_ACTIVATION="${activation}"
        GATEWAY_PRECLAIM_ID="$(path_identity "${activation}")" \
            || die "Could not bind the allocated gateway activation file"
        cp "${gateway_source}" "${activation}" || {
            if path_has_identity "${activation}" "${GATEWAY_PRECLAIM_ID}"; then
                rm -f "${activation}"
            fi
            die "Could not stage the gateway for activation"
        }
        chmod +x "${activation}" || {
            # cp may replace the mktemp inode on macOS. Until the fully staged
            # file is claimed below, preserve an uncertain path on failure.
            die "Could not make the staged gateway executable"
        }
        if [[ "${OS}" == "darwin" ]]; then
            /usr/bin/codesign -f -s - -i com.cisco.defenseclaw.gateway \
                "${activation}" >/dev/null 2>&1 || {
                # codesign may also rewrite the file. Preserve uncertain
                # pre-claim custody instead of deleting a concurrent entry.
                die "Could not normalize the macOS gateway signature; installation was not activated"
            }
        fi
        [[ -f "${activation}" && ! -L "${activation}" ]] \
            || die "Fresh gateway activation is not a real file"
        GATEWAY_ACTIVATION_ID="$(path_identity "${activation}")" \
            || die "Could not bind fresh gateway activation custody"
        if ! ln "${activation}" "${INSTALL_DIR}/defenseclaw-gateway"; then
            if path_has_identity "${activation}" "${GATEWAY_ACTIVATION_ID}"; then
                rm -f "${activation}"
            fi
            die "A DefenseClaw gateway appeared during installation; it was preserved and this installation was not activated"
        fi
        local observed_gateway_id
        observed_gateway_id="$(
            path_identity "${INSTALL_DIR}/defenseclaw-gateway"
        )" || die "Could not bind the fresh gateway publication identity"
        GATEWAY_PUBLISHED_ID="${observed_gateway_id}"
        [[ "${observed_gateway_id}" == "${GATEWAY_ACTIVATION_ID}" ]] \
            || die "Fresh gateway activation identity changed during publication"
    fi
    [[ -z "${extraction_dir}" ]] || rm -rf "${extraction_dir}"

    ok "Gateway installed"
}

# ── Install: Python CLI (from wheel) ─────────────────────────────────────────

install_python_cli() {
    step "Installing DefenseClaw CLI"

    info "Creating Python environment..."
    uv venv "${DEFENSECLAW_VENV}" --python "${PYTHON_VERSION}" --quiet 2>/dev/null \
        || uv venv "${DEFENSECLAW_VENV}" --python 3.12 --quiet 2>/dev/null \
        || uv venv "${DEFENSECLAW_VENV}" --quiet \
        || die "Failed to create Python virtual environment"

    info "Installing from wheel..."
    if [[ "${MODERN_RELEASE:-false}" == true ]]; then
        uv pip install --python "${DEFENSECLAW_VENV}/bin/python" --quiet "${WHEEL_STAGED}" \
            || die "Failed to install CLI from protected release wheel"
    elif [[ -n "${LOCAL_DIR}" ]]; then
        local whl
        whl="$(artifact_path "defenseclaw-*.whl")"
        uv pip install --python "${DEFENSECLAW_VENV}/bin/python" --quiet "${whl}" \
            || die "Failed to install CLI from wheel"
    else
        local whl_name="defenseclaw-${RELEASE_VERSION}-py3-none-any.whl"
        local whl_url tmp
        whl_url="$(artifact_path "${whl_name}")"
        tmp="$(mktemp -d)"
        fetch_artifact "${whl_url}" "${tmp}/${whl_name}"
        uv pip install --python "${DEFENSECLAW_VENV}/bin/python" --quiet "${tmp}/${whl_name}" \
            || die "Failed to install CLI from wheel"
        rm -rf "${tmp}"
    fi

    if [[ "${MODERN_RELEASE:-false}" == true ]]; then
        CLI_PUBLISHED_ID="$(
            "${POLICY_PYTHON}" "${PUBLISH_HELPER}" fresh-symlink \
                "${DEFENSECLAW_VENV}/bin/defenseclaw" "${INSTALL_DIR}/defenseclaw"
        )" || die "A DefenseClaw CLI appeared during installation; it was preserved and this installation was not activated"
    else
        mkdir -p "${INSTALL_DIR}"
        ln -s "${DEFENSECLAW_VENV}/bin/defenseclaw" "${INSTALL_DIR}/defenseclaw" \
            || die "A DefenseClaw CLI appeared during installation; it was preserved and this installation was not activated"
        CLI_PUBLISHED_ID="$(path_identity "${INSTALL_DIR}/defenseclaw")" \
            || die "Could not bind the installed DefenseClaw CLI identity"
    fi
    [[ "${CLI_PUBLISHED_ID}" =~ ^[0-9]+:[0-9]+$ ]] \
        || die "Installed DefenseClaw CLI returned an invalid identity"

    if "${DEFENSECLAW_VENV}/bin/defenseclaw" --help &>/dev/null; then
        ok "CLI installed"
    else
        warn "CLI installed but verification failed — check dependencies"
    fi
}

# ── Install: OpenClaw Plugin (from tarball) ───────────────────────────────────
# Plugin releases are independent of gateway/CLI releases — not every release
# ships a plugin tarball (introduced in 0.3.0). The artifact is probed before
# attempting install so installs on earlier releases do not fail.

release_has_plugin() {
    if [[ -n "${LOCAL_DIR}" ]]; then
        ls "${LOCAL_DIR}"/defenseclaw-plugin-*.tar.gz 2>/dev/null | head -1 | grep -q .
    else
        local url="https://github.com/${REPO}/releases/download/${RELEASE_VERSION}/defenseclaw-plugin-${RELEASE_VERSION}.tar.gz"
        curl -sSfL --head --output /dev/null "${url}" 2>/dev/null
    fi
}

install_plugin() {
    step "Checking for plugin artifact in release ${RELEASE_VERSION:-local} ..."

    if ! release_has_plugin; then
        info "No plugin artifact in this release — skipping plugin install"
        return
    fi

    step "Installing OpenClaw plugin"

    local extensions="${DEFENSECLAW_HOME}/extensions"
    local dest="${extensions}/defenseclaw"
    if [[ "${MODERN_RELEASE:-false}" == true ]]; then
        EXTENSIONS_CLAIM_ID="$(
            "${POLICY_PYTHON}" "${PUBLISH_HELPER}" fresh-directory "${extensions}"
        )" || die "A plugin extension directory appeared during installation; it was preserved"
        PLUGIN_CLAIM_ID="$(
            "${POLICY_PYTHON}" "${PUBLISH_HELPER}" fresh-directory "${dest}"
        )" || die "A DefenseClaw plugin directory appeared during installation; it was preserved"
    else
        mkdir "${extensions}" \
            || die "A plugin extension directory appeared during installation; it was preserved"
        EXTENSIONS_CLAIM_ID="$(path_identity "${extensions}")" \
            || die "Could not bind the plugin extension directory identity"
        mkdir "${dest}" \
            || die "A DefenseClaw plugin directory appeared during installation; it was preserved"
        PLUGIN_CLAIM_ID="$(path_identity "${dest}")" \
            || die "Could not bind the DefenseClaw plugin directory identity"
    fi
    [[ "${EXTENSIONS_CLAIM_ID}" =~ ^[0-9]+:[0-9]+$ \
        && "${PLUGIN_CLAIM_ID}" =~ ^[0-9]+:[0-9]+$ ]] \
        || die "Plugin directory custody returned an invalid identity"

    if [[ -n "${LOCAL_DIR}" ]]; then
        local tarball
        tarball="$(ls "${LOCAL_DIR}"/defenseclaw-plugin-*.tar.gz | head -1)"
        tar -xzf "${tarball}" -C "${dest}"
    else
        local tarball_name="defenseclaw-plugin-${RELEASE_VERSION}.tar.gz"
        local tarball_url tmp
        tarball_url="$(artifact_path "${tarball_name}")"
        tmp="$(mktemp -d)"
        fetch_artifact "${tarball_url}" "${tmp}/${tarball_name}"
        tar -xzf "${tmp}/${tarball_name}" -C "${dest}"
        rm -rf "${tmp}"
    fi

    ok "Plugin installed"
}

# ── OpenClaw ──────────────────────────────────────────────────────────────────

npm_global_install() {
    local pkg="$1"
    local output
    if output=$(npm install -g "${pkg}" --loglevel=error 2>&1); then
        return 0
    fi
    if echo "$output" | grep -qiE "permission|EACCES|EPERM"; then
        info "Requires elevated permissions for global npm install..."
        sudo npm install -g "${pkg}" --loglevel=error
    else
        printf "%s\n" "$output" >&2
        return 1
    fi
}

handle_openclaw() {
    step "Checking OpenClaw"

    if has openclaw; then
        local oc_ver
        oc_ver="$(extract_version "$(openclaw --version 2>&1)")"
        ok "OpenClaw ${oc_ver} found"

        if version_gte "${oc_ver}" "${OPENCLAW_VERSION}"; then
            return
        fi

        warn "Version ${oc_ver} is older than the required ${OPENCLAW_VERSION}"
        echo ""
        if ask_yes_no "Update OpenClaw to ${OPENCLAW_VERSION}?"; then
            info "Updating OpenClaw..."
            npm_global_install "openclaw@${OPENCLAW_VERSION}" \
                || die "Failed to update OpenClaw"
            ok "OpenClaw updated to ${OPENCLAW_VERSION}"
        else
            warn "Skipping update — some DefenseClaw features may not work correctly"
        fi
        return
    fi

    warn "OpenClaw is not installed"
    info "DefenseClaw requires OpenClaw ${OPENCLAW_VERSION} to function."
    echo ""

    if ! ask_yes_no "Install OpenClaw ${OPENCLAW_VERSION}?"; then
        echo ""
        warn "Skipping OpenClaw installation"
        info "Install later:"
        printf "    ${CYAN}npm install -g openclaw@${OPENCLAW_VERSION}${NC}\n"
        printf "    ${CYAN}openclaw onboard --install-daemon${NC}\n"
        return
    fi

    if has npm; then
        info "Installing OpenClaw ${OPENCLAW_VERSION} via npm..."
        npm_global_install "openclaw@${OPENCLAW_VERSION}" \
            || die "Failed to install OpenClaw"
    else
        info "Installing OpenClaw via official installer..."
        curl -fsSL https://openclaw.ai/install.sh | bash -s -- --no-onboard \
            || die "OpenClaw installer failed"
    fi

    if has openclaw; then
        ok "OpenClaw ${OPENCLAW_VERSION} installed"
    else
        ok "OpenClaw installed (may require shell restart to appear in PATH)"
    fi

    echo ""
    info "OpenClaw needs one-time onboarding before first use."
    printf "\n  ${BOLD}Please open a new terminal${NC} and run:\n\n"
    printf "    ${CYAN}openclaw onboard --install-daemon${NC}\n\n"
    info "Complete the onboarding wizard, then come back here."

    wait_for_enter "Press Enter once onboarding is complete..."

    if openclaw --version &>/dev/null; then
        ok "OpenClaw is ready"
    else
        warn "Could not verify OpenClaw — you may need to restart your shell"
    fi
}

# ── Quickstart (optional) ─────────────────────────────────────────────────────
# Invokes ``defenseclaw quickstart`` using the venv binary directly so it
# runs even on a fresh shell where PATH has not been reloaded. Failure is
# non-fatal — the installer's job is to land binaries, quickstart failures
# are runtime/config issues the user can retry without reinstalling.

run_quickstart() {
    if [[ "${RUN_QUICKSTART}" != true ]]; then
        return
    fi

    step "Running quickstart"

    local dc_bin="${DEFENSECLAW_VENV}/bin/defenseclaw"
    if [[ ! -x "${dc_bin}" ]]; then
        warn "CLI binary not found at ${dc_bin} — skipping quickstart"
        return
    fi

    local args=(quickstart --non-interactive --yes)
    if [[ "${CONNECTOR}" == "none" || -z "${CONNECTOR}" ]]; then
        warn "Quickstart skipped because no connector was selected — run 'defenseclaw init' when ready"
        return
    fi
    args+=(--connector "${CONNECTOR}")
    if [[ -n "${QUICKSTART_MODE}" ]]; then
        args+=(--mode "${QUICKSTART_MODE}")
    fi

    if "${dc_bin}" "${args[@]}"; then
        ok "Quickstart completed"
    else
        warn "Quickstart reported errors — run 'defenseclaw doctor' to investigate"
    fi
}

# ── PATH Configuration ────────────────────────────────────────────────────────

ensure_path() {
    local dirs_to_add=()

    if ! echo "${PATH}" | tr ':' '\n' | grep -qxF "${INSTALL_DIR}"; then
        dirs_to_add+=("${INSTALL_DIR}")
    fi

    if [[ ${#dirs_to_add[@]} -eq 0 ]]; then
        return
    fi

    local shell_rc
    shell_rc="$(detect_shell_rc)"

    step "PATH setup required"
    info "Add the following to ${shell_rc}:"
    echo ""
    for d in "${dirs_to_add[@]}"; do
        printf "    ${CYAN}export PATH=\"%s:\$PATH\"${NC}\n" "$d"
    done
    echo ""
    info "Then apply with:"
    printf "    ${CYAN}source %s${NC}\n" "${shell_rc}"
    echo ""
}

# ── Success ───────────────────────────────────────────────────────────────────

print_success() {
    echo ""
    printf "${BOLD}${GREEN}╔══════════════════════════════════════════════════════════╗${NC}\n"
    printf "${BOLD}${GREEN}║        DefenseClaw installed successfully!               ║${NC}\n"
    printf "${BOLD}${GREEN}╚══════════════════════════════════════════════════════════╝${NC}\n"
    echo ""

    # Connector-specific next-step guidance. The picked connector determines
    # which `defenseclaw` command to run next.
    if [[ "${CONNECTOR}" == "openclaw" ]]; then
        printf "  Get started:\n\n"
        if [[ "${INSTALL_SANDBOX}" == true ]] && [[ "${OS}" == "linux" ]]; then
            printf "    ${CYAN}defenseclaw init --connector openclaw --sandbox${NC}\n"
        else
            printf "    ${CYAN}defenseclaw init --connector openclaw --profile observe${NC}\n"
        fi
    elif is_hook_connector "${CONNECTOR}"; then
        printf "  Get started (%s):\n\n" "$(connector_display_name "${CONNECTOR}")"
        printf "    ${CYAN}defenseclaw init --connector %s${NC}\n" "${CONNECTOR}"
    else
        printf "  Get started (pick a connector later):\n\n"
        printf "    ${CYAN}defenseclaw init${NC}\n"
    fi
    if [[ "${INSTALL_SANDBOX}" == true && "${CONNECTOR}" != "openclaw" ]]; then
        warn "Sandbox setup is experimental and currently applies to the OpenClaw/OpenShell path only."
    fi
    echo ""
}

# ── Entry Point ───────────────────────────────────────────────────────────────

printf "\n"
printf "${BOLD}  DefenseClaw Installer${NC}\n"
printf "  ${DIM}Enterprise Governance for Agentic AI${NC}\n"

YES_MODE=false
LOCAL_DIR=""
POLICY_DIR=""
POLICY_DIR_ID=""
MODERN_RELEASE=false
GATEWAY_ARTIFACT=""
WHEEL_ARTIFACT=""
GATEWAY_STAGED=""
GATEWAY_STAGED_BINARY=""
WHEEL_STAGED=""
PUBLISH_HELPER=""
POLICY_PYTHON=""
INSTALL_SUCCEEDED=false
HOME_CLAIM_ID=""
VENV_CLAIM_ID=""
LOCAL_BIN_PARENT_CLAIM_ID=""
INSTALL_DIR_CLAIM_ID=""
EXTENSIONS_CLAIM_ID=""
PLUGIN_CLAIM_ID=""
GATEWAY_ACTIVATION=""
GATEWAY_PRECLAIM_ID=""
GATEWAY_ACTIVATION_ID=""
GATEWAY_PUBLISHED_ID=""
GATEWAY_ROLLBACK_TOKEN=""
PICKED_CONNECTOR_ACTIVATION=""
PICKED_CONNECTOR_ACTIVATION_ID=""
CONNECTOR_MARKER_ROLLBACK_TOKEN=""
CONNECTOR_MARKER_ID=""
CLI_PUBLISHED_ID=""
INSTALL_SANDBOX=false
RUN_QUICKSTART=false
QUICKSTART_MODE=""
CONNECTOR=""
NO_OPENCLAW=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --sandbox) INSTALL_SANDBOX=true; shift ;;
        --local)
            [[ $# -lt 2 ]] && die "--local requires a directory argument"
            LOCAL_DIR="$(cd "$2" && pwd)" || die "Directory not found: $2"
            shift 2
            ;;
        --yes|-y) YES_MODE=true; shift ;;
        --connector)
            [[ $# -lt 2 ]] && die "--connector requires a value (${CONNECTOR_CHOICES[*]})"
            CONNECTOR="$2"
            is_valid_connector "${CONNECTOR}" \
                || die "Invalid --connector '${CONNECTOR}'. Choices: ${CONNECTOR_CHOICES[*]}"
            shift 2
            ;;
        --no-openclaw) NO_OPENCLAW=true; shift ;;
        # Run ``defenseclaw quickstart --non-interactive`` after the
        # binaries land. This gives a single-command install→bootstrap
        # path: everything a user needs to go from ``curl | bash`` to a
        # working guardrail without touching the CLI themselves.
        --quickstart) RUN_QUICKSTART=true; shift ;;
        --quickstart-mode)
            [[ $# -lt 2 ]] && die "--quickstart-mode requires a value (observe|action)"
            QUICKSTART_MODE="$2"
            case "${QUICKSTART_MODE}" in observe|action) ;; *) die "invalid --quickstart-mode: ${QUICKSTART_MODE}" ;; esac
            RUN_QUICKSTART=true
            shift 2
            ;;
        --help|-h)
            echo ""
            echo "Usage:"
            echo '  VERSION=0.8.4'
            echo '  INSTALL_URL="https://raw.githubusercontent.com/cisco-ai-defense/defenseclaw/${VERSION}/scripts/install.sh"'
            echo '  curl -LsSf "$INSTALL_URL" | VERSION="$VERSION" bash'
            echo "  ./scripts/install.sh --local ./dist               # from local build"
            echo "  curl -LsSf <url>/install.sh | bash -s -- --yes    # non-interactive"
            echo "  curl ... | bash -s -- --sandbox                   # OpenClaw/OpenShell sandbox support"
            echo "  curl ... | bash -s -- --quickstart                # run quickstart after install"
            echo ""
            echo "Options:"
            echo "  --sandbox             Also install openshell-sandbox (experimental Linux/OpenClaw path)"
            echo "  --local <dir>         Install from a local dist directory"
            echo "  --yes, -y             Skip all confirmation prompts"
            echo "  --connector <name>    Pick agent connector (${CONNECTOR_CHOICES[*]})"
            echo "  --no-openclaw         Skip OpenClaw runtime+plugin install (alias for --connector none)"
            echo "  --quickstart          Run 'defenseclaw quickstart --non-interactive' post-install"
            echo "  --quickstart-mode M   Pass --mode M to quickstart (observe|action; implies --quickstart)"
            echo "  --help, -h            Show this help"
            echo ""
            echo "Environment variables:"
            echo "  DEFENSECLAW_HOME   Install directory (default: ~/.defenseclaw)"
            echo "  VERSION            Specific release version to install"
            echo "  OPENSHELL_VERSION  openshell-sandbox version (default: 0.0.16)"
            echo ""
            echo "Build artifacts locally first:"
            echo "  make dist          # produces dist/ with all artifacts"
            echo ""
            exit 0
            ;;
        *) die "Unknown option: $1. Use --help for usage." ;;
    esac
done
export YES_MODE
trap cleanup_install_attempt EXIT

# Reconcile --no-openclaw and --connector. The two flags can be combined
# coherently (e.g. --no-openclaw --connector codex), but conflicting use
# (--no-openclaw --connector openclaw) is rejected to avoid silently
# ignoring the operator's intent.
if [[ "${NO_OPENCLAW}" == true ]]; then
    if [[ -z "${CONNECTOR}" ]]; then
        CONNECTOR="none"
    elif [[ "${CONNECTOR}" == "openclaw" ]]; then
        die "--no-openclaw is incompatible with --connector openclaw"
    fi
fi

if [[ -n "${LOCAL_DIR}" ]]; then
    info "Installing from local directory: ${LOCAL_DIR}"
fi

# This installer intentionally owns fresh hosts only. Re-running it over an
# installed controller would bypass release-owned upgrade manifests, bridge
# selection, migration rollback, and post-upgrade health verification.
if has defenseclaw \
    || has defenseclaw-gateway \
    || [[ -e "${DEFENSECLAW_HOME}" || -L "${DEFENSECLAW_HOME}" ]] \
    || [[ -e "${DEFENSECLAW_VENV}" || -L "${DEFENSECLAW_VENV}" ]] \
    || [[ -e "${INSTALL_DIR}/defenseclaw" || -L "${INSTALL_DIR}/defenseclaw" ]] \
    || [[ -e "${INSTALL_DIR}/defenseclaw-gateway" || -L "${INSTALL_DIR}/defenseclaw-gateway" ]]; then
    die "An existing DefenseClaw installation was detected. No changes were made.
  Use the release-owned upgrade resolver so required bridge releases, rollback, and health checks are enforced."
fi

detect_platform
resolve_version
ensure_uv
ensure_python
load_release_policy
pick_connector_interactive
claim_fresh_install_home
install_gateway
install_python_cli

# Only install the OpenClaw plugin and runtime when the user actually picked
# OpenClaw. Other connectors integrate via CLI setup and need neither npm nor
# the plugin tarball.
if [[ "${CONNECTOR}" == "openclaw" ]]; then
    install_plugin
    handle_openclaw
elif is_hook_connector "${CONNECTOR}"; then
    info "Skipping OpenClaw plugin/runtime install (connector: ${CONNECTOR})"
else
    info "Skipping connector setup — run 'defenseclaw init' when ready"
fi

record_picked_connector

if [[ "${INSTALL_SANDBOX}" == true ]]; then
    if [[ "${CONNECTOR}" != "openclaw" ]]; then
        warn "Sandbox setup is experimental and currently applies to the OpenClaw/OpenShell path only — skipping openshell-sandbox"
    elif [[ "${OS}" != "linux" ]]; then
        warn "Sandbox mode requires Linux — skipping openshell-sandbox"
    else
        local script_dir
        script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
        local sandbox_installer="${script_dir}/install-openshell-sandbox.sh"
        if [[ -f "${sandbox_installer}" ]]; then
            bash "${sandbox_installer}"
        else
            step "Installing openshell-sandbox"
            info "Downloading installer..."
            curl -fsSL \
                "https://raw.githubusercontent.com/${REPO}/${RELEASE_VERSION}/scripts/install-openshell-sandbox.sh" \
                | bash
        fi
    fi
fi

run_quickstart
ensure_path
complete_install_attempt
print_success

}

main "$@"
