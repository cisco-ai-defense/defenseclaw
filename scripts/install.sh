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
#   curl -LsSf https://raw.githubusercontent.com/cisco-ai-defense/defenseclaw/main/scripts/install.sh | bash
#
#   # From local dist/ directory (for testing):
#   ./scripts/install.sh --local ./dist
#
# Options:
#   --local <dir>  Install from a local dist directory instead of downloading
#   --yes, -y      Skip confirmation prompts (for CI/automation)
#   --help, -h     Show help
#
set -euo pipefail

# Entire script wrapped in main() so bash parses everything before executing.
# Critical for curl|sh safety — prevents partial execution on network drops.
main() {

# ── Configuration ─────────────────────────────────────────────────────────────

readonly DEFENSECLAW_HOME="${DEFENSECLAW_HOME:-${HOME}/.defenseclaw}"
readonly DEFENSECLAW_VENV="${DEFENSECLAW_HOME}/.venv"
readonly INSTALL_DIR="${HOME}/.local/bin"
readonly REPO="cisco-ai-defense/defenseclaw"
readonly OPENCLAW_VERSION="2026.3.24"

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
                ok "Python ${ver}"
                return
            fi
        fi
    done

    local uv_py
    uv_py="$(uv python find 3.12 2>/dev/null || true)"
    if [[ -n "$uv_py" ]] && [[ -x "$uv_py" ]]; then
        PYTHON_VERSION="$(extract_version "$("$uv_py" --version 2>&1)")"
        ok "Python ${PYTHON_VERSION} (managed by uv)"
        return
    fi

    info "Installing Python 3.12 via uv..."
    uv python install 3.12 || die "Failed to install Python via uv."
    PYTHON_VERSION="3.12"
    ok "Python 3.12 installed"
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
    if [[ -n "${LOCAL_DIR}" ]]; then
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
    expected="$(grep "  ${filename}" "${CHECKSUMS_FILE}" | awk '{print $1}')"
    if [[ -z "${expected}" ]]; then
        warn "No checksum entry for ${filename} — skipping verification"
        return 0
    fi
    if command -v sha256sum &>/dev/null; then
        actual="$(sha256sum "${file}" | awk '{print $1}')"
    elif command -v shasum &>/dev/null; then
        actual="$(shasum -a 256 "${file}" | awk '{print $1}')"
    else
        warn "Neither sha256sum nor shasum found — skipping verification"
        return 0
    fi
    if [[ "${expected}" != "${actual}" ]]; then
        die "Checksum mismatch for ${filename}: expected ${expected}, got ${actual}"
    fi
}

# ── Install: Gateway binary ──────────────────────────────────────────────────

install_gateway() {
    step "Installing gateway"

    mkdir -p "${INSTALL_DIR}"

    if [[ -n "${LOCAL_DIR}" ]]; then
        local artifact
        artifact="$(artifact_path "defenseclaw-gateway-${OS}-${ARCH_NORM}")"
        cp "${artifact}" "${INSTALL_DIR}/defenseclaw-gateway"
        chmod +x "${INSTALL_DIR}/defenseclaw-gateway"
    else
        local url tmp
        local tarball_name="defenseclaw_${RELEASE_VERSION}_${OS}_${ARCH_NORM}.tar.gz"
        url="$(artifact_path "${tarball_name}")"
        tmp="$(mktemp -d)"
        fetch_artifact "${url}" "${tmp}/gateway.tar.gz"
        verify_checksum "${tmp}/gateway.tar.gz" "${tarball_name}"
        tar -xzf "${tmp}/gateway.tar.gz" -C "${tmp}"
        cp "${tmp}/defenseclaw" "${INSTALL_DIR}/defenseclaw-gateway"
        chmod +x "${INSTALL_DIR}/defenseclaw-gateway"
        rm -rf "${tmp}"
    fi

    if [[ "${OS}" == "darwin" ]]; then
        codesign -f -s - "${INSTALL_DIR}/defenseclaw-gateway" 2>/dev/null || true
    fi

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
    if [[ -n "${LOCAL_DIR}" ]]; then
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

    mkdir -p "${INSTALL_DIR}"
    ln -sf "${DEFENSECLAW_VENV}/bin/defenseclaw" "${INSTALL_DIR}/defenseclaw"

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

    local dest="${DEFENSECLAW_HOME}/extensions/defenseclaw"
    rm -rf "${dest}"
    mkdir -p "${dest}"

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
    case "${QUICKSTART_MODE}" in
        action)  args+=(--mode action) ;;
        observe) args+=(--mode observe) ;;
    esac

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
    if [[ "${INSTALL_SANDBOX}" == true ]] && [[ "${OS}" == "linux" ]]; then
        printf "  Get started:\n\n"
        printf "    ${CYAN}defenseclaw init --sandbox${NC}\n"
    else
        printf "  Get started:\n\n"
        printf "    ${CYAN}defenseclaw init --enable-guardrail${NC}\n"
    fi
    echo ""
}

# ── Entry Point ───────────────────────────────────────────────────────────────

printf "\n"
printf "${BOLD}  DefenseClaw Installer${NC}\n"
printf "  ${DIM}Enterprise Governance for Agentic AI${NC}\n"

YES_MODE=false
LOCAL_DIR=""
INSTALL_SANDBOX=false
RUN_QUICKSTART=false
QUICKSTART_MODE="observe"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --sandbox) INSTALL_SANDBOX=true; shift ;;
        --local)
            [[ $# -lt 2 ]] && die "--local requires a directory argument"
            LOCAL_DIR="$(cd "$2" && pwd)" || die "Directory not found: $2"
            shift 2
            ;;
        --yes|-y) YES_MODE=true; shift ;;
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
            echo "  curl -LsSf https://raw.githubusercontent.com/cisco-ai-defense/defenseclaw/main/scripts/install.sh | bash"
            echo "  ./scripts/install.sh --local ./dist               # from local build"
            echo "  curl -LsSf <url>/install.sh | bash -s -- --yes    # non-interactive"
            echo "  curl ... | bash -s -- --sandbox                   # also install openshell-sandbox"
            echo "  curl ... | bash -s -- --quickstart                # run quickstart after install"
            echo ""
            echo "Options:"
            echo "  --sandbox             Also install openshell-sandbox (Linux only)"
            echo "  --local <dir>         Install from a local dist directory"
            echo "  --yes, -y             Skip all confirmation prompts"
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

if [[ -n "${LOCAL_DIR}" ]]; then
    info "Installing from local directory: ${LOCAL_DIR}"
fi

detect_platform
ensure_uv
ensure_python
resolve_version
install_gateway
install_python_cli
install_plugin
handle_openclaw

if [[ "${INSTALL_SANDBOX}" == true ]]; then
    if [[ "${OS}" != "linux" ]]; then
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
                "https://raw.githubusercontent.com/${REPO}/main/scripts/install-openshell-sandbox.sh" \
                | bash
        fi
    fi
fi

run_quickstart
ensure_path
print_success

}

main "$@"
