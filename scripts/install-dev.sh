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
# DefenseClaw Development Installation Script
#
# Installs DefenseClaw from source with all dependencies.
# Run from the repository root: ./scripts/install-dev.sh
#
set -euo pipefail

# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

readonly MIN_GO_VERSION="1.22"
readonly MIN_PYTHON_VERSION="3.10"
readonly MAX_PYTHON_VERSION="3.13"
readonly PREFERRED_PYTHON_VERSIONS=("3.12" "3.11" "3.13" "3.10")

readonly VENV_DIR="${REPO_ROOT}/.venv"
readonly INSTALL_DIR="${HOME}/.local/bin"

readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly BOLD='\033[1m'
readonly NC='\033[0m'

# -----------------------------------------------------------------------------
# Utility Functions
# -----------------------------------------------------------------------------

log_info()    { echo -e "${BLUE}[INFO]${NC} $*"; }
log_success() { echo -e "${GREEN}[OK]${NC} $*"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }
log_step()    { echo -e "\n${BOLD}${CYAN}==> $*${NC}"; }

die() {
    log_error "$@"
    exit 1
}

command_exists() {
    command -v "$1" &> /dev/null
}

version_gte() {
    # Returns 0 if $1 >= $2 (version comparison)
    local v1="${1:-0}"
    local v2="${2:-0}"
    printf '%s\n%s' "${v2}" "${v1}" | sort -V -C
}

version_lte() {
    # Returns 0 if $1 <= $2 (version comparison)
    local v1="${1:-0}"
    local v2="${2:-0}"
    printf '%s\n%s' "${v1}" "${v2}" | sort -V -C
}

version_in_range() {
    # Returns 0 if $1 is between $2 (min) and $3 (max) inclusive
    local ver="${1:-0}"
    local min="${2:-0}"
    local max="${3:-999}"
    version_gte "${ver}" "${min}" && version_lte "${ver}" "${max}"
}

extract_version() {
    # Extract version number from string (e.g., "go1.23.0" -> "1.23.0")
    local input="${1:-}"
    if [[ -z "${input}" ]]; then
        echo "0.0.0"
        return
    fi
    local ver
    # Use awk instead of head to avoid SIGPIPE issues
    ver="$(echo "${input}" | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' 2>/dev/null | awk 'NR==1' || true)"
    if [[ -z "${ver}" ]]; then
        echo "0.0.0"
    else
        echo "${ver}"
    fi
}

# -----------------------------------------------------------------------------
# Dependency Checks
# -----------------------------------------------------------------------------

check_os() {
    log_step "Detecting Operating System"
    
    OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
    ARCH="$(uname -m)"
    
    case "${ARCH}" in
        x86_64)  ARCH_NORMALIZED="amd64" ;;
        aarch64) ARCH_NORMALIZED="arm64" ;;
        arm64)   ARCH_NORMALIZED="arm64" ;;
        *)       die "Unsupported architecture: ${ARCH}" ;;
    esac
    
    case "${OS}" in
        darwin)
            OS_NAME="macOS"
            PLATFORM="${OS}-${ARCH_NORMALIZED}"
            ;;
        linux)
            OS_NAME="Linux"
            PLATFORM="${OS}-${ARCH_NORMALIZED}"
            ;;
        *)
            die "Unsupported operating system: ${OS}"
            ;;
    esac
    
    log_success "Detected ${OS_NAME} (${PLATFORM})"
}

check_git() {
    log_step "Checking Git"
    
    if ! command_exists git; then
        die "Git is not installed. Install it from https://git-scm.com/"
    fi
    
    local git_version
    git_version="$(extract_version "$(git --version)")"
    log_success "Git ${git_version} found"
}

check_go() {
    log_step "Checking Go"
    
    if ! command_exists go; then
        log_warn "Go is not installed."
        echo ""
        echo "  Install Go ${MIN_GO_VERSION}+ from https://go.dev/dl/"
        echo ""
        if [[ "${OS}" == "darwin" ]]; then
            echo "  Or via Homebrew:"
            echo "    brew install go"
            echo ""
        fi
        die "Go is required to build the gateway binary."
    fi
    
    local go_version_raw go_version
    go_version_raw="$(go version)"
    go_version="$(extract_version "${go_version_raw}")"
    
    if ! version_gte "${go_version}" "${MIN_GO_VERSION}"; then
        die "Go ${go_version} found, but ${MIN_GO_VERSION}+ is required. Please upgrade."
    fi
    
    log_success "Go ${go_version} found (>= ${MIN_GO_VERSION} required)"
}

check_python() {
    log_step "Checking Python"
    
    local python_cmd=""
    local python_version=""
    
    # Strategy: prefer stable Python versions (3.12, 3.11) over bleeding-edge (3.14+)
    # Many packages don't have wheels for the newest Python versions yet.
    
    # 1. If uv is available, try to find preferred versions via uv
    if command_exists uv; then
        for preferred in "${PREFERRED_PYTHON_VERSIONS[@]}"; do
            local uv_python
            uv_python="$(uv python find "${preferred}" 2>/dev/null || true)"
            if [[ -n "${uv_python}" ]] && [[ -x "${uv_python}" ]]; then
                local ver
                ver="$(extract_version "$("${uv_python}" --version 2>&1)")"
                if version_in_range "${ver}" "${MIN_PYTHON_VERSION}" "${MAX_PYTHON_VERSION}"; then
                    python_cmd="${uv_python}"
                    python_version="${ver}"
                    log_info "Found Python ${ver} via uv"
                    break
                fi
            fi
        done
    fi
    
    # 2. Try pythonX.Y commands for preferred versions
    if [[ -z "${python_cmd}" ]]; then
        for preferred in "${PREFERRED_PYTHON_VERSIONS[@]}"; do
            local cmd="python${preferred}"
            if command_exists "${cmd}"; then
                local ver
                ver="$(extract_version "$("${cmd}" --version 2>&1)")"
                if version_in_range "${ver}" "${MIN_PYTHON_VERSION}" "${MAX_PYTHON_VERSION}"; then
                    python_cmd="${cmd}"
                    python_version="${ver}"
                    break
                fi
            fi
        done
    fi
    
    # 3. Fall back to python3/python, but only if within supported range
    if [[ -z "${python_cmd}" ]]; then
        for cmd in python3 python; do
            if command_exists "${cmd}"; then
                local ver
                ver="$(extract_version "$("${cmd}" --version 2>&1)")"
                if version_in_range "${ver}" "${MIN_PYTHON_VERSION}" "${MAX_PYTHON_VERSION}"; then
                    python_cmd="${cmd}"
                    python_version="${ver}"
                    break
                elif version_gte "${ver}" "${MIN_PYTHON_VERSION}"; then
                    # Version is too new — warn but don't use it
                    log_warn "Python ${ver} found but may be too new (max supported: ${MAX_PYTHON_VERSION})"
                    log_warn "Some dependencies may not have wheels for Python ${ver} yet."
                fi
            fi
        done
    fi
    
    if [[ -z "${python_cmd}" ]]; then
        log_warn "Python ${MIN_PYTHON_VERSION}-${MAX_PYTHON_VERSION} not found."
        echo ""
        echo "  Install a supported Python version:"
        echo ""
        if [[ "${OS}" == "darwin" ]]; then
            echo "    brew install python@3.12"
            echo ""
            echo "  Or if you have uv installed:"
            echo "    uv python install 3.12"
            echo ""
        else
            echo "    https://www.python.org/downloads/"
            echo ""
        fi
        die "Python ${MIN_PYTHON_VERSION}-${MAX_PYTHON_VERSION} is required."
    fi
    
    PYTHON_CMD="${python_cmd}"
    PYTHON_VERSION="${python_version}"
    
    log_success "Python ${python_version} found (supported: ${MIN_PYTHON_VERSION}-${MAX_PYTHON_VERSION})"
}

check_uv_or_pip() {
    log_step "Checking Package Manager (uv/pip)"
    
    if command_exists uv; then
        local uv_version
        uv_version="$(extract_version "$(uv --version)")"
        PACKAGE_MANAGER="uv"
        log_success "uv ${uv_version} found (recommended)"
    elif command_exists pip3 || command_exists pip; then
        local pip_cmd pip_version
        if command_exists pip3; then
            pip_cmd="pip3"
        else
            pip_cmd="pip"
        fi
        pip_version="$(extract_version "$(${pip_cmd} --version)")"
        PACKAGE_MANAGER="pip"
        log_success "pip ${pip_version} found"
        log_warn "Consider installing uv for faster installs: https://docs.astral.sh/uv/"
    else
        die "Neither uv nor pip found. Install uv from https://docs.astral.sh/uv/"
    fi
}

check_optional_deps() {
    log_step "Checking Optional Dependencies"
    
    # Check for make
    if command_exists make; then
        local make_version
        make_version="$(extract_version "$(make --version 2>/dev/null | head -1)" || echo "unknown")"
        log_success "make found (version ${make_version:-unknown})"
    else
        log_warn "make not found — you can still build manually with 'go build'"
    fi
    
    # Check for golangci-lint
    if command_exists golangci-lint; then
        local lint_version
        lint_version="$(extract_version "$(golangci-lint --version 2>/dev/null)" || echo "unknown")"
        log_success "golangci-lint ${lint_version} found"
    else
        log_info "golangci-lint not found — will install"
    fi
    
    # Check for OPA
    if command_exists opa; then
        local opa_version
        opa_version="$(extract_version "$(opa version 2>/dev/null)" || echo "unknown")"
        log_success "opa ${opa_version} found"
    else
        log_info "opa not found — will install"
    fi
}

print_dependency_summary() {
    log_step "Dependency Summary"
    echo ""
    echo "  Platform:        ${PLATFORM}"
    echo "  Go:              $(go version | awk '{print $3}')"
    echo "  Python:          ${PYTHON_CMD} ${PYTHON_VERSION}"
    echo "  Package Manager: ${PACKAGE_MANAGER}"
    echo ""
}

# -----------------------------------------------------------------------------
# Installation Steps
# -----------------------------------------------------------------------------

setup_python_venv() {
    log_step "Setting Up Python Virtual Environment"
    
    if [[ -d "${VENV_DIR}" ]]; then
        log_info "Virtual environment exists at ${VENV_DIR}"
        if [[ "${YES_MODE:-false}" == true ]]; then
            log_info "Keeping existing virtual environment (--yes mode)."
            return 0
        fi
        read -rp "  Recreate it? [y/N] " response
        if [[ "${response}" =~ ^[Yy]$ ]]; then
            rm -rf "${VENV_DIR}"
        else
            log_info "Keeping existing virtual environment."
            return 0
        fi
    fi
    
    if [[ "${PACKAGE_MANAGER}" == "uv" ]]; then
        # Explicitly specify the Python version to avoid using bleeding-edge versions
        uv venv "${VENV_DIR}" --python "${PYTHON_VERSION}"
        log_success "Created virtual environment at ${VENV_DIR} (Python ${PYTHON_VERSION} via uv)"
    else
        "${PYTHON_CMD}" -m venv "${VENV_DIR}"
        log_success "Created virtual environment at ${VENV_DIR}"
    fi
}

install_python_cli() {
    log_step "Installing Python CLI"
    
    local pip_cmd
    if [[ "${PACKAGE_MANAGER}" == "uv" ]]; then
        pip_cmd="uv pip install --python ${VENV_DIR}/bin/python"
    else
        pip_cmd="${VENV_DIR}/bin/pip install"
        # Upgrade pip first
        "${VENV_DIR}/bin/pip" install --upgrade pip
    fi
    
    # Install the CLI in editable mode with TUI extras
    cd "${REPO_ROOT}"
    ${pip_cmd} -e ".[tui]"
    
    log_success "Python CLI installed (editable mode)"
    mkdir -p "${INSTALL_DIR}"
    ln -sf "${VENV_DIR}/bin/defenseclaw" "${INSTALL_DIR}/defenseclaw"
    log_success "Linked defenseclaw into ${INSTALL_DIR}"
    
    # Note: cisco-ai-skill-scanner requires additional dependencies.
    # Users can manually install: pip install cisco-ai-skill-scanner
    log_info "Scanner dependencies: install manually with pip install cisco-ai-skill-scanner"
    
    # Install dev dependencies (ruff, pytest, pytest-cov)
    log_info "Installing Python dev dependencies..."
    if [[ "${PACKAGE_MANAGER}" == "uv" ]]; then
        uv pip install --group dev --python "${VENV_DIR}/bin/python"
    else
        ${pip_cmd} ruff pytest pytest-cov
    fi
    log_success "Dev dependencies installed"

    # Verify the CLI works
    if "${VENV_DIR}/bin/defenseclaw" --help &> /dev/null; then
        log_success "CLI verification passed"
    else
        log_warn "CLI installed but --help check failed"
    fi
}

build_go_gateway() {
    log_step "Building Go Gateway Binary"
    
    cd "${REPO_ROOT}"
    
    # Fetch dependencies
    log_info "Fetching Go dependencies..."
    go mod download
    
    # Determine build target
    local binary_name="defenseclaw-gateway"
    local ldflags="-X main.version=dev-$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")"
    
    log_info "Building ${binary_name} for ${PLATFORM}..."
    
    GOOS="${OS}" GOARCH="${ARCH_NORMALIZED}" go build \
        -ldflags "${ldflags}" \
        -o "${binary_name}" \
        ./cmd/defenseclaw
    
    if [[ -f "${binary_name}" ]]; then
        log_success "Built ${binary_name}"
        chmod +x "${binary_name}"
    else
        die "Build failed — binary not created"
    fi
}

install_go_gateway() {
    log_step "Installing Go Gateway"
    
    local binary_name="defenseclaw-gateway"
    local src="${REPO_ROOT}/${binary_name}"
    local dest="${INSTALL_DIR}/${binary_name}"
    
    if [[ ! -f "${src}" ]]; then
        die "Binary ${src} not found. Run build first."
    fi
    
    mkdir -p "${INSTALL_DIR}"
    cp "${src}" "${dest}"
    chmod +x "${dest}"
    
    # Re-sign on macOS (copying invalidates adhoc signature)
    if [[ "${OS}" == "darwin" ]]; then
        codesign -f -s - "${dest}" 2>/dev/null || true
    fi
    
    log_success "Installed ${binary_name} to ${dest}"
    
    # Check if INSTALL_DIR is in PATH
    if ! echo "${PATH}" | grep -q "${INSTALL_DIR}"; then
        log_warn "${INSTALL_DIR} is not in your PATH"
        echo ""
        echo "  Add this to your shell profile (~/.bashrc, ~/.zshrc, etc.):"
        echo ""
        echo "    export PATH=\"${INSTALL_DIR}:\$PATH\""
        echo ""
    fi
}

install_dev_tools() {
    log_step "Installing Dev Tools"
    
    # golangci-lint
    if command_exists golangci-lint; then
        log_success "golangci-lint already installed"
    else
        log_info "Installing golangci-lint..."
        go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.11.0
        if command_exists golangci-lint; then
            log_success "golangci-lint installed"
        else
            log_warn "golangci-lint installed to $(go env GOPATH)/bin — ensure it is in your PATH"
        fi
    fi
    
    # OPA
    if command_exists opa; then
        log_success "opa already installed"
    else
        log_info "Installing opa..."
        go install github.com/open-policy-agent/opa@latest
        if command_exists opa; then
            log_success "opa installed"
        else
            log_warn "opa installed to $(go env GOPATH)/bin — ensure it is in your PATH"
        fi
    fi
}

print_next_steps() {
    log_step "Installation Complete"
    
    echo ""
    echo -e "  ${BOLD}Next steps:${NC}"
    echo ""
    echo -e "  1. Activate the Python environment:"
    echo -e "     ${CYAN}source ${VENV_DIR}/bin/activate${NC}"
    echo ""
    echo -e "  2. Initialize DefenseClaw:"
    echo -e "     ${CYAN}defenseclaw init${NC}"
    echo ""
    echo -e "  3. Start the gateway daemon:"
    echo -e "     ${CYAN}defenseclaw-gateway start${NC}"
    echo ""
    echo -e "  4. Check status:"
    echo -e "     ${CYAN}defenseclaw-gateway status${NC}"
    echo ""
    echo -e "  ${BOLD}Gateway daemon commands:${NC}"
    echo ""
    echo -e "  • Start daemon in background:"
    echo -e "    ${CYAN}defenseclaw-gateway start${NC}"
    echo ""
    echo -e "  • Stop daemon:"
    echo -e "    ${CYAN}defenseclaw-gateway stop${NC}"
    echo ""
    echo -e "  • Restart daemon:"
    echo -e "    ${CYAN}defenseclaw-gateway restart${NC}"
    echo ""
    echo -e "  • Check daemon health:"
    echo -e "    ${CYAN}defenseclaw-gateway status${NC}"
    echo ""
    echo -e "  • Run in foreground (for debugging):"
    echo -e "    ${CYAN}./defenseclaw-gateway${NC}"
    echo ""
    echo -e "  • View daemon logs:"
    echo -e "    ${CYAN}tail -f ~/.defenseclaw/gateway.log${NC}"
    echo ""
    echo -e "  ${BOLD}Development commands:${NC}"
    echo ""
    echo -e "  • Run Python CLI from source:"
    echo -e "    ${CYAN}source .venv/bin/activate && defenseclaw --help${NC}"
    echo ""
    echo -e "  • Run tests:"
    echo -e "    ${CYAN}make test${NC}"
    echo ""
    echo -e "  • Rebuild gateway after changes:"
    echo -e "    ${CYAN}make gateway${NC}"
    echo ""
    
    if [[ "${OS}" == "darwin" ]]; then
        echo -e "  ${YELLOW}Note:${NC} OpenShell sandbox is not available on macOS."
        echo "  Scanning, governance, and audit features work normally."
        echo ""
    fi
}

# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------

main() {
    echo ""
    echo -e "${BOLD}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}║  DefenseClaw Development Installation                          ║${NC}"
    echo -e "${BOLD}║  Enterprise Governance for Agentic AI                          ║${NC}"
    echo -e "${BOLD}╚════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    # Change to repo root
    cd "${REPO_ROOT}"
    
    # Verify we're in the right directory
    if [[ ! -f "go.mod" ]] || [[ ! -d "cli" ]]; then
        die "This script must be run from the DefenseClaw repository root."
    fi
    
    # Parse arguments
    local skip_install=false
    local check_only=false
    local yes_mode=false
    
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --skip-install)
                skip_install=true
                shift
                ;;
            --check)
                check_only=true
                shift
                ;;
            --yes|-y)
                yes_mode=true
                shift
                ;;
            --help|-h)
                echo "Usage: $0 [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  --skip-install   Build only, don't install to ${INSTALL_DIR}"
                echo "  --check          Check dependencies only, don't install anything"
                echo "  --yes, -y        Skip confirmation prompts"
                echo "  --help, -h       Show this help message"
                exit 0
                ;;
            *)
                die "Unknown option: $1. Use --help for usage."
                ;;
        esac
    done
    
    # Check dependencies
    check_os
    check_git
    check_go
    check_python
    check_uv_or_pip
    check_optional_deps
    print_dependency_summary
    
    # Exit early if only checking dependencies
    if [[ "${check_only}" == true ]]; then
        log_success "All required dependencies are present."
        exit 0
    fi
    
    # Confirm before proceeding
    if [[ "${yes_mode}" == false ]]; then
        echo ""
        read -rp "Proceed with installation? [Y/n] " response
        if [[ "${response}" =~ ^[Nn]$ ]]; then
            log_info "Installation cancelled."
            exit 0
        fi
    else
        log_info "Proceeding with installation (--yes mode)"
    fi
    
    # Export yes_mode for use in functions
    YES_MODE="${yes_mode}"
    export YES_MODE
    
    # Install
    setup_python_venv
    install_python_cli
    install_dev_tools
    build_go_gateway
    
    if [[ "${skip_install}" == false ]]; then
        install_go_gateway
    else
        log_info "Skipping gateway install (--skip-install)"
    fi
    
    print_next_steps
}

main "$@"
