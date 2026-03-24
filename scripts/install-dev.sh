#!/usr/bin/env bash
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
readonly RECOMMENDED_PYTHON_VERSION="3.11"

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
    
    # Try python3 first, then python
    for cmd in python3 python; do
        if command_exists "${cmd}"; then
            local ver
            ver="$(extract_version "$("${cmd}" --version 2>&1)")"
            if version_gte "${ver}" "${MIN_PYTHON_VERSION}"; then
                python_cmd="${cmd}"
                python_version="${ver}"
                break
            fi
        fi
    done
    
    if [[ -z "${python_cmd}" ]]; then
        log_warn "Python ${MIN_PYTHON_VERSION}+ not found."
        echo ""
        echo "  Install Python from https://www.python.org/downloads/"
        echo ""
        if [[ "${OS}" == "darwin" ]]; then
            echo "  Or via Homebrew:"
            echo "    brew install python@3.12"
            echo ""
        fi
        die "Python ${MIN_PYTHON_VERSION}+ is required."
    fi
    
    PYTHON_CMD="${python_cmd}"
    PYTHON_VERSION="${python_version}"
    
    if version_gte "${python_version}" "${RECOMMENDED_PYTHON_VERSION}"; then
        log_success "Python ${python_version} found (${RECOMMENDED_PYTHON_VERSION}+ recommended)"
    else
        log_success "Python ${python_version} found (>= ${MIN_PYTHON_VERSION} required)"
        log_warn "Python ${RECOMMENDED_PYTHON_VERSION}+ is recommended for best compatibility."
    fi
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
    
    # Check for golangci-lint (for development)
    if command_exists golangci-lint; then
        local lint_version
        lint_version="$(extract_version "$(golangci-lint --version 2>/dev/null)" || echo "unknown")"
        log_success "golangci-lint ${lint_version} found"
    else
        log_info "golangci-lint not found (optional, for linting)"
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
        uv venv "${VENV_DIR}"
    else
        "${PYTHON_CMD}" -m venv "${VENV_DIR}"
    fi
    
    log_success "Created virtual environment at ${VENV_DIR}"
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
    ${pip_cmd} -e "cli[tui]"
    
    log_success "Python CLI installed (editable mode)"
    
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
    build_go_gateway
    
    if [[ "${skip_install}" == false ]]; then
        install_go_gateway
    else
        log_info "Skipping gateway install (--skip-install)"
    fi
    
    print_next_steps
}

main "$@"
