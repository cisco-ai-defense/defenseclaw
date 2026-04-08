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
# DefenseClaw Upgrade Script
#
# Downloads release artifacts from GitHub and replaces the gateway binary,
# Python CLI wheel, and (when included in the release) the OpenClaw plugin.
# Runs version-specific migrations and restarts services.
# Does NOT require a local source checkout.
#
# Usage:
#   ./scripts/upgrade.sh [--yes] [--version VERSION] [--local <dir>] [--help]
#
# Options:
#   --yes, -y             Skip confirmation prompts
#   --version VERSION     Upgrade to a specific release (default: latest)
#   --local <dir>         Install from a local dist/ directory instead of GitHub
#   --skip-plugin         Skip plugin replacement even if an artifact is present
#   --help, -h            Show this help
#
# Environment variables:
#   VERSION               Same as --version
#   DEFENSECLAW_HOME      Override install directory (default: ~/.defenseclaw)
#   OPENCLAW_HOME         Override OpenClaw config dir (default: ~/.openclaw)
#
set -euo pipefail

main() {

# ── Configuration ─────────────────────────────────────────────────────────────

readonly DEFENSECLAW_HOME="${DEFENSECLAW_HOME:-${HOME}/.defenseclaw}"
readonly DEFENSECLAW_VENV="${DEFENSECLAW_HOME}/.venv"
readonly INSTALL_DIR="${HOME}/.local/bin"
readonly OPENCLAW_HOME="${OPENCLAW_HOME:-${HOME}/.openclaw}"
readonly BACKUP_ROOT="${DEFENSECLAW_HOME}/backups"
readonly REPO="cisco-ai-defense/defenseclaw"

# ── Terminal Formatting ───────────────────────────────────────────────────────

if [[ -t 1 ]] || [[ "${FORCE_COLOR:-}" == "1" ]]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
    BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'
    DIM='\033[2m'; NC='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; BLUE=''; CYAN=''; BOLD=''; DIM=''; NC=''
fi

# ── Logging ───────────────────────────────────────────────────────────────────

info()    { printf "${BLUE}  ▸${NC} %s\n" "$*"; }
ok()      { printf "${GREEN}  ✓${NC} %s\n" "$*"; }
warn()    { printf "${YELLOW}  !${NC} %s\n" "$*"; }
err()     { printf "${RED}  ✗${NC} %s\n" "$*" >&2; }
section() { printf "\n${BOLD}${CYAN}─── %s${NC}\n\n" "$*"; }
step()    { printf "  ${CYAN}→${NC} %s\n" "$*"; }

die() { err "$@"; exit 1; }
has() { command -v "$1" &>/dev/null; }

# ── Utilities ─────────────────────────────────────────────────────────────────

extract_version() {
    local input="${1:-}"
    echo "${input}" | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | awk 'NR==1' || true
}

# Returns 0 if the named artifact exists in the release, 1 otherwise.
# For GitHub releases: issues a HEAD request (no download).
# For local dir: checks for the file by glob pattern.
release_has_artifact() {
    local name="$1"
    if [[ -n "${LOCAL_DIR}" ]]; then
        ls "${LOCAL_DIR}"/${name} 2>/dev/null | head -1 | grep -q .
    else
        local url="https://github.com/${REPO}/releases/download/${RELEASE_VERSION}/${name}"
        curl -sSfL --head --output /dev/null "${url}" 2>/dev/null
    fi
}

# ── Argument Parsing ──────────────────────────────────────────────────────────

YES=0
LOCAL_DIR=""
RELEASE_VERSION="${VERSION:-}"
SKIP_PLUGIN=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --yes|-y)   YES=1; shift ;;
        --version)
            [[ $# -lt 2 ]] && die "--version requires a value"
            RELEASE_VERSION="$2"; shift 2 ;;
        --local)
            [[ $# -lt 2 ]] && die "--local requires a directory argument"
            LOCAL_DIR="$(cd "$2" && pwd)" || die "Directory not found: $2"
            shift 2 ;;
        --skip-plugin) SKIP_PLUGIN=1; shift ;;
        --help|-h)
            cat <<EOF

  DefenseClaw Upgrade Script

  Usage: $(basename "$0") [OPTIONS]

  Options:
    --yes, -y             Skip confirmation prompts
    --version VERSION     Upgrade to a specific release (e.g. 0.2.0)
    --local <dir>         Use a local dist/ directory instead of GitHub releases
    --skip-plugin         Skip plugin replacement even if an artifact is present
    --help, -h            Show this help

  Environment variables:
    VERSION               Same as --version
    DEFENSECLAW_HOME      Override install directory (default: ~/.defenseclaw)
    OPENCLAW_HOME         Override OpenClaw config dir (default: ~/.openclaw)

EOF
                exit 0 ;;
        *) err "Unknown option: $1"; exit 1 ;;
    esac
done

# ── Header ────────────────────────────────────────────────────────────────────

printf "\n"
printf "${BOLD}  DefenseClaw Upgrade${NC}\n"
printf "  ${DIM}Downloads release artifacts from GitHub and replaces installed files${NC}\n"
printf "\n"

# ── Platform Detection ────────────────────────────────────────────────────────

section "Detecting Platform"

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

# ── Resolve target release version ───────────────────────────────────────────

section "Resolving Release Version"

if [[ -n "${LOCAL_DIR}" ]]; then
    local_whl="$(ls "${LOCAL_DIR}"/defenseclaw-*.whl 2>/dev/null | head -1 || true)"
    if [[ -n "${local_whl}" ]]; then
        RELEASE_VERSION="$(basename "${local_whl}" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || echo "local")"
    else
        RELEASE_VERSION="${RELEASE_VERSION:-local}"
    fi
    info "Using local dist directory: ${LOCAL_DIR} (version ${RELEASE_VERSION})"
elif [[ -n "${RELEASE_VERSION}" ]]; then
    RELEASE_VERSION="${RELEASE_VERSION#v}"
    ok "Target version: ${RELEASE_VERSION}"
else
    info "Fetching latest release from GitHub..."
    RELEASE_VERSION=$(curl -sSf "https://api.github.com/repos/${REPO}/releases/latest" \
        | grep -oE '"tag_name": *"[^"]+"' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+') \
        || die "Failed to fetch latest release. Set VERSION=x.y.z or use --local <dir>."
    [[ -n "${RELEASE_VERSION}" ]] \
        || die "Could not parse latest release version. Use --version x.y.z to specify explicitly."
    ok "Latest release: ${RELEASE_VERSION}"
fi

# ── Detect currently installed version ───────────────────────────────────────

CURRENT_VERSION="unknown"
if has defenseclaw; then
    CURRENT_VERSION=$(defenseclaw --version 2>/dev/null \
        | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 \
        || python3 -c "from defenseclaw import __version__; print(__version__)" 2>/dev/null \
        || echo "unknown")
fi
CURRENT_VERSION="${CURRENT_VERSION:-unknown}"

ok "Installed version : ${CURRENT_VERSION}"
ok "Upgrade target    : ${RELEASE_VERSION}"

if [[ "${CURRENT_VERSION}" == "${RELEASE_VERSION}" && "${YES}" -eq 0 ]]; then
    printf "\n  Already at version ${RELEASE_VERSION}.\n"
    read -r -p "  Re-apply upgrade anyway? [y/N] " REPLY
    case "$REPLY" in
        [Yy]*) ;;
        *) echo "  Aborted."; exit 0 ;;
    esac
fi

# ── Probe which artifacts this release ships ──────────────────────────────────

tarball_name="defenseclaw-plugin-${RELEASE_VERSION}.tar.gz"

PLUGIN_AVAILABLE=0
if [[ "${SKIP_PLUGIN}" -eq 0 ]]; then
    step "Checking whether release ${RELEASE_VERSION} includes a plugin artifact ..."
    if release_has_artifact "${tarball_name}"; then
        PLUGIN_AVAILABLE=1
        ok "Plugin artifact found — will be replaced"
    else
        warn "No plugin artifact in this release — plugin will not be touched"
    fi
fi

# ── Artifact helpers ──────────────────────────────────────────────────────────

artifact_path() {
    local name="$1"
    if [[ -n "${LOCAL_DIR}" ]]; then
        local match
        match="$(ls "${LOCAL_DIR}"/${name} 2>/dev/null | head -1 || true)"
        [[ -z "${match}" ]] && die "Artifact not found: ${LOCAL_DIR}/${name}"
        echo "${match}"
    else
        echo "https://github.com/${REPO}/releases/download/${RELEASE_VERSION}/${name}"
    fi
}

fetch_artifact() {
    local source="$1" dest="$2"
    if [[ -n "${LOCAL_DIR}" ]]; then
        cp "${source}" "${dest}"
    else
        curl -sSfL "${source}" -o "${dest}" \
            || die "Failed to download: ${source}"
    fi
}

# ── Confirm ───────────────────────────────────────────────────────────────────

if [[ "${YES}" -eq 0 ]]; then
    printf "\n  This will:\n"
    printf "    1. Back up config files in ${BOLD}~/.defenseclaw/${NC}\n"
    printf "    2. Download and replace gateway binary and Python CLI wheel\n"
    if [[ "${PLUGIN_AVAILABLE}" -eq 1 ]]; then
        printf "    3. Download and replace OpenClaw plugin (included in this release)\n"
    else
        printf "    3. ${DIM}Skip plugin (not included in this release)${NC}\n"
    fi
    printf "    4. Run version-specific migrations\n"
    printf "    5. Restart services\n"
    printf "       ${DIM}Source: github.com/${REPO}/releases/tag/${RELEASE_VERSION}${NC}\n\n"
    read -r -p "  Proceed? [y/N] " REPLY
    case "$REPLY" in
        [Yy]*) ;;
        *) echo "  Aborted."; exit 0 ;;
    esac
fi

# ── Step 1: Create backup ─────────────────────────────────────────────────────

section "Creating Backup"

TIMESTAMP=$(date +%Y%m%dT%H%M%S)
BACKUP_DIR="${BACKUP_ROOT}/upgrade-${TIMESTAMP}"
mkdir -p "${BACKUP_DIR}"

if [[ -d "${DEFENSECLAW_HOME}" ]]; then
    for f in config.yaml .env guardrail_runtime.json device.key; do
        src="${DEFENSECLAW_HOME}/$f"
        [[ -f "${src}" ]] && cp "${src}" "${BACKUP_DIR}/" && ok "Backed up: $f"
    done
    if [[ -d "${DEFENSECLAW_HOME}/policies" ]]; then
        cp -r "${DEFENSECLAW_HOME}/policies" "${BACKUP_DIR}/policies"
        ok "Backed up: policies/"
    fi
fi

OPENCLAW_JSON="${OPENCLAW_HOME}/openclaw.json"
if [[ -f "${OPENCLAW_JSON}" ]]; then
    cp "${OPENCLAW_JSON}" "${BACKUP_DIR}/openclaw.json"
    ok "Backed up: openclaw.json"
fi

ok "Backup saved to: ${BACKUP_DIR}"

# ── Step 2: Stop services ─────────────────────────────────────────────────────

section "Stopping Services"

step "Stopping defenseclaw-gateway ..."
defenseclaw-gateway stop 2>/dev/null && ok "Gateway stopped" || warn "Gateway was not running"

# ── Step 3: Download and replace gateway binary ───────────────────────────────

section "Replacing Gateway Binary"

step "Downloading defenseclaw-gateway from release ${RELEASE_VERSION} ..."
mkdir -p "${INSTALL_DIR}"

tmp_gw="$(mktemp -d)"
url="$(artifact_path "defenseclaw_${RELEASE_VERSION}_${OS}_${ARCH_NORM}.tar.gz")"
fetch_artifact "${url}" "${tmp_gw}/gateway.tar.gz"
tar -xzf "${tmp_gw}/gateway.tar.gz" -C "${tmp_gw}"
cp "${tmp_gw}/defenseclaw" "${INSTALL_DIR}/defenseclaw-gateway"
chmod +x "${INSTALL_DIR}/defenseclaw-gateway"
rm -rf "${tmp_gw}"

if [[ "${OS}" == "darwin" ]]; then
    codesign -f -s - "${INSTALL_DIR}/defenseclaw-gateway" 2>/dev/null || true
fi

ok "Gateway binary replaced"

# ── Step 4: Replace Python CLI from wheel ────────────────────────────────────

section "Replacing Python CLI"

UV_BIN="$(command -v uv 2>/dev/null || true)"
if [[ -z "${UV_BIN}" ]]; then
    die "uv not found on PATH — cannot update Python CLI. Install: curl -LsSf https://astral.sh/uv/install.sh | sh"
fi

if [[ ! -d "${DEFENSECLAW_VENV}" ]]; then
    step "Creating venv at ${DEFENSECLAW_VENV} ..."
    "${UV_BIN}" venv "${DEFENSECLAW_VENV}" --python 3.12
fi

VENV_PYTHON="${DEFENSECLAW_VENV}/bin/python"

step "Downloading Python CLI wheel for ${RELEASE_VERSION} ..."
whl_name="defenseclaw-${RELEASE_VERSION}-py3-none-any.whl"
tmp_whl="$(mktemp -d)"
fetch_artifact "$(artifact_path "${whl_name}")" "${tmp_whl}/${whl_name}"
"${UV_BIN}" pip install --python "${VENV_PYTHON}" --quiet "${tmp_whl}/${whl_name}" \
    || die "Failed to install CLI wheel"
rm -rf "${tmp_whl}"

ln -sf "${DEFENSECLAW_VENV}/bin/defenseclaw" "${INSTALL_DIR}/defenseclaw"
ok "Python CLI replaced"

# ── Step 5: Replace OpenClaw plugin (only when included in this release) ──────

if [[ "${PLUGIN_AVAILABLE}" -eq 1 ]]; then
    section "Replacing OpenClaw Plugin"

    step "Downloading plugin tarball for ${RELEASE_VERSION} ..."
    plugin_dest="${DEFENSECLAW_HOME}/extensions/defenseclaw"
    plugin_backup="${BACKUP_DIR}/extensions-defenseclaw"

    if [[ -d "${plugin_dest}" ]]; then
        cp -r "${plugin_dest}" "${plugin_backup}"
        ok "Backed up existing plugin to backup dir"
        rm -rf "${plugin_dest}"
    fi
    mkdir -p "${plugin_dest}"

    tmp_plugin="$(mktemp -d)"
    fetch_artifact "$(artifact_path "${tarball_name}")" "${tmp_plugin}/${tarball_name}"
    tar -xzf "${tmp_plugin}/${tarball_name}" -C "${plugin_dest}"
    rm -rf "${tmp_plugin}"

    ok "Plugin replaced"
elif [[ "${SKIP_PLUGIN}" -eq 1 ]]; then
    info "Plugin replacement skipped (--skip-plugin)"
else
    info "Plugin unchanged (not included in release ${RELEASE_VERSION})"
fi

# ── Step 6: Run migrations ────────────────────────────────────────────────────

section "Running Migrations"

MIGRATION_COUNT=$(python3 -c "
from defenseclaw.migrations import run_migrations
count = run_migrations('${CURRENT_VERSION}', '${RELEASE_VERSION}', '${OPENCLAW_HOME}')
print(count)
" 2>/dev/null || echo "0")

if [[ "${MIGRATION_COUNT}" -eq 0 ]]; then
    ok "No migrations needed"
else
    ok "Applied ${MIGRATION_COUNT} migration(s)"
fi

# ── Step 7: Start services ────────────────────────────────────────────────────

section "Starting Services"

step "Starting defenseclaw-gateway ..."
defenseclaw-gateway start && ok "Gateway started" || warn "Could not start gateway"

if [[ "${PLUGIN_AVAILABLE}" -eq 1 ]]; then
    step "Restarting OpenClaw gateway to load updated plugin ..."
    openclaw gateway restart 2>/dev/null \
        && ok "OpenClaw gateway restarted — DefenseClaw plugin loaded" \
        || warn "Could not restart OpenClaw gateway automatically. Run: openclaw gateway restart"
fi

# ── Done ──────────────────────────────────────────────────────────────────────

section "Upgrade Complete"

ok "DefenseClaw upgraded: ${CURRENT_VERSION} → ${RELEASE_VERSION}"
printf "\n"
printf "  Backup saved to: ${DIM}${BACKUP_DIR}${NC}\n"
printf "  Run ${BOLD}defenseclaw status${NC} to verify all components are healthy.\n"
printf "\n"

} # end main()

main "$@"
