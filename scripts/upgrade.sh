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
# Downloads the gateway binary and Python CLI wheel from a GitHub release,
# runs version-specific migrations, and restarts services.
#
# Plugin installation is NOT handled here — it is part of the initial
# release install (install.sh) and is release-specific.
#
# Usage:
#   ./scripts/upgrade.sh [--yes] [--version VERSION] [--help]
#
# Options:
#   --yes, -y             Skip confirmation prompts
#   --version VERSION     Upgrade to a specific release (default: latest)
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

# ── Argument Parsing ──────────────────────────────────────────────────────────

YES=0
RELEASE_VERSION="${VERSION:-}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --yes|-y)   YES=1; shift ;;
        --version)
            [[ $# -lt 2 ]] && die "--version requires a value"
            RELEASE_VERSION="$2"; shift 2 ;;
        --help|-h)
            cat <<EOF

  DefenseClaw Upgrade Script

  Usage: $(basename "$0") [OPTIONS]

  Options:
    --yes, -y             Skip confirmation prompts
    --version VERSION     Upgrade to a specific release (e.g. 0.2.0)
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

if [[ -n "${RELEASE_VERSION}" ]]; then
    RELEASE_VERSION="${RELEASE_VERSION#v}"
    ok "Target version: ${RELEASE_VERSION}"
else
    info "Fetching latest release from GitHub..."
    RELEASE_VERSION=$(curl -sSf "https://api.github.com/repos/${REPO}/releases/latest" \
        | grep -oE '"tag_name": *"[^"]+"' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+') \
        || die "Failed to fetch latest release. Use --version x.y.z to specify explicitly."
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

# ── Artifact helper ───────────────────────────────────────────────────────────

fetch_artifact() {
    local url="$1" dest="$2"
    curl -sSfL "${url}" -o "${dest}" \
        || die "Failed to download: ${url}"
}

# ── Confirm ───────────────────────────────────────────────────────────────────

if [[ "${YES}" -eq 0 ]]; then
    printf "\n  This will:\n"
    printf "    1. Back up config files in ${BOLD}~/.defenseclaw/${NC}\n"
    printf "    2. Download and replace gateway binary and Python CLI wheel\n"
    printf "    3. Run version-specific migrations\n"
    printf "    4. Restart the gateway service\n"
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
fetch_artifact \
    "https://github.com/${REPO}/releases/download/${RELEASE_VERSION}/defenseclaw_${RELEASE_VERSION}_${OS}_${ARCH_NORM}.tar.gz" \
    "${tmp_gw}/gateway.tar.gz"
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
[[ -z "${UV_BIN}" ]] \
    && die "uv not found on PATH — cannot update Python CLI. Install: curl -LsSf https://astral.sh/uv/install.sh | sh"

if [[ ! -d "${DEFENSECLAW_VENV}" ]]; then
    step "Creating venv at ${DEFENSECLAW_VENV} ..."
    "${UV_BIN}" venv "${DEFENSECLAW_VENV}" --python 3.12
fi

VENV_PYTHON="${DEFENSECLAW_VENV}/bin/python"

step "Downloading Python CLI wheel for ${RELEASE_VERSION} ..."
whl_name="defenseclaw-${RELEASE_VERSION}-py3-none-any.whl"
tmp_whl="$(mktemp -d)"
fetch_artifact \
    "https://github.com/${REPO}/releases/download/${RELEASE_VERSION}/${whl_name}" \
    "${tmp_whl}/${whl_name}"
"${UV_BIN}" pip install --python "${VENV_PYTHON}" --quiet "${tmp_whl}/${whl_name}" \
    || die "Failed to install CLI wheel"
rm -rf "${tmp_whl}"

ln -sf "${DEFENSECLAW_VENV}/bin/defenseclaw" "${INSTALL_DIR}/defenseclaw"
ok "Python CLI replaced"

# ── Step 5: Run migrations ────────────────────────────────────────────────────

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

# ── Step 6: Start services ────────────────────────────────────────────────────

section "Starting Services"

step "Starting defenseclaw-gateway ..."
defenseclaw-gateway start && ok "Gateway started" || warn "Could not start gateway"

step "Restarting OpenClaw gateway ..."
openclaw gateway restart 2>/dev/null \
    && ok "OpenClaw gateway restarted" \
    || warn "Could not restart OpenClaw gateway automatically. Run: openclaw gateway restart"

# ── Done ──────────────────────────────────────────────────────────────────────

section "Upgrade Complete"

ok "DefenseClaw upgraded: ${CURRENT_VERSION} → ${RELEASE_VERSION}"
printf "\n"
printf "  Backup saved to: ${DIM}${BACKUP_DIR}${NC}\n"
printf "  Run ${BOLD}defenseclaw status${NC} to verify all components are healthy.\n"
printf "\n"

} # end main()

main "$@"
