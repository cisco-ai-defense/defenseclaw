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
# Replaces changed files (gateway binary, Python CLI, TS plugin), runs
# version-specific migrations, and restarts services. Does NOT uninstall
# or reinstall from scratch.
#
# Usage:
#   ./scripts/upgrade.sh [--source-dir <dir>] [--skip-pull] [--yes] [--help]
#
# Options:
#   --source-dir <dir>  Path to the defenseclaw source repository.
#                       Defaults to the parent directory of this script.
#   --skip-pull         Skip `git pull` before rebuilding
#   --yes, -y           Skip confirmation prompts
#   --help, -h          Show this help
#
set -euo pipefail

main() {

# ── Configuration ─────────────────────────────────────────────────────────────

readonly DEFENSECLAW_HOME="${DEFENSECLAW_HOME:-${HOME}/.defenseclaw}"
readonly DEFENSECLAW_VENV="${DEFENSECLAW_HOME}/.venv"
readonly OPENCLAW_HOME="${OPENCLAW_HOME:-${HOME}/.openclaw}"
readonly BACKUP_ROOT="${DEFENSECLAW_HOME}/backups"

# ── Terminal Formatting ───────────────────────────────────────────────────────

if [[ -t 1 ]] || [[ "${FORCE_COLOR:-}" == "1" ]]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
    BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'
    DIM='\033[2m'; NC='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; BLUE=''; CYAN=''; BOLD=''; DIM=''; NC=''
fi

# ── Logging ───────────────────────────────────────────────────────────────────

info()    { echo -e "  ${GREEN}✓${NC} $*"; }
warn()    { echo -e "  ${YELLOW}⚠${NC} $*"; }
error()   { echo -e "  ${RED}✗${NC} $*" >&2; }
section() { echo; echo -e "  ${BOLD}── $* ${DIM}─────────────────────────────────────────────────${NC}"; echo; }
step()    { echo -e "  ${CYAN}→${NC} $*"; }

# ── Argument Parsing ──────────────────────────────────────────────────────────

SOURCE_DIR=""
SKIP_PULL=0
YES=0

# Default source directory: parent of scripts/
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_SOURCE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --source-dir) SOURCE_DIR="$2"; shift 2 ;;
        --skip-pull)  SKIP_PULL=1; shift ;;
        --yes|-y)     YES=1; shift ;;
        --help|-h)
            cat <<EOF

  DefenseClaw Upgrade Script

  Usage: $(basename "$0") [OPTIONS]

  Options:
    --source-dir <dir>  Path to defenseclaw source repo (default: $DEFAULT_SOURCE_DIR)
    --skip-pull         Skip git pull
    --yes, -y           Skip confirmation prompts
    --help, -h          Show this help

EOF
            exit 0
            ;;
        *) error "Unknown option: $1"; exit 1 ;;
    esac
done

SOURCE_DIR="${SOURCE_DIR:-$DEFAULT_SOURCE_DIR}"

# ── Header ────────────────────────────────────────────────────────────────────

echo
echo -e "  ${BOLD}DefenseClaw Upgrade${NC}"
echo -e "  ${DIM}Replaces files, runs migrations, and restarts services${NC}"
echo

# ── Pre-flight Checks ─────────────────────────────────────────────────────────

section "Pre-flight Checks"

if [[ ! -d "$SOURCE_DIR" ]]; then
    error "Source directory not found: $SOURCE_DIR"
    error "Use --source-dir <dir> to specify the repository path."
    exit 1
fi
if [[ ! -f "$SOURCE_DIR/Makefile" ]]; then
    error "No Makefile found in $SOURCE_DIR — is this the defenseclaw repository?"
    exit 1
fi
info "Source directory: $SOURCE_DIR"

# ── Detect versions ──────────────────────────────────────────────────────────

CURRENT_VERSION=""
if command -v defenseclaw >/dev/null 2>&1; then
    CURRENT_VERSION=$(python3 -c "
try:
    from defenseclaw import __version__
    print(__version__)
except Exception:
    print('unknown')
" 2>/dev/null || echo "unknown")
fi
CURRENT_VERSION="${CURRENT_VERSION:-unknown}"

NEW_VERSION=$(python3 -c "
import re
with open('$SOURCE_DIR/pyproject.toml') as f:
    for line in f:
        m = re.match(r'^version\s*=\s*[\"'']([^\"'']+)', line.strip())
        if m: print(m.group(1)); break
" 2>/dev/null || echo "unknown")

info "Installed version: $CURRENT_VERSION"
info "New version:       $NEW_VERSION"

if [[ "$CURRENT_VERSION" == "$NEW_VERSION" && "$YES" -eq 0 ]]; then
    echo
    echo -e "  Already at the latest version."
    read -r -p "  Re-apply upgrade anyway? [y/N] " REPLY
    case "$REPLY" in
        [Yy]*) ;;
        *) echo "  Aborted."; exit 0 ;;
    esac
fi

# ── Confirm ───────────────────────────────────────────────────────────────────

if [[ "$YES" -eq 0 ]]; then
    echo
    echo -e "  This will:"
    echo -e "    1. Back up ${BOLD}~/.defenseclaw/${NC} and ${BOLD}~/.openclaw/openclaw.json${NC}"
    if [[ "$SKIP_PULL" -eq 0 ]]; then
        echo -e "    2. Pull latest changes from git"
    fi
    echo -e "    3. Replace gateway binary, Python CLI, and plugin files"
    echo -e "    4. Run version-specific migrations"
    echo -e "    5. Restart services"
    echo
    read -r -p "  Proceed? [y/N] " REPLY
    case "$REPLY" in
        [Yy]*) ;;
        *) echo "  Aborted."; exit 0 ;;
    esac
fi

# ── Step 1: Create backup ────────────────────────────────────────────────────

section "Creating Backup"

TIMESTAMP=$(date +%Y%m%dT%H%M%S)
BACKUP_DIR="${BACKUP_ROOT}/upgrade-${TIMESTAMP}"
mkdir -p "$BACKUP_DIR"

if [[ -d "$DEFENSECLAW_HOME" ]]; then
    for f in config.yaml .env guardrail_runtime.json device.key; do
        src="${DEFENSECLAW_HOME}/$f"
        [[ -f "$src" ]] && cp "$src" "$BACKUP_DIR/" && info "Backed up: $f"
    done
    if [[ -d "${DEFENSECLAW_HOME}/policies" ]]; then
        cp -r "${DEFENSECLAW_HOME}/policies" "${BACKUP_DIR}/policies"
        info "Backed up: policies/"
    fi
fi

OPENCLAW_JSON="${OPENCLAW_HOME}/openclaw.json"
if [[ -f "$OPENCLAW_JSON" ]]; then
    cp "$OPENCLAW_JSON" "${BACKUP_DIR}/openclaw.json"
    info "Backed up: openclaw.json"
fi

info "Backup saved to: $BACKUP_DIR"

# ── Step 2: Update source ────────────────────────────────────────────────────

if [[ "$SKIP_PULL" -eq 0 ]]; then
    section "Updating Source"
    if [[ -d "${SOURCE_DIR}/.git" ]]; then
        step "Running git pull in $SOURCE_DIR ..."
        (cd "$SOURCE_DIR" && git pull) && info "Source updated" || warn "git pull failed — continuing with current source"
    else
        warn "Not a git repository — skipping git pull"
    fi
fi

# ── Step 3: Stop services ────────────────────────────────────────────────────

section "Stopping Services"

step "Stopping defenseclaw-gateway ..."
defenseclaw-gateway stop 2>/dev/null && info "Gateway stopped" || warn "Gateway was not running"

# ── Step 4: Replace files ────────────────────────────────────────────────────

section "Replacing Files"

# Gateway binary
step "Building defenseclaw-gateway ..."
(cd "$SOURCE_DIR" && make gateway-install) && info "Gateway binary replaced" || { error "make gateway-install failed"; exit 1; }

# Python CLI
step "Updating Python CLI ..."
UV_BIN="$(command -v uv 2>/dev/null || true)"
if [[ -z "$UV_BIN" ]]; then
    error "uv not found on PATH — cannot update Python CLI"
    error "Install uv: curl -LsSf https://astral.sh/uv/install.sh | sh"
    exit 1
fi

VENV_PYTHON="${DEFENSECLAW_VENV}/bin/python"

if [[ ! -d "$DEFENSECLAW_VENV" ]]; then
    step "Creating venv at $DEFENSECLAW_VENV ..."
    "$UV_BIN" venv "$DEFENSECLAW_VENV" --python 3.12
fi

"$UV_BIN" pip install -e "$SOURCE_DIR" --python "$VENV_PYTHON"
info "Python CLI updated"

# Plugin
step "Rebuilding OpenClaw plugin ..."
if (cd "$SOURCE_DIR" && make plugin plugin-install 2>/dev/null); then
    info "Plugin files replaced"
else
    warn "Plugin build failed — run 'make plugin plugin-install' manually"
fi

# ── Step 5: Run migrations ───────────────────────────────────────────────────

section "Running Migrations"

MIGRATION_COUNT=$(python3 -c "
from defenseclaw.migrations import run_migrations
count = run_migrations('$CURRENT_VERSION', '$NEW_VERSION', '$OPENCLAW_HOME')
print(count)
" 2>/dev/null || echo "0")

if [[ "$MIGRATION_COUNT" -eq 0 ]]; then
    info "No migrations needed"
else
    info "Applied $MIGRATION_COUNT migration(s)"
fi

# ── Step 6: Start services ───────────────────────────────────────────────────

section "Starting Services"

step "Starting defenseclaw-gateway ..."
defenseclaw-gateway start && info "Gateway started" || warn "Could not start gateway"

step "Restarting OpenClaw gateway to load updated plugin ..."
openclaw gateway restart 2>/dev/null \
    && info "OpenClaw gateway restarted — DefenseClaw plugin loaded" \
    || warn "Could not restart OpenClaw gateway automatically. Run: openclaw gateway restart"

# ── Done ──────────────────────────────────────────────────────────────────────

section "Upgrade Complete"
info "DefenseClaw upgraded: $CURRENT_VERSION → $NEW_VERSION"
echo
echo -e "  Backup saved to: ${DIM}$BACKUP_DIR${NC}"
echo -e "  Run ${BOLD}defenseclaw status${NC} to verify all components are healthy."
echo

} # end main()

main "$@"
