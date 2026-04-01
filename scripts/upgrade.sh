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
# Backs up existing DefenseClaw and OpenClaw state, cleanly uninstalls the
# current setup, pulls the latest source, rebuilds, and reinstalls.
#
# Usage:
#   ./scripts/upgrade.sh [--source-dir <dir>] [--skip-pull] [--yes] [--help]
#
# Options:
#   --source-dir <dir>  Path to the defenseclaw source repository.
#                       Defaults to the parent directory of this script.
#   --skip-pull         Skip `git pull` (useful when upgrading from a local
#                       dist/ directory or when the repo is already up-to-date)
#   --local <dir>       Install from a local dist/ directory instead of
#                       rebuilding from source (uses install.sh --local)
#   --yes, -y           Skip confirmation prompts
#   --help, -h          Show this help
#
set -euo pipefail

main() {

# ── Configuration ─────────────────────────────────────────────────────────────

readonly DEFENSECLAW_HOME="${DEFENSECLAW_HOME:-${HOME}/.defenseclaw}"
readonly DEFENSECLAW_VENV="${DEFENSECLAW_HOME}/.venv"
readonly OPENCLAW_HOME="${OPENCLAW_HOME:-${HOME}/.openclaw}"
readonly INSTALL_DIR="${HOME}/.local/bin"
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
LOCAL_DIST=""
YES=0

# Default source directory: parent of scripts/
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_SOURCE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --source-dir) SOURCE_DIR="$2"; shift 2 ;;
        --skip-pull)  SKIP_PULL=1; shift ;;
        --local)      LOCAL_DIST="$2"; shift 2 ;;
        --yes|-y)     YES=1; shift ;;
        --help|-h)
            cat <<EOF

  DefenseClaw Upgrade Script

  Usage: $(basename "$0") [OPTIONS]

  Options:
    --source-dir <dir>  Path to defenseclaw source repo (default: $DEFAULT_SOURCE_DIR)
    --skip-pull         Skip git pull
    --local <dir>       Install from local dist/ directory
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
echo -e "  ${DIM}Backs up current state, uninstalls, updates, and reinstalls${NC}"
echo

# ── Pre-flight Checks ─────────────────────────────────────────────────────────

section "Pre-flight Checks"

# Check defenseclaw CLI is available
if ! command -v defenseclaw >/dev/null 2>&1; then
    error "defenseclaw CLI not found on PATH. Cannot proceed."
    exit 1
fi
info "defenseclaw CLI found: $(command -v defenseclaw)"

# Check defenseclaw-gateway binary
if ! command -v defenseclaw-gateway >/dev/null 2>&1; then
    error "defenseclaw-gateway not found on PATH."
    exit 1
fi
info "defenseclaw-gateway found: $(command -v defenseclaw-gateway)"

# Validate source directory (unless using --local)
if [[ -z "$LOCAL_DIST" ]]; then
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
fi

# ── Confirm ───────────────────────────────────────────────────────────────────

if [[ "$YES" -eq 0 ]]; then
    echo
    echo -e "  This will:"
    echo -e "    1. Back up ${BOLD}~/.defenseclaw/${NC} and ${BOLD}~/.openclaw/openclaw.json${NC}"
    echo -e "    2. Restore openclaw.json to its pre-DefenseClaw state"
    echo -e "    3. Uninstall the current DefenseClaw plugin and gateway"
    if [[ -n "$LOCAL_DIST" ]]; then
        echo -e "    4. Install from local dist: ${BOLD}$LOCAL_DIST${NC}"
    else
        if [[ "$SKIP_PULL" -eq 0 ]]; then
            echo -e "    4. Pull latest changes from git"
        fi
        echo -e "    5. Rebuild and reinstall DefenseClaw"
    fi
    echo -e "    6. Re-run guardrail setup with your existing configuration"
    echo
    read -r -p "  Proceed? [y/N] " REPLY
    case "$REPLY" in
        [Yy]*) ;;
        *) echo "  Aborted."; exit 0 ;;
    esac
fi

# ── Step 1: Save current guardrail config ─────────────────────────────────────

section "Saving Current Configuration"

GUARDRAIL_MODE=""
GUARDRAIL_PORT=""
GUARDRAIL_SCANNER_MODE=""
GUARDRAIL_BLOCK_MSG=""

CONFIG_YAML="${DEFENSECLAW_HOME}/config.yaml"
if [[ -f "$CONFIG_YAML" ]]; then
    # Extract guardrail settings from config.yaml for re-use after reinstall.
    GUARDRAIL_MODE=$(python3 -c "
import yaml, sys
try:
    c = yaml.safe_load(open('$CONFIG_YAML'))
    g = c.get('guardrail', {})
    print(g.get('mode', '') or '')
except Exception: pass
" 2>/dev/null || true)

    GUARDRAIL_PORT=$(python3 -c "
import yaml, sys
try:
    c = yaml.safe_load(open('$CONFIG_YAML'))
    g = c.get('guardrail', {})
    p = g.get('port', '')
    if p: print(p)
except Exception: pass
" 2>/dev/null || true)

    GUARDRAIL_SCANNER_MODE=$(python3 -c "
import yaml, sys
try:
    c = yaml.safe_load(open('$CONFIG_YAML'))
    g = c.get('guardrail', {})
    print(g.get('scanner_mode', '') or '')
except Exception: pass
" 2>/dev/null || true)

    GUARDRAIL_BLOCK_MSG=$(python3 -c "
import yaml, sys
try:
    c = yaml.safe_load(open('$CONFIG_YAML'))
    g = c.get('guardrail', {})
    print(g.get('block_message', '') or '')
except Exception: pass
" 2>/dev/null || true)

    info "Saved: mode=${GUARDRAIL_MODE:-default} port=${GUARDRAIL_PORT:-default} scanner=${GUARDRAIL_SCANNER_MODE:-default}"
else
    warn "No existing config.yaml found — will use defaults after reinstall"
fi

# ── Step 2: Create backup ─────────────────────────────────────────────────────

section "Creating Backup"

TIMESTAMP=$(date +%Y%m%dT%H%M%S)
BACKUP_DIR="${BACKUP_ROOT}/upgrade-${TIMESTAMP}"
mkdir -p "$BACKUP_DIR"
info "Backup directory: $BACKUP_DIR"

# Backup ~/.defenseclaw/ (config, env, runtime, policies, audit db)
if [[ -d "$DEFENSECLAW_HOME" ]]; then
    step "Backing up ~/.defenseclaw/ ..."
    for f in config.yaml .env guardrail_runtime.json device.key audit.db; do
        src="${DEFENSECLAW_HOME}/$f"
        [[ -f "$src" ]] && cp "$src" "$BACKUP_DIR/" && info "Backed up: $f"
    done
    # Backup policies directory
    if [[ -d "${DEFENSECLAW_HOME}/policies" ]]; then
        cp -r "${DEFENSECLAW_HOME}/policies" "${BACKUP_DIR}/policies"
        info "Backed up: policies/"
    fi
fi

# Backup openclaw.json and all existing .bak files
OPENCLAW_JSON="${OPENCLAW_HOME}/openclaw.json"
if [[ -f "$OPENCLAW_JSON" ]]; then
    step "Backing up openclaw.json and backups ..."
    cp "$OPENCLAW_JSON" "${BACKUP_DIR}/openclaw.json"
    info "Backed up: openclaw.json (current)"
    # Copy all existing backups so we preserve the chain
    for bak in "${OPENCLAW_HOME}"/openclaw.json.bak*; do
        [[ -f "$bak" ]] && cp "$bak" "${BACKUP_DIR}/" && info "Backed up: $(basename "$bak")"
    done
fi

info "Backup complete: $BACKUP_DIR"

# ── Step 3: Restore openclaw.json from original backup ───────────────────────

section "Restoring openclaw.json"

OPENCLAW_ORIGINAL_BAK="${OPENCLAW_HOME}/openclaw.json.bak"
if [[ -f "$OPENCLAW_ORIGINAL_BAK" ]]; then
    step "Restoring openclaw.json from pre-DefenseClaw backup ..."
    # Before restoring, verify the backup doesn't have defenseclaw entries
    if python3 -c "
import json, sys
data = json.load(open('$OPENCLAW_ORIGINAL_BAK'))
plugins = data.get('plugins', {})
allow = plugins.get('allow', [])
sys.exit(0 if 'defenseclaw' not in allow else 1)
" 2>/dev/null; then
        cp "$OPENCLAW_ORIGINAL_BAK" "$OPENCLAW_JSON"
        info "Restored openclaw.json from original backup (no DefenseClaw entries)"
    else
        warn "Backup also contains DefenseClaw entries — using defenseclaw CLI to clean up"
        defenseclaw setup guardrail --disable --non-interactive 2>/dev/null || true
    fi
else
    warn "No openclaw.json.bak found — using defenseclaw CLI to restore"
    defenseclaw setup guardrail --disable --non-interactive 2>/dev/null || true
fi

# ── Step 4: Stop gateway and uninstall plugin ─────────────────────────────────

section "Stopping and Uninstalling"

step "Stopping defenseclaw-gateway ..."
defenseclaw-gateway stop 2>/dev/null && info "Gateway stopped" || warn "Gateway was not running"

step "Removing OpenClaw plugin ..."
PLUGIN_DIR="${OPENCLAW_HOME}/extensions/defenseclaw"
if [[ -d "$PLUGIN_DIR" ]]; then
    rm -rf "$PLUGIN_DIR"
    info "Removed plugin: $PLUGIN_DIR"
else
    info "Plugin directory not present (already removed)"
fi

# ── Step 5: Update source ─────────────────────────────────────────────────────

if [[ -z "$LOCAL_DIST" ]]; then
    section "Updating Source"

    if [[ "$SKIP_PULL" -eq 0 ]]; then
        if [[ -d "${SOURCE_DIR}/.git" ]]; then
            step "Running git pull in $SOURCE_DIR ..."
            (cd "$SOURCE_DIR" && git pull) && info "Source updated"
        else
            warn "Not a git repository — skipping git pull (use --skip-pull to suppress this warning)"
        fi
    else
        info "Skipping git pull (--skip-pull)"
    fi

    # ── Step 6: Rebuild ───────────────────────────────────────────────────────

    section "Rebuilding"

    step "Building Go gateway binary ..."
    (cd "$SOURCE_DIR" && make gateway-install) && info "defenseclaw-gateway rebuilt and installed"

    step "Installing Python CLI ..."
    # Use the system uv (uv venvs do not bundle pip, so python -m pip is
    # unavailable — always use uv for package management).
    UV_BIN="$(command -v uv 2>/dev/null || true)"
    if [[ -z "$UV_BIN" ]]; then
        error "uv not found on PATH — cannot install Python CLI"
        error "Install uv: curl -LsSf https://astral.sh/uv/install.sh | sh"
        exit 1
    fi

    VENV_PYTHON="${DEFENSECLAW_VENV}/bin/python"

    # Recreate the venv if it doesn't exist yet.
    if [[ ! -d "$DEFENSECLAW_VENV" ]]; then
        step "Creating venv at $DEFENSECLAW_VENV ..."
        "$UV_BIN" venv "$DEFENSECLAW_VENV" --python 3.12
    fi

    # Uninstall old non-editable wheel so stale site-packages code (e.g.
    # old guardrail.py that writes models.providers.defenseclaw) can't shadow
    # the new source.
    "$UV_BIN" pip uninstall defenseclaw --python "$VENV_PYTHON" -q 2>/dev/null || true

    # Install editable from current source. This also installs/updates all
    # Python dependencies declared in pyproject.toml.
    "$UV_BIN" pip install -e "$SOURCE_DIR" --python "$VENV_PYTHON"
    info "Python CLI and dependencies updated"

    step "Rebuilding OpenClaw plugin ..."
    if command -v make >/dev/null 2>&1 && [[ -f "${SOURCE_DIR}/Makefile" ]]; then
        (cd "$SOURCE_DIR" && make plugin plugin-install 2>/dev/null) \
            && info "Plugin rebuilt and staged" \
            || warn "Plugin build failed — run 'make plugin plugin-install' manually"
    fi

else
    # ── Step 6 (local): Install from dist/ ───────────────────────────────────

    section "Installing from Local Distribution"

    step "Running install.sh --local $LOCAL_DIST ..."
    bash "${SCRIPT_DIR}/install.sh" --local "$LOCAL_DIST" --yes \
        && info "Installed from local dist" \
        || { error "install.sh failed"; exit 1; }
fi

# ── Step 7: Re-setup guardrail ────────────────────────────────────────────────

section "Re-configuring Guardrail"

SETUP_ARGS=("setup" "guardrail" "--non-interactive")
[[ -n "$GUARDRAIL_MODE" ]]         && SETUP_ARGS+=("--mode" "$GUARDRAIL_MODE")
[[ -n "$GUARDRAIL_PORT" ]]         && SETUP_ARGS+=("--port" "$GUARDRAIL_PORT")
[[ -n "$GUARDRAIL_SCANNER_MODE" ]] && SETUP_ARGS+=("--scanner-mode" "$GUARDRAIL_SCANNER_MODE")
[[ -n "$GUARDRAIL_BLOCK_MSG" ]]    && SETUP_ARGS+=("--block-message" "$GUARDRAIL_BLOCK_MSG")

step "Running: defenseclaw ${SETUP_ARGS[*]} ..."
defenseclaw "${SETUP_ARGS[@]}" && info "Guardrail re-configured"

# ── Step 8: Start gateway ─────────────────────────────────────────────────────

section "Starting Gateway"

step "Starting defenseclaw-gateway ..."
defenseclaw-gateway start && info "Gateway started"

step "Restarting OpenClaw gateway to load updated plugin ..."
openclaw gateway restart 2>/dev/null \
    && info "OpenClaw gateway restarted — DefenseClaw plugin loaded" \
    || warn "Could not restart OpenClaw gateway automatically. Run: openclaw gateway restart"

# ── Done ──────────────────────────────────────────────────────────────────────

section "Upgrade Complete"
info "DefenseClaw has been upgraded successfully"
echo
echo -e "  Backup saved to: ${DIM}$BACKUP_DIR${NC}"
echo -e "  Run ${BOLD}defenseclaw status${NC} to verify all components are healthy."
echo

} # end main()

main "$@"
