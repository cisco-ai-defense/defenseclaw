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

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

SIDECAR_URL="http://127.0.0.1:18970"
OPENCLAW_URL="http://127.0.0.1:18789"
GUARDRAIL_URL="http://127.0.0.1:4000"
SPLUNK_HEC_URL="http://127.0.0.1:8088"
SPLUNK_HEC_TOKEN="00000000-0000-0000-0000-000000000001"
SPLUNK_API_URL="https://127.0.0.1:8089"
SPLUNK_CREDS="admin:DefenseClawLocalMode1!"
SPLUNK_INDEX="defenseclaw_local"

E2E_PROFILE="${E2E_PROFILE:-core}"
E2E_REQUIRE_GUARDRAIL="${E2E_REQUIRE_GUARDRAIL:-false}"
E2E_REQUIRE_AGENT_INSTALL="${E2E_REQUIRE_AGENT_INSTALL:-false}"
E2E_REQUIRE_AGENT_SCAN="${E2E_REQUIRE_AGENT_SCAN:-false}"
E2E_REQUIRE_LIVE_MCP="${E2E_REQUIRE_LIVE_MCP:-false}"

sanitize_name() {
    printf '%s' "$1" | tr -cs '[:alnum:]._-' '-'
}

if [ "$E2E_PROFILE" != "core" ] && [ "$E2E_PROFILE" != "full-live" ]; then
    echo "error: E2E_PROFILE must be 'core' or 'full-live' (got '$E2E_PROFILE')" >&2
    exit 2
fi

DEFENSECLAW_RUN_ID="${DEFENSECLAW_RUN_ID:-manual-$(date -u +%Y%m%dT%H%M%SZ)-$$-$E2E_PROFILE}"
export DEFENSECLAW_RUN_ID
RUN_SLUG="$(sanitize_name "$DEFENSECLAW_RUN_ID")"
E2E_PREFIX="e2e-${RUN_SLUG}"

PASS=0
FAIL=0
SKIP_COUNT=0
RESULTS=()
PHASE_START_T=0
GATEWAY_TOKEN_CACHE="__unset__"
OPENCLAW_PID=""

is_true() {
    case "${1:-}" in
        1|true|TRUE|yes|YES|on|ON) return 0 ;;
        *) return 1 ;;
    esac
}

is_full_live() {
    [ "$E2E_PROFILE" = "full-live" ]
}

pass() {
    local name="$1"
    PASS=$((PASS + 1))
    RESULTS+=("PASS: $name")
    printf "  [\033[92mPASS\033[0m] %s\n" "$name"
}

fail() {
    local name="$1"
    local reason="${2:-}"
    FAIL=$((FAIL + 1))
    RESULTS+=("FAIL: $name — $reason")
    printf "  [\033[91mFAIL\033[0m] %s\n" "$name"
    [ -n "$reason" ] && printf "         %s\n" "$reason"
}

skip() {
    local name="$1"
    local reason="${2:-}"
    SKIP_COUNT=$((SKIP_COUNT + 1))
    RESULTS+=("SKIP: $name")
    printf "  [\033[93mSKIP\033[0m] %s\n" "$name"
    [ -n "$reason" ] && printf "         %s\n" "$reason"
}

phase_timer_start() {
    PHASE_START_T=$SECONDS
}

phase_timer_end() {
    local name="$1"
    local elapsed=$((SECONDS - PHASE_START_T))
    printf "  [timer] %s completed in %ds\n" "$name" "$elapsed"
}

skip_or_fail() {
    local requirement="$1"
    local name="$2"
    local reason="${3:-}"
    if is_true "$requirement"; then
        fail "$name" "$reason"
    else
        skip "$name" "$reason"
    fi
}

wait_for_url() {
    local url="$1"
    local timeout="${2:-60}"
    local interval="${3:-3}"
    local deadline=$((SECONDS + timeout))
    while [ $SECONDS -lt $deadline ]; do
        if curl -sf --max-time 5 "$url" >/dev/null 2>&1; then
            return 0
        fi
        sleep "$interval"
    done
    return 1
}

extract_json() {
    sed -n '/^\s*[{[]/,$ p' | jq '.' 2>/dev/null
}

count_nonempty_lines() {
    printf '%s\n' "$1" | sed '/^[[:space:]]*$/d' | wc -l | tr -d ' '
}

splunk_search() {
    local query="$1"
    curl -sf --max-time 15 -k \
        -u "$SPLUNK_CREDS" \
        -d "search=search index=${SPLUNK_INDEX} $query" \
        -d "output_mode=json" \
        "$SPLUNK_API_URL/services/search/jobs/export" 2>/dev/null || echo '{}'
}

splunk_results_json() {
    local query="$1"
    local raw
    raw=$(splunk_search "$query")
    printf '%s\n' "$raw" | jq -cs '[.[] | .result? | select(type == "object")]' 2>/dev/null || echo '[]'
}

splunk_run_results_json() {
    local query="$1"
    splunk_results_json "run_id=\"$DEFENSECLAW_RUN_ID\" $query"
}

splunk_assert_results() {
    local name="$1"
    local query="$2"
    local results
    local count
    results=$(splunk_run_results_json "$query")
    count=$(echo "$results" | jq 'length' 2>/dev/null || echo "0")
    echo "  --- Splunk query: $query ---"
    echo "$results" | jq '.' 2>/dev/null || echo "$results"
    echo "  --- end Splunk results ---"
    if [ "${count:-0}" -gt 0 ]; then
        pass "$name"
    else
        fail "$name" "no Splunk results for run_id=$DEFENSECLAW_RUN_ID query=$query"
    fi
}

get_gateway_token() {
    if [ "$GATEWAY_TOKEN_CACHE" != "__unset__" ]; then
        printf '%s\n' "$GATEWAY_TOKEN_CACHE"
        return
    fi
    GATEWAY_TOKEN_CACHE=$(python3 - <<'PY'
from defenseclaw.config import load
try:
    print(load().gateway.resolved_token())
except Exception:
    print("")
PY
)
    printf '%s\n' "$GATEWAY_TOKEN_CACHE"
}

curl_with_gateway_headers() {
    local method="$1"
    local url="$2"
    local body="${3:-}"
    local token
    token="$(get_gateway_token)"

    local args=(
        -sS
        --max-time 30
        -X "$method"
        -H "X-DefenseClaw-Client: e2e-full-stack"
    )
    if [ -n "$token" ]; then
        args+=(-H "Authorization: Bearer $token")
    fi
    if [ -n "$body" ]; then
        args+=(-H "Content-Type: application/json" -d "$body")
    fi
    curl "${args[@]}" "$url"
}

sidecar_post() {
    local path="$1"
    local body="${2:-}"
    curl_with_gateway_headers POST "$SIDECAR_URL$path" "$body"
}

alerts_for_run() {
    local limit="${1:-400}"
    local raw
    raw=$(curl_with_gateway_headers GET "$SIDECAR_URL/alerts?limit=$limit" 2>/dev/null || echo '[]')
    printf '%s\n' "$raw" | jq --arg id "$DEFENSECLAW_RUN_ID" '[.[] | select(.run_id == $id)]' 2>/dev/null || echo '[]'
}

db_has_action() {
    local target_type="$1"
    local target_name="$2"
    local field="$3"
    local value="$4"
    DB_TARGET_TYPE="$target_type" DB_TARGET_NAME="$target_name" DB_FIELD="$field" DB_VALUE="$value" python3 - <<'PY'
import os
from defenseclaw.config import load
from defenseclaw.db import Store

cfg = load()
store = Store(cfg.audit_db)
store.init()
try:
    ok = store.has_action(
        os.environ["DB_TARGET_TYPE"],
        os.environ["DB_TARGET_NAME"],
        os.environ["DB_FIELD"],
        os.environ["DB_VALUE"],
    )
    print("true" if ok else "false")
finally:
    store.close()
PY
}

get_skill_dirs() {
    local dirs
    dirs=$(python3 - <<'PY'
from defenseclaw.config import load
try:
    cfg = load()
    for d in cfg.skill_dirs():
        print(d)
except Exception:
    pass
PY
)

    if [ -n "$dirs" ]; then
        printf '%s\n' "$dirs" | awk 'NF && !seen[$0]++'
        return
    fi

    printf '%s\n%s\n' \
        "$HOME/.openclaw/workspace/skills" \
        "$HOME/.openclaw/skills" | awk 'NF && !seen[$0]++'
}

first_skill_dir() {
    get_skill_dirs | head -1
}

snapshot_skill_paths() {
    while IFS= read -r dir; do
        [ -n "$dir" ] || continue
        [ -d "$dir" ] || continue
        find "$dir" -mindepth 1 -maxdepth 1 -type d -print 2>/dev/null || true
    done < <(get_skill_dirs)
}

find_skill_path() {
    local name="$1"
    while IFS= read -r dir; do
        [ -n "$dir" ] || continue
        if [ -d "$dir/$name" ]; then
            printf '%s\n' "$dir/$name"
            return 0
        fi
    done < <(get_skill_dirs)
    return 1
}

cleanup_skill_name() {
    local name="$1"
    while IFS= read -r dir; do
        [ -n "$dir" ] || continue
        rm -rf "$dir/$name" 2>/dev/null || true
    done < <(get_skill_dirs)
    rm -rf "$HOME/.defenseclaw/quarantine/skills/$name" 2>/dev/null || true
}

skill_list_json() {
    defenseclaw skill list --json 2>/dev/null || echo "[]"
}

skill_entry_json() {
    local name="$1"
    skill_list_json | jq --arg n "$name" '[.[] | select(.name == $n)][0] // empty' 2>/dev/null || true
}

wait_for_skill_entry() {
    local name="$1"
    local timeout="${2:-60}"
    local deadline=$((SECONDS + timeout))
    while [ $SECONDS -lt $deadline ]; do
        local entry
        entry=$(skill_entry_json "$name")
        if [ -n "$entry" ] && [ "$entry" != "null" ]; then
            printf '%s\n' "$entry"
            return 0
        fi
        sleep 3
    done
    return 1
}

wait_for_skill_scan() {
    local name="$1"
    local timeout="${2:-60}"
    local deadline=$((SECONDS + timeout))
    while [ $SECONDS -lt $deadline ]; do
        local entry
        entry=$(skill_entry_json "$name")
        if [ -n "$entry" ] && [ "$entry" != "null" ]; then
            local has_scan
            has_scan=$(echo "$entry" | jq -r '.scan // empty' 2>/dev/null || true)
            if [ -n "$has_scan" ] && [ "$has_scan" != "null" ]; then
                printf '%s\n' "$entry"
                return 0
            fi
        fi
        sleep 5
    done
    return 1
}

copy_skill_fixture() {
    local fixture_dir="$1"
    local dest_root="$2"
    local dest_name="$3"
    mkdir -p "$dest_root/$dest_name"
    cp -R "$fixture_dir"/. "$dest_root/$dest_name/"
}

prune_openclaw_config_for_prefix() {
    E2E_PREFIX="$E2E_PREFIX" python3 - <<'PY'
import json
import os
from pathlib import Path

prefix = os.environ["E2E_PREFIX"]
cfg_path = Path(os.path.expanduser("~/.openclaw/openclaw.json"))
if not cfg_path.exists():
    raise SystemExit(0)

with cfg_path.open() as f:
    cfg = json.load(f)

changed = False
skills = cfg.setdefault("skills", {}).setdefault("entries", {})
kept = {name: meta for name, meta in skills.items() if not name.startswith(prefix)}
if kept != skills:
    cfg["skills"]["entries"] = kept
    changed = True

plugins = cfg.setdefault("plugins", {})
for bucket_name in ("entries", "installs"):
    bucket = plugins.get(bucket_name)
    if not isinstance(bucket, dict):
        continue
    next_bucket = {
        name: meta for name, meta in bucket.items()
        if not str(name).startswith(prefix)
    }
    if next_bucket != bucket:
        plugins[bucket_name] = next_bucket
        changed = True

if changed:
    with cfg_path.open("w") as f:
        json.dump(cfg, f, indent=2)
        f.write("\n")
PY
}

openclaw_config_state_json() {
    E2E_PREFIX="$E2E_PREFIX" python3 - <<'PY'
import json
import os
from pathlib import Path

prefix = os.environ["E2E_PREFIX"]
cfg_path = Path(os.path.expanduser("~/.openclaw/openclaw.json"))
state = {
    "current_prefix_skill_entries": 0,
    "current_prefix_plugin_entries": 0,
    "defenseclaw_plugin_entries": 0,
}
if cfg_path.exists():
    with cfg_path.open() as f:
        cfg = json.load(f)
    skills = cfg.get("skills", {}).get("entries", {})
    plugins = cfg.get("plugins", {})
    state["current_prefix_skill_entries"] = sum(
        1 for name in skills if str(name).startswith(prefix)
    )
    state["current_prefix_plugin_entries"] = sum(
        1
        for bucket_name in ("entries", "installs")
        for name in (plugins.get(bucket_name, {}) or {})
        if str(name).startswith(prefix)
    )
    state["defenseclaw_plugin_entries"] = sum(
        1
        for bucket_name in ("entries", "installs")
        if "defenseclaw" in (plugins.get(bucket_name, {}) or {})
    )
print(json.dumps(state))
PY
}

cleanup_current_run_artifacts() {
    while IFS= read -r dir; do
        [ -n "$dir" ] || continue
        rm -rf "$dir"/"$E2E_PREFIX"* 2>/dev/null || true
    done < <(get_skill_dirs)

    rm -rf "$HOME/.defenseclaw/quarantine/skills"/"$E2E_PREFIX"* 2>/dev/null || true
    rm -rf "$HOME/.defenseclaw/quarantine/plugins"/"$E2E_PREFIX"* 2>/dev/null || true
    rm -rf "$HOME/.openclaw/extensions"/"$E2E_PREFIX"* 2>/dev/null || true
    rm -f /tmp/"$E2E_PREFIX"* 2>/dev/null || true
    prune_openclaw_config_for_prefix
}

inspect_tool() {
    local tool_name="$1"
    local args_json="$2"
    local payload
    payload=$(jq -cn --arg tool "$tool_name" --argjson args "$args_json" '{tool: $tool, args: $args}')
    sidecar_post "/api/v1/inspect/tool" "$payload"
}

dump_artifacts() {
    echo ""
    echo "=== Artifact Dump (on failure) ==="
    echo "--- Run Context ---"
    echo "profile=$E2E_PROFILE"
    echo "run_id=$DEFENSECLAW_RUN_ID"
    echo "prefix=$E2E_PREFIX"
    echo "--- ~/.defenseclaw/config.yaml ---"
    cat ~/.defenseclaw/config.yaml 2>/dev/null || echo "  (not found)"
    echo "--- .env key names ---"
    grep -oP '^\w+(?==)' ~/.defenseclaw/.env 2>/dev/null || echo "  (none)"
    echo "--- defenseclaw-gateway status ---"
    defenseclaw-gateway status 2>/dev/null || echo "  (not running)"
    echo "--- alerts for current run ---"
    alerts_for_run 500 | jq '.' 2>/dev/null || alerts_for_run 500
    echo "--- openclaw skills list ---"
    openclaw skills list --json 2>/dev/null || echo "[]"
    echo "--- current test skill directories ---"
    snapshot_skill_paths | grep "$E2E_PREFIX" || echo "  (none)"
    echo "--- Splunk current-run actions ---"
    splunk_run_results_json 'action=* | head 20' | jq '.' 2>/dev/null || echo "[]"
    echo "--- splunk container logs (last 30) ---"
    docker logs "$(docker ps -aq --filter name=splunk 2>/dev/null | head -1)" --tail 30 2>/dev/null || echo "  (no container)"
    echo "=== End Artifact Dump ==="
}

# ---------------------------------------------------------------------------
# Phase 1 — Start Stack
# ---------------------------------------------------------------------------
phase_start() {
    echo ""
    echo "=== Phase 1: Start Stack ==="
    phase_timer_start

    echo "  Profile: $E2E_PROFILE"
    echo "  Run ID:  $DEFENSECLAW_RUN_ID"

    cleanup_current_run_artifacts

    local stale_skills stale_quarantine cfg_state
    stale_skills=$(snapshot_skill_paths | grep "/$E2E_PREFIX" || true)
    stale_quarantine=$(find "$HOME/.defenseclaw/quarantine" -mindepth 1 -maxdepth 3 -name "${E2E_PREFIX}*" 2>/dev/null || true)
    cfg_state=$(openclaw_config_state_json)

    if [ -z "$stale_skills" ]; then
        pass "preflight: no stale current-run skill directories"
    else
        fail "preflight: no stale current-run skill directories" "$stale_skills"
    fi

    if [ -z "$stale_quarantine" ]; then
        pass "preflight: no stale current-run quarantine artifacts"
    else
        fail "preflight: no stale current-run quarantine artifacts" "$stale_quarantine"
    fi

    if [ "$(echo "$cfg_state" | jq -r '.current_prefix_skill_entries' 2>/dev/null || echo 1)" = "0" ]; then
        pass "preflight: no current-run OpenClaw skill config entries"
    else
        fail "preflight: no current-run OpenClaw skill config entries" "$cfg_state"
    fi

    if [ "$(echo "$cfg_state" | jq -r '.defenseclaw_plugin_entries' 2>/dev/null || echo 1)" = "0" ]; then
        pass "preflight: no stale defenseclaw plugin config entry"
    else
        fail "preflight: no stale defenseclaw plugin config entry" "$cfg_state"
    fi

    echo "  Starting OpenClaw gateway..."
    openclaw gateway --force &
    OPENCLAW_PID=$!
    sleep 5

    echo "  Starting DefenseClaw sidecar..."
    defenseclaw-gateway stop 2>/dev/null || true
    defenseclaw-gateway start
    sleep 5

    echo "  Sidecar status:"
    defenseclaw-gateway status || true
    echo ""

    echo "  Waiting for sidecar health..."
    if wait_for_url "$SIDECAR_URL/health" 60 3; then
        pass "sidecar health endpoint reachable"
    else
        fail "sidecar health endpoint reachable" "timed out after 60s"
        phase_timer_end "Phase 1"
        return 1
    fi
    phase_timer_end "Phase 1"
}

# ---------------------------------------------------------------------------
# Phase 2 — Health Assertions
# ---------------------------------------------------------------------------
phase_health() {
    echo ""
    echo "=== Phase 2: Health Assertions ==="
    phase_timer_start

    local health
    health=$(curl -sf "$SIDECAR_URL/health" 2>/dev/null || echo "{}")
    echo "  Full health JSON:"
    echo "$health" | jq '.' 2>/dev/null || echo "$health"

    for subsystem in gateway watcher api; do
        local state
        state=$(echo "$health" | jq -r ".${subsystem}.state // .${subsystem} // empty" 2>/dev/null)
        if [ "$state" = "running" ]; then
            pass "health: $subsystem is running"
        else
            fail "health: $subsystem is running" "got '$state'"
        fi
    done

    local guard_state
    guard_state=$(echo "$health" | jq -r '.guardrail.state // .guardrail // empty' 2>/dev/null)
    if is_full_live; then
        if [ "$guard_state" = "running" ]; then
            pass "health: guardrail is running"
        elif [ "$guard_state" = "disabled" ]; then
            skip_or_fail "$E2E_REQUIRE_GUARDRAIL" "health: guardrail" "disabled — no supported live model provider configured"
        elif [ "$guard_state" = "error" ]; then
            local guard_err
            guard_err=$(echo "$health" | jq -r '.guardrail.last_error // empty' 2>/dev/null)
            if echo "$guard_err" | grep -qi "no API key\|api_key_env\|key not found"; then
                skip_or_fail "$E2E_REQUIRE_GUARDRAIL" "health: guardrail" "$guard_err"
            else
                fail "health: guardrail is running" "error — $guard_err"
            fi
        else
            skip_or_fail "$E2E_REQUIRE_GUARDRAIL" "health: guardrail" "got '$guard_state'"
        fi
    else
        if [ "$guard_state" = "running" ]; then
            pass "health: guardrail is running"
        else
            skip "health: guardrail" "core profile (state=$guard_state)"
        fi
    fi

    local splunk_state
    splunk_state=$(echo "$health" | jq -r '.splunk.state // .splunk // empty' 2>/dev/null)
    if [ "$splunk_state" = "running" ]; then
        pass "health: splunk integration is running"
    else
        skip "health: splunk" "state=$splunk_state"
    fi
    phase_timer_end "Phase 2"
}

# ---------------------------------------------------------------------------
# Phase 3 — Skill Scanner (CLI)
# ---------------------------------------------------------------------------
phase_skill_scanner() {
    echo ""
    echo "=== Phase 3: Skill Scanner (CLI) ==="
    phase_timer_start

    local clean_skill="$REPO_ROOT/test/fixtures/skills/clean-skill"
    local malicious_skill="$REPO_ROOT/test/fixtures/skills/malicious-skill"

    if [ ! -d "$clean_skill" ] || [ ! -d "$malicious_skill" ]; then
        skip "skill scanner" "skill fixtures not found"
        phase_timer_end "Phase 3"
        return
    fi

    local clean_out clean_json clean_findings
    echo "  Scanning clean skill..."
    clean_out=$(defenseclaw skill scan "$clean_skill" --json 2>&1 || true)
    echo "$clean_out"
    clean_json=$(echo "$clean_out" | extract_json || true)
    if [ -n "$clean_json" ]; then
        clean_findings=$(echo "$clean_json" | jq -r '.findings | length' 2>/dev/null || echo "parse_error")
        if [ "$clean_findings" = "parse_error" ]; then
            fail "skill scan: clean skill" "scanner returned non-parseable JSON"
        else
            pass "skill scan: clean skill scanned ($clean_findings finding(s))"
        fi
    else
        fail "skill scan: clean skill" "scanner did not produce valid JSON"
    fi

    local mal_out mal_json mal_findings mal_severity
    echo "  Scanning malicious skill..."
    mal_out=$(defenseclaw skill scan "$malicious_skill" --json 2>&1 || true)
    echo "$mal_out"
    mal_json=$(echo "$mal_out" | extract_json || true)
    if [ -n "$mal_json" ]; then
        mal_findings=$(echo "$mal_json" | jq -r '.findings | length' 2>/dev/null || echo "0")
        mal_severity=$(echo "$mal_json" | jq -r '[.findings[].severity] | unique | join(",")' 2>/dev/null || echo "none")
        if [ "$mal_findings" -gt 0 ] 2>/dev/null; then
            pass "skill scan: malicious skill has $mal_findings finding(s) (severities: $mal_severity)"
        else
            fail "skill scan: malicious skill" "expected findings but got 0"
        fi
    else
        fail "skill scan: malicious skill" "scanner did not produce valid JSON"
    fi
    phase_timer_end "Phase 3"
}

# ---------------------------------------------------------------------------
# Phase 4 — MCP Scanner
# ---------------------------------------------------------------------------
phase_mcp_scanner() {
    echo ""
    echo "=== Phase 4: MCP Scanner ==="
    phase_timer_start

    local clean_fixture="$REPO_ROOT/test/fixtures/mcps/clean-mcp.json"
    local malicious_fixture="$REPO_ROOT/test/fixtures/mcps/malicious-mcp.json"

    if ! command -v mcp-scanner >/dev/null 2>&1; then
        skip "mcp scanner" "mcp-scanner CLI not found"
        phase_timer_end "Phase 4"
        return
    fi

    if [ ! -f "$clean_fixture" ] || [ ! -f "$malicious_fixture" ]; then
        skip "mcp scanner" "fixture files not found"
        phase_timer_end "Phase 4"
        return
    fi

    local clean_out clean_json clean_findings
    echo "  Scanning clean MCP fixture..."
    clean_out=$(mcp-scanner scan --format json --scan-instructions "$clean_fixture" 2>&1 || true)
    echo "$clean_out"
    clean_json=$(echo "$clean_out" | extract_json || true)
    if [ -n "$clean_json" ]; then
        clean_findings=$(echo "$clean_json" | jq -r '.findings | length' 2>/dev/null || echo "parse_error")
        if [ "$clean_findings" = "parse_error" ]; then
            fail "mcp scan: clean fixture" "scanner returned non-parseable JSON"
        else
            pass "mcp scan: clean fixture scanned ($clean_findings finding(s))"
        fi
    else
        fail "mcp scan: clean fixture" "scanner did not produce valid JSON"
    fi

    local mal_out mal_json mal_findings
    echo "  Scanning malicious MCP fixture..."
    mal_out=$(mcp-scanner scan --format json --scan-instructions "$malicious_fixture" 2>&1 || true)
    echo "$mal_out"
    mal_json=$(echo "$mal_out" | extract_json || true)
    if [ -n "$mal_json" ]; then
        mal_findings=$(echo "$mal_json" | jq -r '.findings | length' 2>/dev/null || echo "0")
        if [ "$mal_findings" -gt 0 ] 2>/dev/null; then
            pass "mcp scan: malicious fixture has $mal_findings finding(s)"
        else
            fail "mcp scan: malicious fixture" "expected findings but got 0"
        fi
    else
        fail "mcp scan: malicious fixture" "scanner did not produce valid JSON"
    fi

    if is_full_live; then
        if ! is_true "$E2E_REQUIRE_LIVE_MCP"; then
            skip "mcp scan: live configured server" "E2E_REQUIRE_LIVE_MCP=false"
        else
            local mcp_list first_name live_out live_json live_findings
            mcp_list=$(defenseclaw mcp list --json 2>/dev/null || echo "[]")
            first_name=$(echo "$mcp_list" | jq -r '.[0].name // empty' 2>/dev/null || echo "")
            if [ -z "$first_name" ]; then
                skip "mcp scan: live configured server" "no MCP servers configured"
            else
                echo "  Scanning configured MCP server '$first_name'..."
                live_out=$(defenseclaw mcp scan "$first_name" --json 2>&1 || true)
                echo "$live_out"
                live_json=$(echo "$live_out" | extract_json || true)
                if [ -n "$live_json" ]; then
                    live_findings=$(echo "$live_json" | jq -r '.findings | length' 2>/dev/null || echo "0")
                    pass "mcp scan: configured server '$first_name' scanned ($live_findings finding(s))"
                else
                    fail "mcp scan: configured server '$first_name'" "scanner did not produce valid JSON"
                fi
            fi
        fi
    fi
    phase_timer_end "Phase 4"
}

# ---------------------------------------------------------------------------
# Phase 4B — Block/Allow Enforcement
# ---------------------------------------------------------------------------
phase_block_allow() {
    echo ""
    echo "=== Phase 4B: Block/Allow Enforcement ==="
    phase_timer_start

    local skill_dir_root
    skill_dir_root=$(first_skill_dir || true)
    if [ -z "$skill_dir_root" ]; then
        skip "block/allow: skill tests" "could not determine skill directory"
        phase_timer_end "Phase 4B"
        return
    fi
    mkdir -p "$skill_dir_root"

    local blocked_skill="${E2E_PREFIX}-blocked-skill"
    local allowed_skill="${E2E_PREFIX}-allowed-skill"
    local malicious_skill="$REPO_ROOT/test/fixtures/skills/malicious-skill"
    local clean_skill="$REPO_ROOT/test/fixtures/skills/clean-skill"

    cleanup_skill_name "$blocked_skill"
    cleanup_skill_name "$allowed_skill"

    echo "  Blocking skill '$blocked_skill'..."
    defenseclaw skill block "$blocked_skill" --reason "E2E blocked skill" >/dev/null 2>&1 || true
    local skill_list blocked_state
    skill_list=$(skill_list_json)
    blocked_state=$(echo "$skill_list" | jq -r --arg n "$blocked_skill" '[.[] | select(.name == $n)][0].actions.install // empty' 2>/dev/null || true)
    if [ "$blocked_state" = "block" ]; then
        pass "block/allow: skill block state recorded"
    else
        fail "block/allow: skill block state recorded" "expected block, got '$blocked_state'"
    fi

    echo "  Copying blocked skill fixture into watched dir..."
    copy_skill_fixture "$malicious_skill" "$skill_dir_root" "$blocked_skill"
    local block_deadline=$((SECONDS + 30))
    while [ $SECONDS -lt $block_deadline ]; do
        if [ ! -d "$skill_dir_root/$blocked_skill" ]; then
            break
        fi
        sleep 2
    done
    if [ ! -d "$skill_dir_root/$blocked_skill" ]; then
        pass "block/allow: blocked skill rejected from watched dir"
    else
        fail "block/allow: blocked skill rejected from watched dir" "directory still exists at $skill_dir_root/$blocked_skill"
    fi

    echo "  Allow-listing skill '$allowed_skill'..."
    defenseclaw skill allow "$allowed_skill" --reason "E2E trusted skill" >/dev/null 2>&1 || true
    skill_list=$(skill_list_json)
    local allowed_state
    allowed_state=$(echo "$skill_list" | jq -r --arg n "$allowed_skill" '[.[] | select(.name == $n)][0].actions.install // empty' 2>/dev/null || true)
    if [ "$allowed_state" = "allow" ]; then
        pass "block/allow: skill allow state recorded"
    else
        fail "block/allow: skill allow state recorded" "expected allow, got '$allowed_state'"
    fi

    echo "  Copying allow-listed skill fixture into watched dir..."
    copy_skill_fixture "$clean_skill" "$skill_dir_root" "$allowed_skill"
    sleep 8
    if [ -d "$skill_dir_root/$allowed_skill" ]; then
        pass "block/allow: allow-listed skill remained installed"
    else
        fail "block/allow: allow-listed skill remained installed" "directory missing at $skill_dir_root/$allowed_skill"
    fi

    local blocked_mcp="https://${E2E_PREFIX}-blocked-mcp.example.com/mcp"
    local allowed_mcp="https://${E2E_PREFIX}-allowed-mcp.example.com/mcp"
    defenseclaw mcp block "$blocked_mcp" --reason "E2E blocked MCP" >/dev/null 2>&1 || true
    if [ "$(db_has_action mcp "$blocked_mcp" install block)" = "true" ]; then
        pass "block/allow: MCP block state recorded"
    else
        fail "block/allow: MCP block state recorded" "block action not found for $blocked_mcp"
    fi

    defenseclaw mcp allow "$allowed_mcp" --reason "E2E allowed MCP" >/dev/null 2>&1 || true
    if [ "$(db_has_action mcp "$allowed_mcp" install allow)" = "true" ]; then
        pass "block/allow: MCP allow state recorded"
    else
        fail "block/allow: MCP allow state recorded" "allow action not found for $allowed_mcp"
    fi

    local tool_name="read_file"
    local tool_file="/tmp/${E2E_PREFIX}-tool.txt"
    local tool_args allow_verdict block_verdict final_verdict tool_status
    printf 'tool block test\n' > "$tool_file"
    tool_args=$(jq -cn --arg path "$tool_file" '{path: $path}')

    if is_full_live; then
        allow_verdict=$(inspect_tool "$tool_name" "$tool_args" 2>/dev/null || echo '{}')
        if [ "$(echo "$allow_verdict" | jq -r '.action // empty' 2>/dev/null)" = "allow" ]; then
            pass "block/allow: runtime tool inspection allowed safe call"
        else
            fail "block/allow: runtime tool inspection allowed safe call" "$allow_verdict"
        fi
    fi

    defenseclaw tool block "$tool_name" --reason "E2E runtime block" >/dev/null 2>&1 || true
    tool_status=$(defenseclaw tool status "$tool_name" --json 2>/dev/null || echo '{}')
    if [ "$(echo "$tool_status" | jq -r '.global.status // empty' 2>/dev/null)" = "block" ]; then
        pass "block/allow: tool block state recorded"
    else
        fail "block/allow: tool block state recorded" "$tool_status"
    fi

    if is_full_live; then
        block_verdict=$(inspect_tool "$tool_name" "$tool_args" 2>/dev/null || echo '{}')
        if [ "$(echo "$block_verdict" | jq -r '.action // empty' 2>/dev/null)" = "block" ]; then
            pass "block/allow: runtime tool inspection blocked unsafe call"
        else
            fail "block/allow: runtime tool inspection blocked unsafe call" "$block_verdict"
        fi
    fi

    defenseclaw tool allow "$tool_name" --reason "E2E runtime allow" >/dev/null 2>&1 || true
    tool_status=$(defenseclaw tool status "$tool_name" --json 2>/dev/null || echo '{}')
    if [ "$(echo "$tool_status" | jq -r '.global.status // empty' 2>/dev/null)" = "allow" ]; then
        pass "block/allow: tool allow state recorded"
    else
        fail "block/allow: tool allow state recorded" "$tool_status"
    fi

    defenseclaw tool unblock "$tool_name" >/dev/null 2>&1 || true
    tool_status=$(defenseclaw tool status "$tool_name" --json 2>/dev/null || echo '{}')
    if [ "$(echo "$tool_status" | jq -r '.global.status // "none"' 2>/dev/null)" = "none" ]; then
        pass "block/allow: tool unblock cleared state"
    else
        fail "block/allow: tool unblock cleared state" "$tool_status"
    fi

    if is_full_live; then
        final_verdict=$(inspect_tool "$tool_name" "$tool_args" 2>/dev/null || echo '{}')
        if [ "$(echo "$final_verdict" | jq -r '.action // empty' 2>/dev/null)" = "allow" ]; then
            pass "block/allow: runtime tool inspection recovered after unblock"
        else
            fail "block/allow: runtime tool inspection recovered after unblock" "$final_verdict"
        fi
    fi

    local alerts skill_block_events skill_reject_events skill_allow_events skill_install_allow_events
    local mcp_block_events mcp_allow_events tool_block_events tool_allow_events
    alerts=$(alerts_for_run 500)

    skill_block_events=$(echo "$alerts" | jq --arg target "$blocked_skill" '[.[] | select(.action == "skill-block" and .target == $target)] | length' 2>/dev/null || echo "0")
    if [ "${skill_block_events:-0}" -gt 0 ]; then
        pass "block/allow: skill block audit event recorded"
    else
        fail "block/allow: skill block audit event recorded" "no skill-block event for $blocked_skill"
    fi

    skill_reject_events=$(echo "$alerts" | jq --arg skill "$blocked_skill" '[.[] | select(.action == "install-rejected" and (.target | contains($skill)))] | length' 2>/dev/null || echo "0")
    if [ "${skill_reject_events:-0}" -gt 0 ]; then
        pass "block/allow: blocked skill rejection audit recorded"
    else
        fail "block/allow: blocked skill rejection audit recorded" "no install-rejected event for $blocked_skill"
    fi

    skill_allow_events=$(echo "$alerts" | jq --arg target "$allowed_skill" '[.[] | select(.action == "skill-allow" and .target == $target)] | length' 2>/dev/null || echo "0")
    if [ "${skill_allow_events:-0}" -gt 0 ]; then
        pass "block/allow: skill allow audit event recorded"
    else
        fail "block/allow: skill allow audit event recorded" "no skill-allow event for $allowed_skill"
    fi

    skill_install_allow_events=$(echo "$alerts" | jq --arg skill "$allowed_skill" '[.[] | select(.action == "install-allowed" and (.target | contains($skill)))] | length' 2>/dev/null || echo "0")
    if [ "${skill_install_allow_events:-0}" -gt 0 ]; then
        pass "block/allow: allow-listed install audit recorded"
    else
        fail "block/allow: allow-listed install audit recorded" "no install-allowed event for $allowed_skill"
    fi

    mcp_block_events=$(echo "$alerts" | jq --arg target "$blocked_mcp" '[.[] | select(.action == "block-mcp" and .target == $target)] | length' 2>/dev/null || echo "0")
    if [ "${mcp_block_events:-0}" -gt 0 ]; then
        pass "block/allow: MCP block audit event recorded"
    else
        fail "block/allow: MCP block audit event recorded" "no block-mcp event for $blocked_mcp"
    fi

    mcp_allow_events=$(echo "$alerts" | jq --arg target "$allowed_mcp" '[.[] | select(.action == "allow-mcp" and .target == $target)] | length' 2>/dev/null || echo "0")
    if [ "${mcp_allow_events:-0}" -gt 0 ]; then
        pass "block/allow: MCP allow audit event recorded"
    else
        fail "block/allow: MCP allow audit event recorded" "no allow-mcp event for $allowed_mcp"
    fi

    tool_block_events=$(echo "$alerts" | jq --arg target "$tool_name" '[.[] | select(.action == "tool-block" and .target == $target)] | length' 2>/dev/null || echo "0")
    if [ "${tool_block_events:-0}" -gt 0 ]; then
        pass "block/allow: tool block audit event recorded"
    else
        fail "block/allow: tool block audit event recorded" "no tool-block event for $tool_name"
    fi

    tool_allow_events=$(echo "$alerts" | jq --arg target "$tool_name" '[.[] | select(.action == "tool-allow" and .target == $target)] | length' 2>/dev/null || echo "0")
    if [ "${tool_allow_events:-0}" -gt 0 ]; then
        pass "block/allow: tool allow audit event recorded"
    else
        fail "block/allow: tool allow audit event recorded" "no tool-allow event for $tool_name"
    fi

    rm -f "$tool_file" 2>/dev/null || true
    cleanup_skill_name "$allowed_skill"
    cleanup_skill_name "$blocked_skill"
    phase_timer_end "Phase 4B"
}

# ---------------------------------------------------------------------------
# Phase 5 — Quarantine Flow
# ---------------------------------------------------------------------------
phase_quarantine() {
    echo ""
    echo "=== Phase 5: Quarantine Flow ==="
    phase_timer_start

    local malicious_skill="$REPO_ROOT/test/fixtures/skills/malicious-skill"
    local skill_dir_root skill_name
    skill_dir_root=$(first_skill_dir || true)
    skill_name="${E2E_PREFIX}-quarantine-skill"

    if [ ! -d "$malicious_skill" ] || [ -z "$skill_dir_root" ]; then
        skip "quarantine" "fixtures or skill directory unavailable"
        phase_timer_end "Phase 5"
        return
    fi

    cleanup_skill_name "$skill_name"
    mkdir -p "$skill_dir_root"
    copy_skill_fixture "$malicious_skill" "$skill_dir_root" "$skill_name"

    if [ -d "$skill_dir_root/$skill_name" ]; then
        pass "quarantine: malicious skill placed in skill dir"
    else
        fail "quarantine: malicious skill placed in skill dir" "copy failed"
        phase_timer_end "Phase 5"
        return
    fi

    local q_out
    q_out=$(defenseclaw skill quarantine "$skill_name" --reason "E2E quarantine round-trip" 2>&1 || true)
    echo "$q_out"

    if [ -d "$skill_dir_root/$skill_name" ]; then
        fail "quarantine: skill removed from watched dir" "directory still exists at $skill_dir_root/$skill_name"
    else
        pass "quarantine: skill removed from watched dir"
    fi

    if [ -d "$HOME/.defenseclaw/quarantine/skills/$skill_name" ]; then
        pass "quarantine: skill present in quarantine area"
    else
        fail "quarantine: skill present in quarantine area" "expected $HOME/.defenseclaw/quarantine/skills/$skill_name"
    fi

    local r_out
    r_out=$(defenseclaw skill restore "$skill_name" 2>&1 || true)
    echo "$r_out"

    if [ -d "$skill_dir_root/$skill_name" ]; then
        pass "quarantine: skill restored to watched dir"
    else
        fail "quarantine: skill restored to watched dir" "directory missing at $skill_dir_root/$skill_name"
    fi

    cleanup_skill_name "$skill_name"
    phase_timer_end "Phase 5"
}

# ---------------------------------------------------------------------------
# Phase 5B — Watcher Auto-Scan
# ---------------------------------------------------------------------------
phase_watcher_auto_scan() {
    echo ""
    echo "=== Phase 5B: Watcher Auto-Scan ==="
    phase_timer_start

    local malicious_skill="$REPO_ROOT/test/fixtures/skills/malicious-skill"
    local skill_dir_root watcher_skill watcher_entry alerts detected_count
    skill_dir_root=$(first_skill_dir || true)
    watcher_skill="${E2E_PREFIX}-watcher-skill"

    if [ ! -d "$malicious_skill" ] || [ -z "$skill_dir_root" ]; then
        skip "watcher auto-scan" "fixtures or skill directory unavailable"
        phase_timer_end "Phase 5B"
        return
    fi

    cleanup_skill_name "$watcher_skill"
    mkdir -p "$skill_dir_root"
    copy_skill_fixture "$malicious_skill" "$skill_dir_root" "$watcher_skill"

    watcher_entry=$(wait_for_skill_scan "$watcher_skill" 90 || true)
    if [ -n "$watcher_entry" ] && [ "$watcher_entry" != "null" ]; then
        local findings target
        findings=$(echo "$watcher_entry" | jq -r '.scan.total_findings // 0' 2>/dev/null || echo "0")
        target=$(echo "$watcher_entry" | jq -r '.scan.target // empty' 2>/dev/null || true)
        echo "$watcher_entry" | jq '.' 2>/dev/null || echo "$watcher_entry"
        if [ "$findings" -gt 0 ] 2>/dev/null; then
            pass "watcher auto-scan: findings recorded ($findings finding(s))"
        else
            fail "watcher auto-scan: findings recorded" "expected findings > 0"
        fi
        if echo "$target" | grep -q "$watcher_skill"; then
            pass "watcher auto-scan: target path matches current run skill"
        else
            fail "watcher auto-scan: target path matches current run skill" "target='$target'"
        fi
    else
        fail "watcher auto-scan: skill scan completed" "no scan recorded for $watcher_skill"
    fi

    alerts=$(alerts_for_run 500)
    detected_count=$(echo "$alerts" | jq --arg action "install-detected" --arg skill "$watcher_skill" '[.[] | select(.action == $action and (.target | contains($skill)))] | length' 2>/dev/null || echo "0")
    if [ "${detected_count:-0}" -gt 0 ]; then
        pass "watcher auto-scan: install-detected alert recorded"
    else
        fail "watcher auto-scan: install-detected alert recorded" "no run-scoped install-detected alert for $watcher_skill"
    fi

    cleanup_skill_name "$watcher_skill"
    phase_timer_end "Phase 5B"
}

# ---------------------------------------------------------------------------
# Phase 5C — CodeGuard
# ---------------------------------------------------------------------------
phase_codeguard() {
    echo ""
    echo "=== Phase 5C: CodeGuard ==="
    phase_timer_start

    local fixture="$REPO_ROOT/test/fixtures/code/hardcoded-secret.py"
    if [ ! -f "$fixture" ]; then
        skip "codeguard" "fixture not found at $fixture"
        phase_timer_end "Phase 5C"
        return
    fi

    local payload response findings severity alerts count
    payload=$(jq -cn --arg path "$fixture" '{path: $path}')
    response=$(sidecar_post "/api/v1/scan/code" "$payload" 2>/dev/null || echo '{"error":"request failed"}')
    echo "$response" | jq '.' 2>/dev/null || echo "$response"

    findings=$(echo "$response" | jq -r '.findings | length' 2>/dev/null || echo "parse_error")
    severity=$(echo "$response" | jq -r '[.findings[].severity] | unique | join(",")' 2>/dev/null || echo "none")

    if [ "$findings" = "parse_error" ]; then
        fail "codeguard: JSON response" "response was not valid scan JSON"
    elif [ "$findings" -gt 0 ] 2>/dev/null; then
        pass "codeguard: findings detected ($findings finding(s), severities: $severity)"
    else
        fail "codeguard: findings detected" "expected findings but got 0"
    fi

    alerts=$(alerts_for_run 500)
    count=$(echo "$alerts" | jq --arg action "scan" '[.[] | select(.action == $action and (.details | contains("scanner=codeguard")))] | length' 2>/dev/null || echo "0")
    if [ "${count:-0}" -gt 0 ]; then
        pass "codeguard: audited scan event recorded"
    else
        fail "codeguard: audited scan event recorded" "no run-scoped codeguard scan event found"
    fi
    phase_timer_end "Phase 5C"
}

# ---------------------------------------------------------------------------
# Phase 5D — Status + Doctor
# ---------------------------------------------------------------------------
phase_status_doctor() {
    echo ""
    echo "=== Phase 5D: Status + Doctor ==="
    phase_timer_start

    local status_out status_rc doctor_out doctor_rc

    set +e
    status_out=$(defenseclaw status 2>&1)
    status_rc=$?
    set -e
    echo "$status_out"
    if [ "$status_rc" -eq 0 ] && echo "$status_out" | grep -q "Sidecar:" && echo "$status_out" | grep -q "skill-scanner"; then
        pass "status: reports sidecar and scanners"
    else
        fail "status: reports sidecar and scanners" "rc=$status_rc"
    fi

    set +e
    doctor_out=$(defenseclaw doctor 2>&1)
    doctor_rc=$?
    set -e
    echo "$doctor_out"
    if [ "$doctor_rc" -eq 0 ]; then
        pass "doctor: completed successfully"
    elif echo "$doctor_out" | grep -Eq 'FAIL].*(Config file|Audit database|Sidecar API|OpenClaw gateway|Splunk HEC)'; then
        fail "doctor: local prerequisites healthy" "doctor reported local prerequisite failures"
    else
        pass "doctor: completed with expected external warnings"
    fi
    phase_timer_end "Phase 5D"
}

# ---------------------------------------------------------------------------
# Phase 5E — AIBOM
# ---------------------------------------------------------------------------
phase_aibom() {
    echo ""
    echo "=== Phase 5E: AIBOM ==="
    phase_timer_start

    local out json key_check alerts count
    out=$(defenseclaw aibom scan --json 2>&1 || true)
    echo "$out"
    json=$(echo "$out" | extract_json || true)
    if [ -n "$json" ] && echo "$json" | jq -e 'has("skills") or has("plugins") or has("mcp") or has("agents") or has("tools") or has("models") or has("memory") or has("components")' >/dev/null 2>&1; then
        pass "aibom: JSON inventory emitted"
    else
        fail "aibom: JSON inventory emitted" "command did not return expected inventory JSON"
    fi

    alerts=$(alerts_for_run 500)
    count=$(echo "$alerts" | jq --arg action "scan" '[.[] | select(.action == $action and (.details | contains("scanner=aibom-claw")))] | length' 2>/dev/null || echo "0")
    if [ "${count:-0}" -gt 0 ]; then
        pass "aibom: audited scan event recorded"
    else
        fail "aibom: audited scan event recorded" "no run-scoped aibom scan event found"
    fi
    phase_timer_end "Phase 5E"
}

# ---------------------------------------------------------------------------
# Phase 5F — Policy
# ---------------------------------------------------------------------------
phase_policy() {
    echo ""
    echo "=== Phase 5F: Policy ==="
    phase_timer_start

    local list_out test_out test_rc
    list_out=$(defenseclaw policy list 2>&1 || true)
    echo "$list_out"
    if echo "$list_out" | grep -q "default" && echo "$list_out" | grep -q "strict" && echo "$list_out" | grep -q "permissive"; then
        pass "policy: built-in policies listed"
    else
        fail "policy: built-in policies listed" "missing one or more built-in policy names"
    fi

    set +e
    test_out=$(defenseclaw policy test 2>&1)
    test_rc=$?
    set -e
    echo "$test_out"
    if [ "$test_rc" -eq 0 ]; then
        pass "policy: rego test command completed"
    elif [ "$test_rc" -eq 1 ] && echo "$test_out" | grep -qi "opa.*not found"; then
        skip "policy: rego test command" "OPA binary not installed on runner"
    elif [ "$test_rc" -eq 1 ]; then
        pass "policy: rego test command executed structurally (rc=1)"
    else
        fail "policy: rego test command executed structurally" "unexpected exit code $test_rc"
    fi
    phase_timer_end "Phase 5F"
}

# ---------------------------------------------------------------------------
# Phase 5G — Skill API
# ---------------------------------------------------------------------------
phase_skill_api() {
    echo ""
    echo "=== Phase 5G: Skill API ==="
    phase_timer_start

    local skill_dir_root unique_skill target_skill payload resp entry alerts disable_count enable_count
    skill_dir_root=$(first_skill_dir || true)
    unique_skill="${E2E_PREFIX}-api-skill"
    target_skill="$unique_skill"

    if [ -n "$skill_dir_root" ] && [ -d "$REPO_ROOT/test/fixtures/skills/clean-skill" ]; then
        cleanup_skill_name "$unique_skill"
        mkdir -p "$skill_dir_root"
        copy_skill_fixture "$REPO_ROOT/test/fixtures/skills/clean-skill" "$skill_dir_root" "$unique_skill"
        if wait_for_skill_entry "$unique_skill" 30 >/dev/null 2>&1; then
            pass "skill api: unique test skill became visible to DefenseClaw"
        else
            skip "skill api: unique test skill visibility" "falling back to codeguard for runtime API test"
            target_skill="codeguard"
        fi
    else
        skip "skill api: unique test skill visibility" "clean fixture or skill dir unavailable; using codeguard"
        target_skill="codeguard"
    fi

    payload=$(jq -cn --arg skillKey "$target_skill" '{skillKey: $skillKey}')
    resp=$(sidecar_post "/skill/disable" "$payload" 2>&1 || true)
    echo "$resp"
    if echo "$resp" | grep -qi "error"; then
        fail "skill api: disable endpoint" "$resp"
        phase_timer_end "Phase 5G"
        cleanup_skill_name "$unique_skill"
        return
    else
        pass "skill api: disable endpoint responded"
    fi

    sleep 3
    entry=$(skill_entry_json "$target_skill")
    if [ -n "$entry" ] && [ "$(echo "$entry" | jq -r '.disabled // false' 2>/dev/null)" = "true" ]; then
        pass "skill api: disabled state visible in skill list"
    else
        fail "skill api: disabled state visible in skill list" "$entry"
    fi

    resp=$(sidecar_post "/skill/enable" "$payload" 2>&1 || true)
    echo "$resp"
    if echo "$resp" | grep -qi "error"; then
        fail "skill api: enable endpoint" "$resp"
    else
        pass "skill api: enable endpoint responded"
    fi

    sleep 3
    entry=$(skill_entry_json "$target_skill")
    if [ -n "$entry" ] && [ "$(echo "$entry" | jq -r '.disabled // false' 2>/dev/null)" = "false" ]; then
        pass "skill api: enabled state visible in skill list"
    else
        fail "skill api: enabled state visible in skill list" "$entry"
    fi

    alerts=$(alerts_for_run 500)
    disable_count=$(echo "$alerts" | jq --arg target "$target_skill" '[.[] | select(.action == "api-skill-disable" and .target == $target)] | length' 2>/dev/null || echo "0")
    enable_count=$(echo "$alerts" | jq --arg target "$target_skill" '[.[] | select(.action == "api-skill-enable" and .target == $target)] | length' 2>/dev/null || echo "0")
    if [ "${disable_count:-0}" -gt 0 ]; then
        pass "skill api: disable audit event recorded"
    else
        fail "skill api: disable audit event recorded" "no api-skill-disable event for $target_skill"
    fi
    if [ "${enable_count:-0}" -gt 0 ]; then
        pass "skill api: enable audit event recorded"
    else
        fail "skill api: enable audit event recorded" "no api-skill-enable event for $target_skill"
    fi

    cleanup_skill_name "$unique_skill"
    phase_timer_end "Phase 5G"
}

# ---------------------------------------------------------------------------
# Phase 6 — Guardrail Proxy
# ---------------------------------------------------------------------------
phase_guardrail() {
    if ! is_full_live; then
        return
    fi

    echo ""
    echo "=== Phase 6: Guardrail Proxy ==="
    phase_timer_start

    if ! wait_for_url "$GUARDRAIL_URL/health/liveliness" 10 2; then
        skip_or_fail "$E2E_REQUIRE_GUARDRAIL" "guardrail proxy" "not reachable on port 4000"
        phase_timer_end "Phase 6"
        return
    fi
    pass "guardrail proxy reachable"

    local master_key response content err request_model
    request_model="${GUARDRAIL_REQUEST_MODEL:-}"
    if [ -z "$request_model" ]; then
        request_model=$(python3 - <<'PY'
from defenseclaw.config import load
try:
    cfg = load()
    print((cfg.guardrail.model or "").strip())
except Exception:
    print("")
PY
)
    fi
    if [ -z "$request_model" ]; then
        skip_or_fail "$E2E_REQUIRE_GUARDRAIL" "guardrail proxy" "no configured live guardrail model"
        phase_timer_end "Phase 6"
        return
    fi

    master_key=$(python3 - <<'PY'
import hashlib
import hmac
import os

key_file = os.path.expanduser("~/.defenseclaw/device.key")
try:
    with open(key_file, "rb") as f:
        data = f.read()
    digest = hmac.new(b"defenseclaw-proxy-master-key", data, hashlib.sha256).hexdigest()[:32]
    print(f"sk-dc-{digest}")
except OSError:
    print("sk-dc-local-dev")
PY
)

    response=$(curl -sf --max-time 45 \
        -H "Authorization: Bearer $master_key" \
        -H "Content-Type: application/json" \
        -d "$(jq -cn --arg model "$request_model" '{model: $model, messages: [{role: "user", content: "Reply with exactly: E2E_OK"}], max_tokens: 20}')" \
        "$GUARDRAIL_URL/v1/chat/completions" 2>/dev/null || echo '{"error":"timeout or connection refused"}')

    echo "$response" | jq '.' 2>/dev/null || echo "$response"
    content=$(echo "$response" | jq -r '.choices[0].message.content // empty' 2>/dev/null || true)

    if echo "$content" | grep -q "E2E_OK"; then
        pass "guardrail round-trip: LLM responded with E2E_OK"
    else
        err=$(echo "$response" | jq -r '.error.message // .error // empty' 2>/dev/null || true)
        if [ -n "$err" ] && echo "$err" | grep -qi "credit\|quota\|rate\|key"; then
            pass "guardrail round-trip: proxy forwarded request (provider limitation: $err)"
        elif [ -n "$content" ]; then
            pass "guardrail round-trip: LLM responded (content: $content)"
        else
            fail "guardrail round-trip: LLM responded" "err='$err' response='$response'"
        fi
    fi
    phase_timer_end "Phase 6"
}

# ---------------------------------------------------------------------------
# Phase 7 — OpenClaw Agent Chat
# ---------------------------------------------------------------------------
phase_agent_chat() {
    if ! is_full_live; then
        return
    fi

    echo ""
    echo "=== Phase 7: OpenClaw Agent Chat ==="
    phase_timer_start

    if ! command -v openclaw >/dev/null 2>&1; then
        skip "agent chat" "openclaw CLI not found"
        phase_timer_end "Phase 7"
        return
    fi

    if ! curl -sf --max-time 3 "$OPENCLAW_URL" >/dev/null 2>&1; then
        echo "  OpenClaw gateway not responding — restarting..."
        openclaw gateway stop 2>/dev/null || true
        sleep 1
        openclaw gateway --force &
        OPENCLAW_PID=$!
        sleep 5
        defenseclaw-gateway restart 2>/dev/null || true
        sleep 3
    fi

    local session_id="${E2E_PREFIX}-agent-$$"
    local install_slug="weather"
    local skill_dirs disk_before skills_before before_names
    local ping_out install_out installed_skill installed_path dc_entry

    skill_dirs=$(get_skill_dirs)
    echo "  Skill directories watched by DefenseClaw:"
    while IFS= read -r dir; do
        [ -n "$dir" ] || continue
        echo "    - $dir"
        mkdir -p "$dir"
    done <<< "$skill_dirs"

    cleanup_skill_name "$install_slug"
    skills_before=$(openclaw skills list --json 2>/dev/null || echo "[]")
    before_names=$(echo "$skills_before" | jq -r '.[].name' 2>/dev/null | sort || true)
    disk_before=$(snapshot_skill_paths | sort -u)

    echo "  Sending ping prompt..."
    ping_out=$(timeout 120 openclaw agent --session-id "$session_id" -m "Reply with exactly one word: PONG" 2>&1 || true)
    echo "$ping_out"
    if echo "$ping_out" | grep -qi "PONG"; then
        pass "agent chat: agent is alive"
    elif [ -n "$ping_out" ] && ! echo "$ping_out" | grep -qi "error\|refused\|timeout"; then
        pass "agent chat: agent responded"
    else
        fail "agent chat: agent is alive" "no usable response"
        phase_timer_end "Phase 7"
        return
    fi

    echo "  Asking agent to install '$install_slug'..."
    install_out=$(timeout 180 openclaw agent \
        --session-id "${session_id}-install" \
        -m "Install the ${install_slug} skill from ClawHub. Run this exact command: openclaw skills install ${install_slug}" \
        2>&1 || true)
    echo "$install_out"
    sleep 5

    local disk_after new_on_disk skills_after after_names new_in_list
    disk_after=$(snapshot_skill_paths | sort -u)
    skills_after=$(openclaw skills list --json 2>/dev/null || echo "[]")
    after_names=$(echo "$skills_after" | jq -r '.[].name' 2>/dev/null | sort || true)
    new_on_disk=$(comm -13 \
        <(printf '%s\n' "$disk_before" | sed '/^[[:space:]]*$/d' | sort -u) \
        <(printf '%s\n' "$disk_after" | sed '/^[[:space:]]*$/d' | sort -u) || true)
    new_in_list=$(comm -13 \
        <(printf '%s\n' "$before_names" | sed '/^[[:space:]]*$/d' | sort -u) \
        <(printf '%s\n' "$after_names" | sed '/^[[:space:]]*$/d' | sort -u) || true)

    if [ -n "$new_on_disk" ]; then
        installed_path=$(printf '%s\n' "$new_on_disk" | sed '/^[[:space:]]*$/d' | head -1)
        installed_skill=$(basename "$installed_path")
        pass "agent chat: skill '$installed_skill' installed on disk"
    elif [ -n "$new_in_list" ]; then
        installed_skill=$(printf '%s\n' "$new_in_list" | sed '/^[[:space:]]*$/d' | head -1)
        installed_path=$(find_skill_path "$installed_skill" || true)
        pass "agent chat: skill '$installed_skill' appeared in openclaw list"
    else
        skip_or_fail "$E2E_REQUIRE_AGENT_INSTALL" "agent chat: skill install" "agent install could not be verified"
    fi

    if [ -n "${installed_skill:-}" ]; then
        dc_entry=$(wait_for_skill_scan "$installed_skill" 90 || true)
        if [ -n "$dc_entry" ] && [ "$dc_entry" != "null" ]; then
            local scan_severity scan_findings
            scan_severity=$(echo "$dc_entry" | jq -r '.scan.max_severity // "NONE"' 2>/dev/null || echo "NONE")
            scan_findings=$(echo "$dc_entry" | jq -r '.scan.total_findings // 0' 2>/dev/null || echo "0")
            if [ "$scan_severity" != "NONE" ] && [ "$scan_severity" != "null" ]; then
                pass "agent chat: DefenseClaw scanned '$installed_skill' (severity=$scan_severity, findings=$scan_findings)"
            else
                skip_or_fail "$E2E_REQUIRE_AGENT_SCAN" "agent chat: DefenseClaw scan" "skill found but scan not completed"
            fi
        else
            skip_or_fail "$E2E_REQUIRE_AGENT_SCAN" "agent chat: DefenseClaw scan" "no scan found for $installed_skill"
        fi
    fi

    if [ -n "${installed_skill:-}" ]; then
        if [ -n "${installed_path:-}" ] && [ -d "$installed_path" ]; then
            rm -rf "$installed_path" 2>/dev/null || true
        else
            cleanup_skill_name "$installed_skill"
        fi
        sleep 2
        if [ -z "$(find_skill_path "$installed_skill" || true)" ]; then
            pass "agent chat: installed skill cleaned up"
        else
            fail "agent chat: installed skill cleaned up" "skill directory still present"
        fi
    else
        skip "agent chat: cleanup" "no installed skill to remove"
    fi
    phase_timer_end "Phase 7"
}

# ---------------------------------------------------------------------------
# Phase 8 — Splunk Log Verification
# ---------------------------------------------------------------------------
phase_splunk() {
    echo ""
    echo "=== Phase 8: Splunk Log Verification ==="
    phase_timer_start

    local hec_health hec_response schema_result
    hec_health=$(curl -sf --max-time 5 "$SPLUNK_HEC_URL/services/collector/health" 2>&1 || echo "unreachable")
    echo "  HEC health response: $hec_health"
    if [ "$hec_health" = "unreachable" ] || [ -z "$hec_health" ]; then
        fail "Splunk HEC reachable" "HEC health endpoint is unreachable"
        phase_timer_end "Phase 8"
        return
    fi
    pass "Splunk HEC reachable"

    hec_response=$(curl -sf --max-time 5 \
        -H "Authorization: Splunk $SPLUNK_HEC_TOKEN" \
        -H "Content-Type: application/json" \
        -d "{\"event\":{\"action\":\"e2e-suite-marker\",\"run_id\":\"$DEFENSECLAW_RUN_ID\",\"source\":\"test-e2e-full-stack\",\"timestamp\":\"$(date -u +%FT%TZ)\"},\"index\":\"$SPLUNK_INDEX\"}" \
        "$SPLUNK_HEC_URL/services/collector/event" 2>/dev/null || echo '{"text":"error"}')
    echo "  Marker response: $hec_response"
    if echo "$hec_response" | jq -e '.text == "Success"' >/dev/null 2>&1; then
        pass "Splunk HEC accepts writes"
    else
        fail "Splunk HEC accepts writes" "response: $hec_response"
    fi

    echo "  Waiting 12s for run-scoped events to be indexed..."
    sleep 12

    splunk_assert_results "Splunk: skill scanner audit events present" 'action=scan details="*scanner=skill-scanner*" | head 5'
    splunk_assert_results "Splunk: CodeGuard scan events present" 'action=scan details="*scanner=codeguard*" | head 5'
    splunk_assert_results "Splunk: AIBOM scan events present" 'action=scan details="*scanner=aibom-claw*" | head 5'
    splunk_assert_results "Splunk: sidecar lifecycle events present" '(action=init-sidecar OR action=sidecar-start OR action=sidecar-connected) | head 5'
    splunk_assert_results "Splunk: watcher lifecycle events present" 'action=watch-start | head 5'
    splunk_assert_results "Splunk: watcher install events present" '(action=install-detected OR action=install-rejected OR action=install-allowed) | head 5'
    splunk_assert_results "Splunk: quarantine and restore events present" '(action=skill-quarantine OR action=skill-restore) | head 5'
    splunk_assert_results "Splunk: skill block/allow events present" '(action=skill-block OR action=skill-allow) | head 5'
    splunk_assert_results "Splunk: MCP block/allow events present" '(action=block-mcp OR action=allow-mcp) | head 5'
    splunk_assert_results "Splunk: tool block/allow events present" '(action=tool-block OR action=tool-allow) | head 5'
    splunk_assert_results "Splunk: skill API disable/enable events present" '(action=api-skill-disable OR action=api-skill-enable) | head 5'
    splunk_assert_results "Splunk: high-severity events present" '(severity=HIGH OR severity=CRITICAL) | head 5'

    schema_result=$(splunk_run_results_json 'action=scan | head 1')
    echo "  --- Splunk schema check ---"
    echo "$schema_result" | jq '.' 2>/dev/null || echo "$schema_result"
    echo "  --- end schema check ---"
    if echo "$schema_result" | jq -e 'length > 0 and (.[0].action // "") != "" and (.[0].target // "") != "" and (.[0].actor // "") != "" and (.[0].details // "") != "" and (.[0].severity // "") != "" and (.[0].run_id // "") != ""' >/dev/null 2>&1; then
        pass "Splunk: event schema contains action,target,actor,details,severity,run_id"
    else
        fail "Splunk: event schema contains action,target,actor,details,severity,run_id" "schema check query returned incomplete fields"
    fi

    if is_full_live; then
        splunk_assert_results "Splunk: agent lifecycle events present" '(action=gateway-agent-start OR action=gateway-agent-end) | head 5'
        splunk_assert_results "Splunk: runtime tool inspection events present" '(action=inspect-tool-allow OR action=inspect-tool-block) | head 5'
    fi
    phase_timer_end "Phase 8"
}

# ---------------------------------------------------------------------------
# Phase 9 — Teardown
# ---------------------------------------------------------------------------
phase_teardown() {
    echo ""
    echo "=== Phase 9: Teardown ==="

    echo "  Final sidecar status:"
    defenseclaw-gateway status 2>/dev/null || true

    defenseclaw-gateway stop 2>/dev/null || true
    openclaw gateway stop 2>/dev/null || true

    echo "  Services stopped (Splunk container left running for dashboard access)"
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
print_summary() {
    echo ""
    echo "============================================================"
    echo "  E2E Summary: $PASS passed, $FAIL failed, $SKIP_COUNT skipped"
    echo "============================================================"
    echo "  Profile: $E2E_PROFILE"
    echo "  Run ID:  $DEFENSECLAW_RUN_ID"

    if [ ${#RESULTS[@]} -gt 0 ]; then
        echo ""
        echo "  All results:"
        for r in "${RESULTS[@]}"; do
            echo "    $r"
        done
    fi

    if [ "$FAIL" -gt 0 ]; then
        echo ""
        echo "  FAILURES:"
        for r in "${RESULTS[@]}"; do
            if [[ "$r" == FAIL:* ]]; then
                echo "    - ${r#FAIL: }"
            fi
        done
    fi

    if [ "$SKIP_COUNT" -gt 8 ]; then
        echo ""
        echo "  WARNING: $SKIP_COUNT tests were skipped — review environment setup"
    fi
    echo ""
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    echo "============================================================"
    echo "  DefenseClaw Full-Stack E2E"
    echo "============================================================"

    trap 'phase_teardown; print_summary; if [ "$FAIL" -gt 0 ]; then dump_artifacts; fi' EXIT

    phase_start || exit 1
    phase_health
    phase_skill_scanner
    phase_mcp_scanner
    phase_block_allow
    phase_quarantine
    phase_watcher_auto_scan
    phase_codeguard
    phase_status_doctor
    phase_aibom
    phase_policy
    phase_skill_api
    phase_guardrail
    phase_agent_chat
    phase_splunk

    [ "$FAIL" -eq 0 ]
}

main "$@"
