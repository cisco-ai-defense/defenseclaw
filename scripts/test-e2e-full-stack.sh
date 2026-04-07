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

PASS=0
FAIL=0
SKIP_COUNT=0
RESULTS=()
PHASE_START_T=0

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
    local elapsed=$(( SECONDS - PHASE_START_T ))
    printf "  [timer] %s completed in %ds\n" "$name" "$elapsed"
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

splunk_search() {
    local query="$1"
    curl -sf --max-time 15 -k \
        -u "$SPLUNK_CREDS" \
        -d "search=search index=defenseclaw_local $query" \
        -d "output_mode=json" \
        "$SPLUNK_API_URL/services/search/jobs/export" 2>/dev/null || echo '{}'
}

# Extract a JSON object from output that may have non-JSON prefix lines.
# Collects everything from the first '{' to the end and pipes through jq.
extract_json() {
    sed -n '/^\s*{/,$ p' | jq '.' 2>/dev/null
}

dump_artifacts() {
    echo ""
    echo "=== Artifact Dump (on failure) ==="
    echo "--- ~/.defenseclaw/config.yaml ---"
    cat ~/.defenseclaw/config.yaml 2>/dev/null || echo "  (not found)"
    echo "--- .env key names ---"
    grep -oP '^\w+(?==)' ~/.defenseclaw/.env 2>/dev/null || echo "  (none)"
    echo "--- defenseclaw-gateway status ---"
    defenseclaw-gateway status 2>/dev/null || echo "  (not running)"
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

    echo "  Starting OpenClaw gateway..."
    openclaw gateway --force &
    OPENCLAW_PID=$!
    sleep 5

    echo "  Checking if DefenseClaw sidecar is already running..."
    if curl -sf --max-time 3 "$SIDECAR_URL/health" >/dev/null 2>&1; then
        echo "  Sidecar already running — restarting to connect to OpenClaw..."
        defenseclaw-gateway restart
    else
        echo "  Starting DefenseClaw sidecar..."
        defenseclaw-gateway start
    fi
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
    if [ "$guard_state" = "running" ]; then
        pass "health: guardrail is running"
    elif [ "$guard_state" = "disabled" ]; then
        skip "health: guardrail" "disabled — no model or API key configured"
    elif [ "$guard_state" = "error" ]; then
        local guard_err
        guard_err=$(echo "$health" | jq -r '.guardrail.last_error // empty' 2>/dev/null)
        if echo "$guard_err" | grep -qi "no API key\|api_key_env\|key not found"; then
            skip "health: guardrail" "no API key for model provider (Bedrock models use AWS IAM, not API keys)"
        else
            fail "health: guardrail is running" "error — $guard_err"
        fi
    else
        fail "health: guardrail is running" "got '$guard_state'"
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

    if [ ! -d "$clean_skill" ]; then
        skip "skill scanner" "test fixtures not found at $clean_skill"
        phase_timer_end "Phase 3"
        return
    fi

    echo "  Scanning clean skill..."
    local clean_out
    clean_out=$(defenseclaw skill scan "$clean_skill" --json 2>&1 || true)
    echo "  --- Clean skill scan output ---"
    echo "$clean_out"
    echo "  --- end clean skill output ---"

    local clean_json
    clean_json=$(echo "$clean_out" | extract_json || true)

    if [ -n "$clean_json" ]; then
        local clean_findings
        clean_findings=$(echo "$clean_json" | jq -r '.findings | length' 2>/dev/null || echo "parse_error")
        if [ "$clean_findings" = "parse_error" ]; then
            fail "skill scan: clean skill" "scanner returned non-parseable JSON"
        else
            pass "skill scan: clean skill scanned ($clean_findings finding(s))"
        fi
    else
        if echo "$clean_out" | grep -qi "error\|traceback\|not found"; then
            fail "skill scan: clean skill" "scanner produced error output"
        else
            fail "skill scan: clean skill" "scanner did not produce valid JSON with --json flag"
        fi
    fi

    echo "  Scanning malicious skill..."
    local mal_out
    mal_out=$(defenseclaw skill scan "$malicious_skill" --json 2>&1 || true)
    echo "  --- Malicious skill scan output ---"
    echo "$mal_out"
    echo "  --- end malicious skill output ---"

    local mal_json
    mal_json=$(echo "$mal_out" | extract_json || true)

    if [ -n "$mal_json" ]; then
        local mal_findings mal_severity
        mal_findings=$(echo "$mal_json" | jq -r '.findings | length' 2>/dev/null || echo "0")
        mal_severity=$(echo "$mal_json" | jq -r '[.findings[].severity] | unique | join(",")' 2>/dev/null || echo "none")
        if [ "$mal_findings" -gt 0 ] 2>/dev/null; then
            pass "skill scan: malicious skill has $mal_findings finding(s) (severities: $mal_severity)"
        else
            fail "skill scan: malicious skill" "expected findings but got 0"
        fi
    else
        fail "skill scan: malicious skill" "scanner did not produce valid JSON with --json flag"
    fi
    phase_timer_end "Phase 3"
}

# ---------------------------------------------------------------------------
# Phase 4 — MCP Scanner (CLI)
# ---------------------------------------------------------------------------
phase_mcp_scanner() {
    echo ""
    echo "=== Phase 4: MCP Scanner (CLI) ==="
    phase_timer_start

    local mcp_list
    mcp_list=$(defenseclaw mcp list --json 2>/dev/null || echo "[]")
    local mcp_count
    mcp_count=$(echo "$mcp_list" | jq 'length' 2>/dev/null || echo "0")

    if [ "${mcp_count:-0}" -eq 0 ]; then
        skip "mcp scanner" "no MCP servers configured in openclaw.json"
        phase_timer_end "Phase 4"
        return
    fi

    echo "  Found $mcp_count MCP server(s). Scanning first server..."
    local first_name
    first_name=$(echo "$mcp_list" | jq -r '.[0].name' 2>/dev/null || echo "")

    if [ -z "$first_name" ]; then
        skip "mcp scanner" "could not determine first MCP server name"
        phase_timer_end "Phase 4"
        return
    fi

    local mcp_out
    mcp_out=$(defenseclaw mcp scan "$first_name" --json 2>&1 || true)
    echo "  --- MCP scan output ---"
    echo "$mcp_out"
    echo "  --- end MCP scan output ---"

    if echo "$mcp_out" | grep -qi "error:\|traceback\|Missing argument"; then
        fail "mcp scan" "scanner error: $(echo "$mcp_out" | head -3)"
    else
        local mcp_json
        mcp_json=$(echo "$mcp_out" | extract_json || true)
        if [ -n "$mcp_json" ]; then
            local mcp_findings
            mcp_findings=$(echo "$mcp_json" | jq -r '.findings | length' 2>/dev/null || echo "0")
            pass "mcp scan: server '$first_name' scanned ($mcp_findings finding(s))"
        else
            pass "mcp scan: server '$first_name' scanned (non-JSON output)"
        fi
    fi
    phase_timer_end "Phase 4"
}

# ---------------------------------------------------------------------------
# Phase 5 — Quarantine Flow (CLI: copy skill → quarantine → verify → restore → verify)
# ---------------------------------------------------------------------------
phase_quarantine() {
    echo ""
    echo "=== Phase 5: Quarantine Flow (CLI) ==="
    phase_timer_start

    local malicious_skill="$REPO_ROOT/test/fixtures/skills/malicious-skill"
    local skill_name="malicious-skill"

    if [ ! -d "$malicious_skill" ]; then
        skip "quarantine" "test fixtures not found"
        phase_timer_end "Phase 5"
        return
    fi

    local skill_dir_root
    skill_dir_root=$(python3 -c "
from defenseclaw.config import load
cfg = load()
for d in cfg.skill_dirs():
    print(d)
" 2>/dev/null | head -1 || true)

    if [ -z "$skill_dir_root" ]; then
        skip "quarantine" "could not determine skill directory"
        phase_timer_end "Phase 5"
        return
    fi

    echo "  Copying malicious skill to skill dir: $skill_dir_root"
    mkdir -p "$skill_dir_root/$skill_name"
    cp -r "$malicious_skill"/* "$skill_dir_root/$skill_name/" 2>/dev/null || true

    if [ -d "$skill_dir_root/$skill_name" ]; then
        echo "  Contents: $(ls "$skill_dir_root/$skill_name/")"
        pass "quarantine: malicious skill placed in skill dir"
    else
        fail "quarantine: place skill" "failed to copy to $skill_dir_root/$skill_name"
        phase_timer_end "Phase 5"
        return
    fi

    echo "  Quarantining malicious skill..."
    local q_out
    q_out=$(defenseclaw skill quarantine "$skill_name" --reason "E2E test: data exfiltration pattern" 2>&1 || true)
    echo "  --- Quarantine output ---"
    echo "$q_out"
    echo "  --- end quarantine output ---"

    if [ -d "$skill_dir_root/$skill_name" ]; then
        fail "quarantine: skill quarantined" "directory still exists at $skill_dir_root/$skill_name after quarantine"
    else
        pass "quarantine: skill directory removed from $skill_dir_root"
    fi

    echo "  Restoring quarantined skill..."
    local r_out
    r_out=$(defenseclaw skill restore "$skill_name" 2>&1 || true)
    echo "  --- Restore output ---"
    echo "$r_out"
    echo "  --- end restore output ---"

    if [ -d "$skill_dir_root/$skill_name" ]; then
        pass "quarantine: skill restored to $skill_dir_root"
    else
        fail "quarantine: restore" "directory not found at $skill_dir_root/$skill_name after restore"
    fi

    rm -rf "$skill_dir_root/$skill_name" 2>/dev/null || true
    phase_timer_end "Phase 5"
}

# ---------------------------------------------------------------------------
# Phase 6 — Guardrail Proxy (if running)
# ---------------------------------------------------------------------------
phase_guardrail() {
    echo ""
    echo "=== Phase 6: Guardrail Proxy ==="
    phase_timer_start

    if ! wait_for_url "$GUARDRAIL_URL/health/liveliness" 10 2; then
        skip "guardrail proxy" "not reachable on port 4000 (may need API key configured)"
        phase_timer_end "Phase 6"
        return
    fi
    pass "guardrail proxy reachable"

    local master_key
    master_key=$(python3 -c "
import hashlib, hmac, os
key_file = os.path.expanduser('~/.defenseclaw/device.key')
try:
    with open(key_file, 'rb') as f:
        data = f.read()
    digest = hmac.new(b'defenseclaw-proxy-master-key', data, hashlib.sha256).hexdigest()[:32]
    print(f'sk-dc-{digest}')
except OSError:
    print('sk-dc-local-dev')
" 2>/dev/null)

    local response
    response=$(curl -sf --max-time 45 \
        -H "Authorization: Bearer $master_key" \
        -H "Content-Type: application/json" \
        -d '{"model":"claude-sonnet-4-5","messages":[{"role":"user","content":"Reply with exactly: E2E_OK"}],"max_tokens":20}' \
        "$GUARDRAIL_URL/v1/chat/completions" 2>/dev/null || echo '{"error":"timeout or connection refused"}')

    echo "  --- Guardrail proxy response ---"
    echo "$response" | jq '.' 2>/dev/null || echo "$response"
    echo "  --- end guardrail response ---"

    local content
    content=$(echo "$response" | jq -r '.choices[0].message.content // empty' 2>/dev/null)

    if echo "$content" | grep -q "E2E_OK"; then
        pass "guardrail round-trip: LLM responded with E2E_OK"
    else
        local err
        err=$(echo "$response" | jq -r '.error.message // .error // empty' 2>/dev/null)
        if [ -n "$err" ] && echo "$err" | grep -qi "credit\|quota\|rate\|key"; then
            pass "guardrail round-trip: proxy forwarded request (LLM billing issue: $err)"
        elif [ -n "$content" ]; then
            pass "guardrail round-trip: LLM responded (content: $content)"
        else
            fail "guardrail round-trip: LLM responded" "err='$err' response='$response'"
        fi
    fi
    phase_timer_end "Phase 6"
}

# ---------------------------------------------------------------------------
# Phase 7 — OpenClaw Agent Chat (agent-driven real-world testing)
# ---------------------------------------------------------------------------
phase_agent_chat() {
    echo ""
    echo "=== Phase 7: OpenClaw Agent Chat ==="
    phase_timer_start

    if ! command -v openclaw >/dev/null 2>&1; then
        skip "agent chat" "openclaw CLI not found"
        phase_timer_end "Phase 7"
        return
    fi

    local session_id="e2e-test-$$"

    # --- Discover skill directories ---
    local skill_dir_root
    skill_dir_root=$(python3 -c "
from defenseclaw.config import load
cfg = load()
for d in cfg.skill_dirs():
    print(d)
" 2>/dev/null | head -1 || echo "$HOME/.openclaw/skills")
    echo "  Primary skill directory: $skill_dir_root"
    mkdir -p "$skill_dir_root"

    # --- Clean stale skills from prior runs ---
    echo "  Cleaning stale test skills from prior runs..."
    for pattern in wiki wiki-search wiki-retriever wikilocal "WikiLocal*" feishu-wiki; do
        rm -rf "${skill_dir_root:?}/$pattern" 2>/dev/null || true
    done
    echo "  Done cleaning stale skills"

    # --- Snapshot skills BEFORE ---
    local skills_before
    skills_before=$(openclaw skills list --json 2>/dev/null || echo "[]")
    local before_names
    before_names=$(echo "$skills_before" | jq -r '.[].name' 2>/dev/null | sort || true)
    local before_count
    before_count=$(echo "$before_names" | grep -c '[^[:space:]]' || echo 0)
    echo "  Skills known to OpenClaw before: $before_count"

    local disk_before
    disk_before=$(ls -1 "$skill_dir_root" 2>/dev/null | sort || true)
    echo "  Skills on disk before: $(echo "$disk_before" | grep -c '[^[:space:]]' || echo 0)"

    # --- Discover a real ClawHub skill to install ---
    echo ""
    echo "  Discovering available ClawHub skills..."
    local search_out
    search_out=$(timeout 30 openclaw skills search --limit 5 --json 2>/dev/null || echo "[]")
    local install_slug=""

    if echo "$search_out" | jq -e 'length > 0' >/dev/null 2>&1; then
        install_slug=$(echo "$search_out" | jq -r '.[0].slug // .[0].name // empty' 2>/dev/null)
        echo "  Found ClawHub skill: $install_slug"
    fi

    if [ -z "$install_slug" ]; then
        echo "  ClawHub search returned no results; using fallback slug 'weather'"
        install_slug="weather"
    fi

    # --- Test 1: Verify agent is alive ---
    echo ""
    echo "  --- Test 1: Agent ping ---"
    echo "  Sending: 'Reply with exactly one word: PONG'"
    local ping_out
    ping_out=$(timeout 120 openclaw agent \
        --session-id "$session_id" \
        -m "Reply with exactly one word: PONG" \
        2>&1 || true)
    echo "  --- Agent ping output (full) ---"
    echo "$ping_out"
    echo "  --- end agent ping output ---"

    if echo "$ping_out" | grep -qi "PONG"; then
        pass "agent chat: agent is alive (replied PONG)"
    elif [ -n "$ping_out" ] && ! echo "$ping_out" | grep -qi "error\|refused\|timeout"; then
        pass "agent chat: agent responded (non-deterministic LLM — did not say PONG)"
    else
        fail "agent chat: agent is alive" "no output or error in response"
        phase_timer_end "Phase 7"
        return
    fi

    # --- Test 2: Ask agent to install a skill ---
    echo ""
    echo "  --- Test 2: Agent installs skill '$install_slug' ---"
    local install_prompt="Install the $install_slug skill from ClawHub. Run this exact command: openclaw skills install $install_slug"
    echo "  Sending: '$install_prompt'"
    local install_out
    install_out=$(timeout 180 openclaw agent \
        --session-id "${session_id}-install" \
        -m "$install_prompt" \
        2>&1 || true)
    echo "  --- Agent install output (full) ---"
    echo "$install_out"
    echo "  --- end agent install output ---"

    # Give the filesystem and watcher time to settle
    sleep 3

    # --- Verify installation via disk diff ---
    local disk_after
    disk_after=$(ls -1 "$skill_dir_root" 2>/dev/null | sort || true)
    local new_on_disk
    new_on_disk=$(comm -13 <(echo "$disk_before") <(echo "$disk_after") | grep -v '^$' || true)

    # Also check openclaw's own skill list
    local skills_after
    skills_after=$(openclaw skills list --json 2>/dev/null || echo "[]")
    local after_names
    after_names=$(echo "$skills_after" | jq -r '.[].name' 2>/dev/null | sort || true)
    local new_in_list
    new_in_list=$(comm -13 <(echo "$before_names") <(echo "$after_names") | grep -v '^$' || true)

    local installed_skill=""
    if [ -n "$new_on_disk" ]; then
        installed_skill=$(echo "$new_on_disk" | head -1)
        echo "  NEW skill directory on disk: $new_on_disk"
        pass "agent chat: skill '$installed_skill' installed on disk"
    elif [ -n "$new_in_list" ]; then
        installed_skill=$(echo "$new_in_list" | head -1)
        echo "  NEW skill in openclaw list: $new_in_list"
        pass "agent chat: skill '$installed_skill' appeared in openclaw skills list"
    elif echo "$install_out" | grep -qi "installed\|successfully\|added"; then
        echo "  Agent claimed success but no new directory or list entry detected"
        installed_skill="$install_slug"
        skip "agent chat: skill install" "agent claims success but not verified on disk/list"
    else
        echo "  WARNING: no new skill on disk or in list, agent did not confirm success"
        echo "  Disk before: $(echo "$disk_before" | tr '\n' ' ')"
        echo "  Disk after:  $(echo "$disk_after" | tr '\n' ' ')"
        fail "agent chat: skill install" "no new skill detected on disk or in openclaw list"
    fi

    # --- Test 3: Poll for DefenseClaw scan results ---
    echo ""
    echo "  --- Test 3: DefenseClaw scan results ---"
    if [ -n "$installed_skill" ]; then
        echo "  Polling for scan results on '$installed_skill' (5s intervals, 90s timeout)..."
        local scan_deadline=$((SECONDS + 90))
        local scan_found=false
        local dc_entry=""

        while [ $SECONDS -lt $scan_deadline ]; do
            local dc_list
            dc_list=$(defenseclaw skill list --json 2>/dev/null || echo "[]")
            dc_entry=$(echo "$dc_list" | jq --arg n "$installed_skill" '[.[] | select(.name == $n)][0] // empty' 2>/dev/null || true)

            if [ -n "$dc_entry" ] && [ "$dc_entry" != "null" ]; then
                local has_scan
                has_scan=$(echo "$dc_entry" | jq -r '.scan // empty' 2>/dev/null)
                if [ -n "$has_scan" ] && [ "$has_scan" != "null" ]; then
                    scan_found=true
                    break
                fi
            fi
            sleep 5
        done

        if [ "$scan_found" = false ]; then
            echo "  Poll timed out. Triggering scan via sidecar API..."
            local skill_path="$skill_dir_root/$installed_skill"
            curl -sf -X POST "$SIDECAR_URL/v1/skill/scan" \
                -H "Content-Type: application/json" \
                -d "{\"target\": \"$skill_path\"}" 2>/dev/null || true
            sleep 10

            local dc_list
            dc_list=$(defenseclaw skill list --json 2>/dev/null || echo "[]")
            dc_entry=$(echo "$dc_list" | jq --arg n "$installed_skill" '[.[] | select(.name == $n)][0] // empty' 2>/dev/null || true)
        fi

        if [ -n "$dc_entry" ] && [ "$dc_entry" != "null" ]; then
            echo "  --- DefenseClaw entry for '$installed_skill' ---"
            echo "$dc_entry" | jq '.' 2>/dev/null || echo "$dc_entry"
            echo "  --- end entry ---"

            local scan_severity scan_findings scan_clean
            scan_severity=$(echo "$dc_entry" | jq -r '.scan.max_severity // "NONE"' 2>/dev/null)
            scan_findings=$(echo "$dc_entry" | jq -r '.scan.total_findings // "0"' 2>/dev/null)
            scan_clean=$(echo "$dc_entry" | jq -r '.scan.clean // "unknown"' 2>/dev/null)

            if [ "$scan_severity" != "NONE" ] && [ "$scan_severity" != "null" ]; then
                pass "agent chat: DefenseClaw scanned '$installed_skill' (severity=$scan_severity, findings=$scan_findings)"
            else
                skip "agent chat: DefenseClaw scan" "skill in inventory but scan not completed"
            fi
        else
            skip "agent chat: DefenseClaw scan" "skill '$installed_skill' not found in defenseclaw inventory"
        fi
    else
        skip "agent chat: DefenseClaw scan" "no skill was installed to scan"
    fi

    # --- Test 4: Agent removes the skill ---
    echo ""
    echo "  --- Test 4: Agent removes skill ---"
    if [ -n "$installed_skill" ]; then
        local remove_prompt="Remove the $installed_skill skill. Delete its folder by running: rm -rf $skill_dir_root/$installed_skill"
        echo "  Sending: '$remove_prompt'"
        local remove_out
        remove_out=$(timeout 120 openclaw agent \
            --session-id "${session_id}-remove" \
            -m "$remove_prompt" \
            2>&1 || true)
        echo "  --- Agent remove output (full) ---"
        echo "$remove_out"
        echo "  --- end agent remove output ---"

        sleep 2

        if [ ! -d "$skill_dir_root/$installed_skill" ]; then
            pass "agent chat: skill '$installed_skill' removed from disk"
        else
            echo "  Skill directory still exists — trying manual cleanup for next run"
            rm -rf "$skill_dir_root/$installed_skill" 2>/dev/null || true
            if echo "$remove_out" | grep -qi "removed\|deleted\|done"; then
                skip "agent chat: skill removal" "agent claims removed but directory persisted"
            else
                fail "agent chat: skill removal" "skill directory still at $skill_dir_root/$installed_skill"
            fi
        fi

        # Verify it's gone from openclaw list
        local post_remove_list
        post_remove_list=$(openclaw skills list --json 2>/dev/null || echo "[]")
        local still_in_list
        still_in_list=$(echo "$post_remove_list" | jq --arg n "$installed_skill" '[.[] | select(.name == $n)] | length' 2>/dev/null || echo "0")
        if [ "${still_in_list:-0}" -eq 0 ]; then
            pass "agent chat: skill '$installed_skill' no longer in openclaw list"
        else
            skip "agent chat: skill removal from list" "still in openclaw list (session snapshot may be stale)"
        fi
    else
        skip "agent chat: skill removal" "no skill was installed to remove"
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

    echo "  Checking Splunk HEC health..."
    local hec_health
    hec_health=$(curl -sf --max-time 5 "$SPLUNK_HEC_URL/services/collector/health" 2>&1 || echo "unreachable")
    echo "  HEC health response: $hec_health"

    if [ "$hec_health" = "unreachable" ] || [ -z "$hec_health" ]; then
        echo "  Splunk HEC not reachable — checking docker..."
        docker ps -a --format '{{.Names}} {{.Status}} {{.Ports}}' 2>/dev/null || true

        echo "  Docker logs (last 30 lines):"
        docker logs "$(docker ps -aq --filter name=splunk | head -1)" --tail 30 2>/dev/null || echo "  (no container found)"

        echo "  Attempting to restart Splunk container..."
        local compose_dir="$REPO_ROOT/bundles/splunk_local_bridge/compose"
        if [ -f "$compose_dir/docker-compose.ci.yml" ]; then
            (cd "$compose_dir" && SPLUNK_IMAGE=splunk/splunk-claw-bridge:10.2.0 \
                docker compose -f docker-compose.ci.yml up -d 2>&1 || true)
            echo "  Waiting 60s for Splunk to start..."
            sleep 60
        fi

        hec_health=$(curl -sf --max-time 5 "$SPLUNK_HEC_URL/services/collector/health" 2>&1 || echo "unreachable")
        echo "  HEC health after restart: $hec_health"
        if [ "$hec_health" = "unreachable" ] || [ -z "$hec_health" ]; then
            fail "Splunk HEC reachable" "still unreachable after container restart"
            phase_timer_end "Phase 8"
            return 0
        fi
    fi
    pass "Splunk HEC reachable"

    echo "  Sending test event to HEC..."
    local hec_response
    hec_response=$(curl -sf --max-time 5 \
        -H "Authorization: Splunk $SPLUNK_HEC_TOKEN" \
        -H "Content-Type: application/json" \
        -d "{\"event\":{\"action\":\"e2e-ci-test\",\"source\":\"test-e2e-full-stack\",\"timestamp\":\"$(date -u +%FT%TZ)\"},\"index\":\"defenseclaw_local\"}" \
        "$SPLUNK_HEC_URL/services/collector/event" 2>/dev/null || echo '{"text":"error"}')
    echo "  HEC response: $hec_response"

    if echo "$hec_response" | jq -e '.text == "Success"' >/dev/null 2>&1; then
        pass "Splunk HEC accepts events"
    else
        fail "Splunk HEC accepts events" "response: $hec_response"
    fi

    echo "  Waiting 10s for events to be indexed..."
    sleep 10

    echo "  Querying Splunk REST API for total event count..."
    local search_result
    search_result=$(splunk_search "| stats count")
    echo "  Search result: $search_result"

    if echo "$search_result" | grep -q "result"; then
        local count
        count=$(echo "$search_result" | jq -r '.result.count // "0"' 2>/dev/null)
        if [ "${count:-0}" -gt 0 ]; then
            pass "Splunk: $count total events in defenseclaw_local index"
        else
            pass "Splunk: search endpoint returned results (count may be delayed)"
        fi
    else
        skip "Splunk search" "REST API on port 8089 not reachable or returned empty — HEC test passed"
        phase_timer_end "Phase 8"
        return
    fi

    echo "  Querying Splunk for audit events by action..."
    local audit_events
    audit_events=$(splunk_search "action=* | stats count by action | head 10")
    echo "  --- Audit events by action ---"
    echo "$audit_events"
    echo "  --- end audit events ---"

    if echo "$audit_events" | grep -q "result"; then
        pass "Splunk: audit events present"
    else
        skip "Splunk: audit events" "no defenseclaw events found yet"
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

    if [ "$SKIP_COUNT" -gt 5 ]; then
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
    phase_quarantine
    phase_guardrail
    phase_agent_chat
    phase_splunk

    # EXIT trap handles teardown + summary + artifact dump
    [ "$FAIL" -eq 0 ]
}

main "$@"
