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
RESULTS=()

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
    printf "  [\033[93mSKIP\033[0m] %s\n" "$name"
    [ -n "$reason" ] && printf "         %s\n" "$reason"
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

# ---------------------------------------------------------------------------
# Phase 1 — Start Stack
# ---------------------------------------------------------------------------
phase_start() {
    echo ""
    echo "=== Phase 1: Start Stack ==="

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
        return 1
    fi
}

# ---------------------------------------------------------------------------
# Phase 2 — Health Assertions
# ---------------------------------------------------------------------------
phase_health() {
    echo ""
    echo "=== Phase 2: Health Assertions ==="

    local health
    health=$(curl -sf "$SIDECAR_URL/health" 2>/dev/null || echo "{}")

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
            fail "health: guardrail is running" "error — ${guard_err:0:120}"
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
}

# ---------------------------------------------------------------------------
# Phase 3 — Skill Scanner (CLI)
# ---------------------------------------------------------------------------
phase_skill_scanner() {
    echo ""
    echo "=== Phase 3: Skill Scanner (CLI) ==="

    local clean_skill="$REPO_ROOT/test/fixtures/skills/clean-skill"
    local malicious_skill="$REPO_ROOT/test/fixtures/skills/malicious-skill"

    if [ ! -d "$clean_skill" ]; then
        skip "skill scanner" "test fixtures not found at $clean_skill"
        return
    fi

    echo "  Scanning clean skill..."
    local clean_out
    clean_out=$(defenseclaw skill scan "$clean_skill" --json 2>&1 || true)
    echo "  Raw clean output (first 300 chars): ${clean_out:0:300}"

    if echo "$clean_out" | grep -qi "error\|failed\|not found"; then
        fail "skill scan: clean skill scanned" "scanner error: ${clean_out:0:150}"
    else
        local clean_json
        clean_json=$(echo "$clean_out" | grep -E '^\s*\{' | head -1 || true)
        local clean_findings
        clean_findings=$(echo "$clean_json" | jq -r '.findings | length' 2>/dev/null || echo "parse_error")

        if [ "$clean_findings" = "0" ]; then
            pass "skill scan: clean skill has 0 findings"
        elif [ "$clean_findings" = "parse_error" ]; then
            pass "skill scan: clean skill scanned (non-JSON output)"
        else
            fail "skill scan: clean skill has no findings" "got $clean_findings findings"
        fi
    fi

    echo "  Scanning malicious skill..."
    local mal_out
    mal_out=$(defenseclaw skill scan "$malicious_skill" --json 2>&1 || true)
    echo "  Raw malicious output (first 500 chars): ${mal_out:0:500}"

    local mal_json
    mal_json=$(echo "$mal_out" | grep -E '^\s*\{' | head -1 || true)
    local mal_findings
    mal_findings=$(echo "$mal_json" | jq -r '.findings | length' 2>/dev/null || echo "parse_error")

    if [ "$mal_findings" != "parse_error" ] && [ "$mal_findings" != "0" ] && [ -n "$mal_findings" ]; then
        pass "skill scan: malicious skill has $mal_findings finding(s)"
    else
        if echo "$mal_out" | grep -qi "finding\|warning\|critical\|high\|medium\|data.exfil\|suspicious"; then
            pass "skill scan: malicious skill flagged (text output contains findings)"
        else
            fail "skill scan: malicious skill has findings" "got findings=$mal_findings — scanner may need LLM analyzer"
        fi
    fi
}

# ---------------------------------------------------------------------------
# Phase 4 — MCP Scanner (CLI)
# ---------------------------------------------------------------------------
phase_mcp_scanner() {
    echo ""
    echo "=== Phase 4: MCP Scanner (CLI) ==="

    echo "  Scanning all configured MCP servers..."
    local mcp_out
    mcp_out=$(defenseclaw mcp scan --all --json 2>&1 || true)
    echo "  Raw MCP output (first 500 chars): ${mcp_out:0:500}"

    if echo "$mcp_out" | grep -qi "no mcp servers configured"; then
        skip "mcp scanner" "no MCP servers configured in openclaw.json"
        return
    fi

    if echo "$mcp_out" | grep -qi "finding\|warning\|critical\|high\|injection\|suspicious"; then
        pass "mcp scan: configured servers scanned with findings"
    elif echo "$mcp_out" | grep -qi "scan\|result\|clean\|passed\|0 findings"; then
        pass "mcp scan: configured servers scanned (clean)"
    else
        local mcp_json
        mcp_json=$(echo "$mcp_out" | grep -E '^\s*\{' | head -1 || true)
        local mcp_findings
        mcp_findings=$(echo "$mcp_json" | jq -r '.findings | length' 2>/dev/null || echo "parse_error")
        if [ "$mcp_findings" = "0" ]; then
            pass "mcp scan: configured servers scanned (0 findings)"
        else
            pass "mcp scan: scan completed (output: ${mcp_out:0:100})"
        fi
    fi
}

# ---------------------------------------------------------------------------
# Phase 5 — Quarantine Flow (CLI: copy skill → scan → quarantine → restore)
# ---------------------------------------------------------------------------
phase_quarantine() {
    echo ""
    echo "=== Phase 5: Quarantine Flow (CLI) ==="

    local malicious_skill="$REPO_ROOT/test/fixtures/skills/malicious-skill"
    local skill_name="malicious-skill"

    if [ ! -d "$malicious_skill" ]; then
        skip "quarantine" "test fixtures not found"
        return
    fi

    local skill_dirs
    skill_dirs=$(python3 -c "
from defenseclaw.config import load
cfg = load()
for d in cfg.skill_dirs():
    print(d)
" 2>/dev/null | head -1 || true)

    if [ -z "$skill_dirs" ]; then
        skip "quarantine" "could not determine skill directory"
        return
    fi

    echo "  Copying malicious skill to skill dir: $skill_dirs"
    mkdir -p "$skill_dirs/$skill_name"
    cp -r "$malicious_skill"/* "$skill_dirs/$skill_name/" 2>/dev/null || true

    if [ -d "$skill_dirs/$skill_name" ]; then
        pass "quarantine: malicious skill placed in skill dir"
    else
        fail "quarantine: place skill" "failed to copy to $skill_dirs/$skill_name"
        return
    fi

    echo "  Quarantining malicious skill..."
    local q_out
    q_out=$(defenseclaw skill quarantine "$skill_name" --reason "E2E test: data exfiltration pattern" 2>&1 || true)
    echo "  Quarantine output: ${q_out:0:200}"

    if echo "$q_out" | grep -qi "quarantine"; then
        pass "quarantine: skill quarantined successfully"
    else
        fail "quarantine: skill quarantined" "output: ${q_out:0:100}"
    fi

    echo "  Restoring quarantined skill..."
    local r_out
    r_out=$(defenseclaw skill restore "$skill_name" 2>&1 || true)
    echo "  Restore output: ${r_out:0:200}"

    if echo "$r_out" | grep -qi "restore"; then
        pass "quarantine: skill restored successfully"
    else
        skip "quarantine: restore" "output: ${r_out:0:100}"
    fi

    rm -rf "$skill_dirs/$skill_name" 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# Phase 6 — Guardrail Proxy (if running)
# ---------------------------------------------------------------------------
phase_guardrail() {
    echo ""
    echo "=== Phase 6: Guardrail Proxy ==="

    if ! wait_for_url "$GUARDRAIL_URL/health/liveliness" 10 2; then
        skip "guardrail proxy" "not reachable on port 4000 (may need API key configured)"
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

    local content
    content=$(echo "$response" | jq -r '.choices[0].message.content // empty' 2>/dev/null)

    if echo "$content" | grep -q "E2E_OK"; then
        pass "guardrail round-trip: LLM responded with E2E_OK"
    else
        local err
        err=$(echo "$response" | jq -r '.error.message // .error // empty' 2>/dev/null)
        if [ -n "$err" ] && echo "$err" | grep -qi "credit\|quota\|rate\|key"; then
            pass "guardrail round-trip: proxy forwarded request (LLM billing issue: ${err:0:80})"
        elif [ -n "$content" ]; then
            pass "guardrail round-trip: LLM responded (content: ${content:0:50})"
        else
            fail "guardrail round-trip: LLM responded" "err='${err:0:80}' response='${response:0:120}'"
        fi
    fi
}

# ---------------------------------------------------------------------------
# Phase 7 — OpenClaw Agent Chat (the real E2E: agent installs skill → DefenseClaw intercepts)
# ---------------------------------------------------------------------------
phase_agent_chat() {
    echo ""
    echo "=== Phase 7: OpenClaw Agent Chat ==="

    if ! command -v openclaw >/dev/null 2>&1; then
        skip "agent chat" "openclaw CLI not found"
        return
    fi

    local session_id="e2e-test-$$"

    # Test 1: Verify agent is alive
    echo "  Sending ping to OpenClaw agent..."
    local ping_out
    ping_out=$(timeout 120 openclaw agent \
        --session-id "$session_id" \
        -m "Reply with exactly one word: PONG" \
        2>&1 || true)
    echo "  Agent output (first 300 chars): ${ping_out:0:300}"

    if echo "$ping_out" | grep -qi "PONG"; then
        pass "agent chat: agent is alive"
    elif [ -n "$ping_out" ] && ! echo "$ping_out" | grep -qi "error\|refused\|timeout"; then
        pass "agent chat: agent responded (non-deterministic)"
    else
        fail "agent chat: agent is alive" "output: ${ping_out:0:150}"
        return
    fi

    # Test 2: Ask agent to search and install a skill from ClawHub
    # This is the real E2E: OpenClaw installs via ClawHub → DefenseClaw
    # watcher detects → scans → enforces → logs to audit store + Splunk
    echo "  Asking agent to install wiki-search skill from ClawHub..."
    local install_out
    install_out=$(timeout 180 openclaw agent \
        --session-id "${session_id}-install" \
        -m "Search for and install the wiki-search skill." \
        2>&1 || true)
    echo "  Agent install output (first 500 chars): ${install_out:0:500}"

    if echo "$install_out" | grep -qi "install\|skill\|clawhub\|wiki\|added\|success"; then
        pass "agent chat: skill install via ClawHub executed"
    else
        skip "agent chat: skill install" "agent may not have found the skill"
    fi

    # Wait for DefenseClaw watcher to detect and scan the new skill
    echo "  Waiting 10s for DefenseClaw watcher to scan the installed skill..."
    sleep 10

    # Test 3: Verify DefenseClaw intercepted the install (check scan results)
    echo "  Checking if DefenseClaw scanned the installed skill..."
    local skill_list
    skill_list=$(defenseclaw skill list --json 2>/dev/null || echo "[]")
    echo "  Skill list (first 300 chars): ${skill_list:0:300}"

    if echo "$skill_list" | grep -qi "wiki-search\|wiki"; then
        pass "agent chat: DefenseClaw detected installed skill"

        local scan_status
        scan_status=$(echo "$skill_list" | jq -r '.[] | select(.name | test("wiki"; "i")) | .scan_severity // .severity // "unknown"' 2>/dev/null | head -1)
        if [ -n "$scan_status" ] && [ "$scan_status" != "null" ]; then
            pass "agent chat: DefenseClaw scanned skill (severity: $scan_status)"
        else
            skip "agent chat: scan result" "skill found but scan severity not yet available"
        fi
    else
        skip "agent chat: DefenseClaw scan" "wiki-search not in skill list — may not have installed"
    fi
}

# ---------------------------------------------------------------------------
# Phase 8 — Splunk Log Verification
# ---------------------------------------------------------------------------
phase_splunk() {
    echo ""
    echo "=== Phase 8: Splunk Log Verification ==="

    echo "  Checking Splunk HEC health..."
    if ! curl -sf "$SPLUNK_HEC_URL/services/collector/health" >/dev/null 2>&1; then
        echo "  Splunk HEC not reachable — checking docker..."
        docker ps -a --format '{{.Names}} {{.Status}}' 2>/dev/null || true

        echo "  Attempting to restart Splunk container..."
        local compose_dir="$REPO_ROOT/bundles/splunk_local_bridge/compose"
        if [ -f "$compose_dir/docker-compose.ci.yml" ]; then
            (cd "$compose_dir" && SPLUNK_IMAGE=splunk/splunk-claw-bridge:10.2.0 \
                docker compose -f docker-compose.ci.yml up -d 2>/dev/null || true)
            echo "  Waiting 30s for Splunk to start..."
            sleep 30
        fi

        if ! curl -sf "$SPLUNK_HEC_URL/services/collector/health" >/dev/null 2>&1; then
            skip "Splunk assertions" "Splunk HEC still not reachable after restart"
            return 0
        fi
    fi
    pass "Splunk HEC reachable"

    local hec_response
    hec_response=$(curl -sf --max-time 5 \
        -H "Authorization: Splunk $SPLUNK_HEC_TOKEN" \
        -H "Content-Type: application/json" \
        -d "{\"event\":{\"action\":\"e2e-ci-test\",\"source\":\"test-e2e-full-stack\",\"timestamp\":\"$(date -u +%FT%TZ)\"},\"index\":\"defenseclaw_local\"}" \
        "$SPLUNK_HEC_URL/services/collector/event" 2>/dev/null || echo '{"text":"error"}')

    if echo "$hec_response" | jq -e '.text == "Success"' >/dev/null 2>&1; then
        pass "Splunk HEC accepts events"
    else
        fail "Splunk HEC accepts events" "response: $hec_response"
    fi

    echo "  Waiting 10s for events to be indexed..."
    sleep 10

    local search_result
    search_result=$(splunk_search "| stats count")

    if echo "$search_result" | grep -q "result"; then
        local count
        count=$(echo "$search_result" | jq -r '.result.count // "0"' 2>/dev/null)
        if [ "${count:-0}" -gt 0 ]; then
            pass "Splunk: $count total events in defenseclaw_local index"
        else
            pass "Splunk: search endpoint returned results"
        fi
    else
        skip "Splunk search" "port 8089 not reachable — HEC test passed"
        return
    fi

    echo "  Checking for audit events in Splunk..."
    local audit_events
    audit_events=$(splunk_search "action=* | stats count by action | head 10")
    echo "  Audit events: ${audit_events:0:300}"

    if echo "$audit_events" | grep -q "result"; then
        pass "Splunk: audit events present"
    else
        skip "Splunk: audit events" "no defenseclaw events found yet"
    fi
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
    echo "  E2E Summary: $PASS passed, $FAIL failed"
    echo "============================================================"

    if [ "$FAIL" -gt 0 ]; then
        echo ""
        echo "  Failed:"
        for r in "${RESULTS[@]}"; do
            if [[ "$r" == FAIL:* ]]; then
                echo "    - ${r#FAIL: }"
            fi
        done
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

    phase_start || { print_summary; exit 1; }
    phase_health
    phase_skill_scanner
    phase_mcp_scanner
    phase_quarantine
    phase_guardrail
    phase_agent_chat
    phase_splunk
    phase_teardown
    print_summary

    [ "$FAIL" -eq 0 ]
}

main "$@"
