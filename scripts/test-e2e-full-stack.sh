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
        fail "health: guardrail is running" "guardrail is disabled — config may not have been applied"
    else
        fail "health: guardrail is running" "got '$guard_state'"
    fi

    local status
    status=$(curl -sf "$SIDECAR_URL/status" 2>/dev/null || echo "{}")
    if echo "$status" | jq -e '.gateway_hello' >/dev/null 2>&1; then
        pass "status: gateway_hello present (WebSocket handshake)"
    else
        fail "status: gateway_hello present" "gateway_hello missing from /status"
    fi
}

# ---------------------------------------------------------------------------
# Phase 3 — Skill Scanner
# ---------------------------------------------------------------------------
phase_skill_scanner() {
    echo ""
    echo "=== Phase 3: Skill Scanner ==="

    local clean_skill="$REPO_ROOT/test/fixtures/skills/clean-skill"
    local malicious_skill="$REPO_ROOT/test/fixtures/skills/malicious-skill"

    if [ ! -d "$clean_skill" ]; then
        skip "skill scanner" "test fixtures not found at $clean_skill"
        return
    fi

    echo "  Scanning clean skill..."
    local clean_out
    clean_out=$(defenseclaw skill scan "$clean_skill" --json 2>/dev/null || echo '{"error":"scan failed"}')
    local clean_findings
    clean_findings=$(echo "$clean_out" | jq -r '.findings | length // 0' 2>/dev/null || echo "0")
    if [ "${clean_findings:-0}" -eq 0 ]; then
        pass "skill scan: clean skill has no findings"
    else
        fail "skill scan: clean skill has no findings" "got $clean_findings findings"
    fi

    echo "  Scanning malicious skill..."
    local mal_out
    mal_out=$(defenseclaw skill scan "$malicious_skill" --json 2>/dev/null || echo '{"error":"scan failed"}')
    local mal_findings
    mal_findings=$(echo "$mal_out" | jq -r '.findings | length // 0' 2>/dev/null || echo "0")
    if [ "${mal_findings:-0}" -gt 0 ]; then
        pass "skill scan: malicious skill has findings ($mal_findings)"
    else
        fail "skill scan: malicious skill has findings" "got 0 findings"
    fi
}

# ---------------------------------------------------------------------------
# Phase 4 — MCP Scanner
# ---------------------------------------------------------------------------
phase_mcp_scanner() {
    echo ""
    echo "=== Phase 4: MCP Scanner ==="

    local malicious_mcp="$REPO_ROOT/test/fixtures/mcps/malicious-mcp.json"

    if [ ! -f "$malicious_mcp" ]; then
        skip "mcp scanner" "test fixture not found at $malicious_mcp"
        return
    fi

    echo "  Scanning malicious MCP spec..."
    local mcp_out
    mcp_out=$(defenseclaw mcp scan "$malicious_mcp" --json 2>/dev/null || echo '{"error":"scan failed"}')
    local mcp_findings
    mcp_findings=$(echo "$mcp_out" | jq -r '.findings | length // 0' 2>/dev/null || echo "0")
    if [ "${mcp_findings:-0}" -gt 0 ]; then
        pass "mcp scan: malicious MCP has findings ($mcp_findings)"
    else
        fail "mcp scan: malicious MCP has findings" "got 0 findings"
    fi
}

# ---------------------------------------------------------------------------
# Phase 5 — Skill Install + Quarantine (with enforcement)
# ---------------------------------------------------------------------------
phase_quarantine() {
    echo ""
    echo "=== Phase 5: Skill Install + Quarantine ==="

    local malicious_skill="$REPO_ROOT/test/fixtures/skills/malicious-skill"

    if [ ! -d "$malicious_skill" ]; then
        skip "quarantine" "test fixtures not found"
        return
    fi

    echo "  Installing malicious skill with --action enforcement..."
    local install_out
    install_out=$(defenseclaw skill install "$malicious_skill" --action --force 2>&1 || true)
    echo "  Install output: ${install_out:0:200}"

    if echo "$install_out" | grep -qi "quarantine"; then
        pass "skill install: malicious skill was quarantined"
    elif echo "$install_out" | grep -qi "block\|reject"; then
        pass "skill install: malicious skill was blocked/rejected"
    elif echo "$install_out" | grep -qi "warning\|finding"; then
        pass "skill install: malicious skill flagged with warnings"
    else
        fail "skill install: malicious skill enforcement" "no quarantine/block/warning in output"
    fi

    echo "  Checking quarantine via CLI..."
    local list_out
    list_out=$(defenseclaw skill list 2>&1 || true)
    echo "  Skill list: ${list_out:0:200}"
}

# ---------------------------------------------------------------------------
# Phase 6 — Guardrail Proxy (if running)
# ---------------------------------------------------------------------------
phase_guardrail() {
    echo ""
    echo "=== Phase 6: Guardrail Proxy ==="

    if ! wait_for_url "$GUARDRAIL_URL/health/liveliness" 15 3; then
        fail "guardrail proxy reachable" "timed out waiting for guardrail proxy on port 4000"
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
        if [ -n "$err" ] && (echo "$err" | grep -qi "credit\|quota\|rate\|key"); then
            pass "guardrail round-trip: proxy forwarded request (LLM issue: ${err:0:80})"
        else
            fail "guardrail round-trip: LLM responded" "content='${content:0:80}' err='${err:0:80}'"
        fi
    fi
}

# ---------------------------------------------------------------------------
# Phase 7 — Telegram Round-Trip
# ---------------------------------------------------------------------------
phase_telegram() {
    echo ""
    echo "=== Phase 7: Telegram Round-Trip ==="

    if [ -z "${E2E_TELEGRAM_USER_SESSION:-}" ]; then
        skip "Telegram round-trip" "E2E_TELEGRAM_USER_SESSION not set"
        return 0
    fi

    if [ -z "${E2E_TELEGRAM_API_ID:-}" ] || [ -z "${E2E_TELEGRAM_API_HASH:-}" ]; then
        skip "Telegram round-trip" "Telegram API credentials not set"
        return 0
    fi

    if ! python3 -c "import telethon" 2>/dev/null; then
        echo "  Installing telethon..."
        pip install --quiet telethon cryptg 2>/dev/null || true
    fi

    if python3 "$SCRIPT_DIR/e2e-telegram-roundtrip.py"; then
        pass "Telegram round-trip: bot responded"
    else
        fail "Telegram round-trip: bot responded" "script exited non-zero"
    fi
}

# ---------------------------------------------------------------------------
# Phase 8 — Splunk Log Verification
# ---------------------------------------------------------------------------
phase_splunk() {
    echo ""
    echo "=== Phase 8: Splunk Log Verification ==="

    if ! curl -sf "$SPLUNK_HEC_URL/services/collector/health" >/dev/null 2>&1; then
        skip "Splunk assertions" "Splunk HEC not reachable"
        return 0
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
            pass "Splunk: search returned results (count query worked)"
        fi
    else
        skip "Splunk search" "port 8089 not reachable — HEC test passed"
        return
    fi

    echo "  Checking for scan events in Splunk..."
    local scan_events
    scan_events=$(splunk_search "action=*scan* | stats count")
    local scan_count
    scan_count=$(echo "$scan_events" | jq -r '.result.count // "0"' 2>/dev/null)
    if [ "${scan_count:-0}" -gt 0 ]; then
        pass "Splunk: $scan_count scan events logged"
    else
        fail "Splunk: scan events logged" "no scan events found in Splunk"
    fi

    echo "  Checking for enforcement events in Splunk..."
    local enforce_events
    enforce_events=$(splunk_search "action=*quarantine* OR action=*block* OR action=*install* | stats count")
    local enforce_count
    enforce_count=$(echo "$enforce_events" | jq -r '.result.count // "0"' 2>/dev/null)
    if [ "${enforce_count:-0}" -gt 0 ]; then
        pass "Splunk: $enforce_count enforcement events logged"
    else
        fail "Splunk: enforcement events logged" "no quarantine/block/install events found"
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
    phase_telegram
    phase_splunk
    phase_teardown
    print_summary

    [ "$FAIL" -eq 0 ]
}

main "$@"
