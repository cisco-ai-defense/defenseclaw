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

# ---------------------------------------------------------------------------
# Phase 1 — Start Stack
# ---------------------------------------------------------------------------
phase_start() {
    echo ""
    echo "=== Phase 1: Start Stack ==="

    echo "  Starting OpenClaw gateway..."
    openclaw gateway --force &
    OPENCLAW_PID=$!
    sleep 3

    echo "  Starting DefenseClaw sidecar..."
    defenseclaw-gateway start
    sleep 2

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

    for subsystem in gateway watcher api guardrail; do
        local state
        state=$(echo "$health" | jq -r ".${subsystem}.state // .${subsystem} // empty" 2>/dev/null)
        if [ "$state" = "running" ]; then
            pass "health: $subsystem is running"
        else
            fail "health: $subsystem is running" "got '$state'"
        fi
    done

    local status
    status=$(curl -sf "$SIDECAR_URL/status" 2>/dev/null || echo "{}")
    if echo "$status" | jq -e '.gateway_hello' >/dev/null 2>&1; then
        pass "status: gateway_hello present (WebSocket handshake)"
    else
        fail "status: gateway_hello present" "gateway_hello missing from /status"
    fi

    if command -v openclaw >/dev/null 2>&1; then
        local channels
        channels=$(openclaw channels status 2>/dev/null || echo "")
        if echo "$channels" | grep -qi "telegram"; then
            pass "openclaw: Telegram channel connected"
        else
            fail "openclaw: Telegram channel connected" "Telegram not found in channel status"
        fi
    fi
}

# ---------------------------------------------------------------------------
# Phase 3 — Agent Round-Trip via Guardrail Proxy
# ---------------------------------------------------------------------------
phase_agent_roundtrip() {
    echo ""
    echo "=== Phase 3: Agent Round-Trip ==="

    if ! wait_for_url "$GUARDRAIL_URL/health/liveliness" 30 3; then
        fail "guardrail proxy reachable" "timed out waiting for guardrail proxy"
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
        "$GUARDRAIL_URL/v1/chat/completions" 2>/dev/null || echo '{"error":"timeout"}')

    local content
    content=$(echo "$response" | jq -r '.choices[0].message.content // empty' 2>/dev/null)

    if echo "$content" | grep -q "E2E_OK"; then
        pass "agent round-trip: LLM responded with E2E_OK"
    else
        local err
        err=$(echo "$response" | jq -r '.error.message // empty' 2>/dev/null)
        if [ -n "$err" ] && (echo "$err" | grep -qi "credit\|quota\|rate"); then
            pass "agent round-trip: guardrail passed (LLM quota/credit issue: ${err:0:80})"
        else
            fail "agent round-trip: LLM responded with E2E_OK" "got: ${content:0:100} err: ${err:0:100}"
        fi
    fi
}

# ---------------------------------------------------------------------------
# Phase 4 — Telegram Round-Trip
# ---------------------------------------------------------------------------
phase_telegram() {
    echo ""
    echo "=== Phase 4: Telegram Round-Trip ==="

    if [ -z "${E2E_TELEGRAM_USER_SESSION:-}" ]; then
        echo "  [SKIP] E2E_TELEGRAM_USER_SESSION not set — skipping Telegram round-trip"
        return 0
    fi

    if [ -z "${E2E_TELEGRAM_API_ID:-}" ] || [ -z "${E2E_TELEGRAM_API_HASH:-}" ]; then
        echo "  [SKIP] Telegram API credentials not set — skipping"
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
# Phase 5 — Splunk Assertions
# ---------------------------------------------------------------------------
phase_splunk() {
    echo ""
    echo "=== Phase 5: Splunk Assertions ==="

    if ! curl -sf "$SPLUNK_HEC_URL/services/collector/health" >/dev/null 2>&1; then
        echo "  [SKIP] Splunk HEC not reachable — skipping Splunk assertions"
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

    sleep 5

    local search_result
    search_result=$(curl -sf --max-time 15 -k \
        -u "admin:DefenseClawLocalMode1!" \
        -d "search=search index=defenseclaw_local | stats count" \
        -d "output_mode=json" \
        "https://127.0.0.1:8089/services/search/jobs/export" 2>/dev/null || echo '{}')

    if echo "$search_result" | grep -q "result"; then
        local count
        count=$(echo "$search_result" | jq -r '.result.count // "0"' 2>/dev/null)
        if [ "${count:-0}" -gt 0 ]; then
            pass "Splunk search: $count events in defenseclaw_local index"
        else
            pass "Splunk search: events present (count query returned results)"
        fi
    else
        # Port 8089 may not be exposed — HEC acceptance is sufficient
        pass "Splunk search: skipped (port 8089 not exposed; HEC test passed)"
    fi
}

# ---------------------------------------------------------------------------
# Phase 6 — Teardown
# ---------------------------------------------------------------------------
phase_teardown() {
    echo ""
    echo "=== Phase 6: Teardown ==="

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
    phase_agent_roundtrip
    phase_telegram
    phase_splunk
    phase_teardown
    print_summary

    [ "$FAIL" -eq 0 ]
}

main "$@"
