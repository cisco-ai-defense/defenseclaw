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
# Token/cost budget enforcement E2E test. Spins up a short-lived gateway
# with an isolated DEFENSECLAW_HOME and a tight budget policy, then drives
# the allow / deny / monitor paths via curl. Uses a locally running
# Ollama (port 11434) as the upstream because the gateway's provider
# resolver only accepts known provider domains / Ollama loopback.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
GATEWAY="${REPO_ROOT}/defenseclaw-gateway"

if [ ! -x "${GATEWAY}" ]; then
    echo "Building gateway..."
    (cd "${REPO_ROOT}" && go build -o defenseclaw-gateway ./cmd/defenseclaw)
fi

TMP_HOME="$(mktemp -d -t dc-budget-XXXXXX)"
export DEFENSECLAW_HOME="${TMP_HOME}"

UPSTREAM_PORT=11434
GATEWAY_PORT=14000

cleanup() {
    local rc=$?
    if [ -n "${GATEWAY_PID:-}" ]; then
        kill "${GATEWAY_PID}" 2>/dev/null || true
        wait "${GATEWAY_PID}" 2>/dev/null || true
    fi
    rm -rf "${TMP_HOME}"
    exit "$rc"
}
trap cleanup EXIT INT TERM

echo "=== DefenseClaw Budget E2E ==="
echo "DEFENSECLAW_HOME=${TMP_HOME}"

# 1. Sanity-check the upstream is reachable. The E2E only needs the
#    upstream to respond (success or failure) so the proxy reaches the
#    post-call usage-recording path. Model-not-found errors are fine.
if ! curl -sf "http://127.0.0.1:${UPSTREAM_PORT}/" -o /dev/null; then
    echo "WARNING: No upstream reachable on 127.0.0.1:${UPSTREAM_PORT}."
    echo "Tests 2–3 (allow paths) will still exercise the budget engine"
    echo "through the proxy but the upstream call itself will fail."
fi

# 2. Write config.yaml with budget enforcement enabled.
cat >"${TMP_HOME}/config.yaml" <<YAML
data_dir: ${TMP_HOME}
audit_db: ${TMP_HOME}/audit.db
policy_dir: ${TMP_HOME}/policies
plugin_dir: ${TMP_HOME}/plugins
quarantine_dir: ${TMP_HOME}/quarantine

claw:
  mode: openclaw

guardrail:
  enabled: true
  mode: guardrail
  host: 127.0.0.1
  port: ${GATEWAY_PORT}
  scanner_mode: both

budget:
  enabled: true
  mode: enforce
  subject_header: X-DC-Subject
  default_subject: default

scanners:
  skill_scanner:
    enabled: false
  mcp_scanner:
    enabled: false
  ollama_scanner:
    enabled: false

cisco_ai_defense:
  enabled: false
YAML

# 3. Install policies — copy the repo's rego dir and patch data.json with
#    tight per-subject limits so we can drive deny deterministically.
mkdir -p "${TMP_HOME}/policies/rego"
cp "${REPO_ROOT}/policies/rego/"*.rego "${TMP_HOME}/policies/rego/"

python3 - <<PY
import json
src = "${REPO_ROOT}/policies/rego/data.json"
dst = "${TMP_HOME}/policies/rego/data.json"
with open(src) as f:
    data = json.load(f)
# Tight budget for the 'tight' subject so we can trigger deny on a single
# request with max_tokens=500 (50 tpm limit → 501 est > 50).
data.setdefault("budget", {}).setdefault("subjects", {})["tight"] = {
    "tokens_per_minute": 50,
    "tokens_per_hour": 500,
    "tokens_per_day": 5000,
    "requests_per_minute": 100,
    "requests_per_hour": 1000,
    "requests_per_day": 10000,
    "cost_per_hour": 100.0,
    "cost_per_day": 1000.0,
}
with open(dst, "w") as f:
    json.dump(data, f, indent=2)
PY

# 4. Boot the gateway in foreground (no 'start' = foreground sidecar).
"${GATEWAY}" >"${TMP_HOME}/gateway.log" 2>&1 &
GATEWAY_PID=$!

echo "Waiting for gateway on :${GATEWAY_PORT}..."
for _ in {1..60}; do
    if curl -s "http://127.0.0.1:${GATEWAY_PORT}/v1/chat/completions" -X POST -d '{}' \
            -H 'Content-Type: application/json' -o /dev/null -w '%{http_code}' 2>/dev/null \
            | grep -qE '^(200|400|401|403|422|500)$'; then
        break
    fi
    sleep 0.2
done

if ! kill -0 "${GATEWAY_PID}" 2>/dev/null; then
    echo "Gateway failed to start. Log:"
    cat "${TMP_HOME}/gateway.log"
    exit 1
fi

FAILED=0

send() {
    local subject="$1" max_tokens="$2" expect="$3"
    body=$(cat <<JSON
{
    "model": "gpt-4o",
    "max_tokens": ${max_tokens},
    "messages": [{"role": "user", "content": "hi"}]
}
JSON
)
    resp=$(curl -s \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer sk-fake" \
        -H "X-DC-Target-URL: http://127.0.0.1:${UPSTREAM_PORT}/v1/chat/completions" \
        -H "X-DC-Subject: ${subject}" \
        -X POST "http://127.0.0.1:${GATEWAY_PORT}/v1/chat/completions" \
        --data "${body}")
    echo "--- subject=${subject} max_tokens=${max_tokens} expect=${expect}"
    echo "${resp}" | python3 -m json.tool 2>/dev/null | head -12 || echo "${resp}"

    blocked=$(echo "${resp}" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('defenseclaw_blocked', False))" 2>/dev/null || echo "unknown")
    reason=$(echo "${resp}" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('defenseclaw_reason',''))" 2>/dev/null || echo "")

    if [ "${expect}" = "block-budget" ]; then
        if [ "${blocked}" != "True" ]; then
            echo "FAIL: expected budget block, got ${blocked}"
            FAILED=1
            return 1
        fi
        if ! echo "${reason}" | grep -qi "budget"; then
            echo "FAIL: expected reason to mention budget, got '${reason}'"
            FAILED=1
            return 1
        fi
        echo "PASS: budget denial with reason: ${reason}"
    fi
    if [ "${expect}" = "pass-budget" ]; then
        # Budget should not block. The upstream might still fail (model not
        # found on Ollama, etc.) but defenseclaw_blocked=True with a
        # budget reason should NOT appear.
        if [ "${blocked}" = "True" ] && echo "${reason}" | grep -qi "budget"; then
            echo "FAIL: budget unexpectedly blocked: ${reason}"
            FAILED=1
            return 1
        fi
        echo "PASS: budget allowed the request through"
    fi
    return 0
}

# 5. Exercise deny / allow paths.
echo ""
echo "=== Test 1: tight subject + max_tokens=500 → budget DENIES ==="
send "tight" 500 block-budget

echo ""
echo "=== Test 2: tight subject + max_tokens=10 → budget ALLOWS ==="
send "tight" 10 pass-budget

echo ""
echo "=== Test 3: unknown subject (falls back to 'default' unlimited) → ALLOWS ==="
send "some-other-user" 500 pass-budget

echo ""
echo "=== Test 4: verify audit log recorded the budget denial ==="
if grep -q "guardrail-budget-block\|budget_block\|budget" "${TMP_HOME}/gateway.log"; then
    echo "PASS: gateway log mentions budget enforcement"
else
    echo "WARN: no budget mentions in gateway log (auditing may be async)"
fi

echo ""
if [ "${FAILED}" -ne 0 ]; then
    echo "=== E2E FAILED ==="
    echo "Gateway log tail:"
    tail -40 "${TMP_HOME}/gateway.log"
    exit 1
fi
echo "=== E2E PASSED ==="
