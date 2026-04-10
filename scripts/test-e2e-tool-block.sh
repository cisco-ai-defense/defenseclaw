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

# test-e2e-tool-block.sh — E2E test for tool-level block/allow lists
#
# Mirrors the exact flow the OpenClaw plugin uses for every tool call:
#   1. Ask the gateway: POST /api/v1/inspect/tool
#   2. If action=allow  → execute the tool for real
#   3. If action=block  → refuse execution, print why
#
# Test flow:
#   1. Build + init
#   2. Start the gateway sidecar
#   3. run_tool read_file  → allowed, file content printed
#   4. Block read_file     → defenseclaw tool block
#   5. run_tool read_file  → BLOCKED, execution skipped
#   6. defenseclaw tool list --blocked
#   7. Unblock read_file   → defenseclaw tool unblock
#   8. run_tool read_file  → allowed again, file content printed
#
# Requirements: curl, jq

set -euo pipefail

GATEWAY="./defenseclaw-gateway"
DC="defenseclaw"        # Python CLI (must be on PATH after 'make install' or 'make dev-install')
API_BASE="http://127.0.0.1:18970"
INSPECT_URL="${API_BASE}/api/v1/inspect/tool"
SIDECAR_PID=""
TEST_FILE="/tmp/defenseclaw-e2e-test.txt"
TOOL_NAME="read_file"
ARGS=""   # set after TEST_FILE is created

# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

pass()  { echo "  ✓  $*"; }
fail()  { echo "  ✗  $*" >&2; exit 1; }
step()  { echo; echo "=== $* ==="; }
info()  { echo "  →  $*"; }

wait_healthy() {
    local retries=20
    while [ $retries -gt 0 ]; do
        if curl -sf "${API_BASE}/health" >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.5
        retries=$((retries - 1))
    done
    fail "gateway did not become healthy after 10 s"
}

# run_tool <tool_name> <json_args>
#
# Mirrors the OpenClaw plugin flow:
#   1. Inspect the tool via the gateway
#   2. If allowed  → execute the underlying action for real
#   3. If blocked  → print the reason and return non-zero
#
# Returns 0 if the tool executed, 1 if it was blocked.
run_tool() {
    local tool="$1"
    local args="${2}"
    [ -z "${args}" ] && args="{}"

    info "[plugin] inspect: tool=${tool}"
    local resp
    resp=$(curl -sf -X POST "${INSPECT_URL}" \
        -H "Content-Type: application/json" \
        -H "X-DefenseClaw-Client: e2e-test" \
        -d "{\"tool\":\"${tool}\",\"args\":${args}}")

    local action severity
    action=$(echo "${resp}"   | jq -r '.action   // empty' 2>/dev/null || echo "")
    severity=$(echo "${resp}" | jq -r '.severity // empty' 2>/dev/null || echo "")
    info "[gateway] verdict: action=${action}  severity=${severity}"

    if [ "${action}" = "block" ]; then
        local reason
        reason=$(echo "${resp}" | jq -r '.reason')
        echo "  ✗  [plugin] BLOCKED — execution refused"
        echo "     reason: ${reason}"
        return 1
    fi

    info "[plugin] allowed — executing tool=${tool}"

    # Actually execute the tool's underlying action.
    # This is exactly what the plugin does after a clean inspect verdict.
    case "${tool}" in
        read_file)
            local fpath
            fpath=$(echo "${args}" | jq -r '.path')
            echo "  ── file contents of ${fpath} ──"
            cat "${fpath}"
            echo "  ────────────────────────────"
            ;;
        write_file)
            local fpath content
            fpath=$(echo "${args}"    | jq -r '.path')
            content=$(echo "${args}"  | jq -r '.content')
            echo "${content}" > "${fpath}"
            info "wrote ${#content} bytes to ${fpath}"
            ;;
        bash_exec|shell_exec)
            local cmd
            cmd=$(echo "${args}" | jq -r '.command // .cmd')
            info "running: ${cmd}"
            bash -c "${cmd}"
            ;;
        *)
            info "(no execution handler for tool=${tool} — inspect-only demo)"
            ;;
    esac

    return 0
}

cleanup() {
    rm -f "${TEST_FILE}"
    if [ -n "${SIDECAR_PID}" ]; then
        kill "${SIDECAR_PID}" 2>/dev/null || true
        wait "${SIDECAR_PID}" 2>/dev/null || true
    fi
    # Kill any other defenseclaw-gateway processes that may linger on the same port.
    pkill -f defenseclaw-gateway 2>/dev/null || true
}
trap cleanup EXIT

# --------------------------------------------------------------------------
# Prereq checks
# --------------------------------------------------------------------------

step "Prereq checks"
[ -f "${GATEWAY}" ]                     || fail "Gateway binary not found — run 'make build' first."
command -v curl >/dev/null 2>&1         || fail "curl is required"
command -v jq   >/dev/null 2>&1         || fail "jq is required"
command -v "${DC}" >/dev/null 2>&1      || fail "'${DC}' CLI not found — run 'make install' or 'make dev-install' first."
pass "all prereqs met"

# --------------------------------------------------------------------------
# Step 1 — Prepare test file + clean init
# --------------------------------------------------------------------------

step "Step 1 — Prepare test environment"
echo "secret_report: all systems nominal" > "${TEST_FILE}"
info "created test file: ${TEST_FILE}"
# Build args JSON safely — avoids shell quoting issues with embedded paths.
ARGS=$(jq -cn --arg path "${TEST_FILE}" '{"path": $path}')
rm -rf ~/.defenseclaw
${DC} init
pass "defenseclaw initialized"

# --------------------------------------------------------------------------
# Step 2 — Start gateway sidecar
# --------------------------------------------------------------------------

step "Step 2 — Start gateway sidecar"
"${GATEWAY}" > /tmp/defenseclaw-sidecar.log 2>&1 &
SIDECAR_PID=$!
info "sidecar PID=${SIDECAR_PID}"
wait_healthy
pass "gateway healthy at ${API_BASE}"

# --------------------------------------------------------------------------
# Step 3 — Call the tool (no block in place — should work)
# --------------------------------------------------------------------------

step "Step 3 — Call '${TOOL_NAME}' with no block in place"
ARGS="{\"path\":\"${TEST_FILE}\"}"
if run_tool "${TOOL_NAME}" "${ARGS}"; then
    pass "tool executed successfully"
else
    fail "tool was unexpectedly blocked"
fi

# --------------------------------------------------------------------------
# Step 4 — Block the tool
# --------------------------------------------------------------------------

step "Step 4 — Block tool '${TOOL_NAME}'"
${DC} tool block "${TOOL_NAME}" --reason "e2e test: read_file blocked for this environment"
pass "block command succeeded"

# --------------------------------------------------------------------------
# Step 5 — Try to call the same tool — should be refused
# --------------------------------------------------------------------------

step "Step 5 — Call '${TOOL_NAME}' after block — expect refusal"
if run_tool "${TOOL_NAME}" "${ARGS}"; then
    fail "tool executed but should have been blocked"
else
    pass "tool was correctly blocked — execution did not happen"
fi

# --------------------------------------------------------------------------
# Step 6 — Show the block list
# --------------------------------------------------------------------------

step "Step 6 — Block list"
${DC} tool list --blocked
if ${DC} tool list --blocked | grep -q "${TOOL_NAME}"; then
    pass "'${TOOL_NAME}' appears in blocked list"
else
    fail "'${TOOL_NAME}' not found in blocked list"
fi

# --------------------------------------------------------------------------
# Step 7 — Unblock the tool
# --------------------------------------------------------------------------

step "Step 7 — Unblock tool '${TOOL_NAME}'"
${DC} tool unblock "${TOOL_NAME}"
pass "unblock command succeeded"

# --------------------------------------------------------------------------
# Step 8 — Call the tool again — should work
# --------------------------------------------------------------------------

step "Step 8 — Call '${TOOL_NAME}' after unblock — expect success"
if run_tool "${TOOL_NAME}" "${ARGS}"; then
    pass "tool executed successfully after unblock"
else
    fail "tool was still blocked after unblock"
fi

# --------------------------------------------------------------------------
# Done
# --------------------------------------------------------------------------

echo
echo "=== All tool-block E2E tests passed ==="
