#!/usr/bin/env bash
# test-e2e-tool-block-sandbox.sh — E2E test for tool-level block/allow lists (sandbox mode)
#
# Sandbox variant of test-e2e-tool-block.sh. Uses the already-running sidecar
# at 10.200.0.1:18970 instead of starting its own. Does NOT reinitialize
# ~/.defenseclaw or start/stop the gateway.
#
# Mirrors the exact flow the OpenClaw plugin uses for every tool call:
#   1. Ask the gateway: POST /api/v1/inspect/tool
#   2. If action=allow  → execute the tool for real
#   3. If action=block  → refuse execution, print why
#
# Test flow:
#   1. Prereq checks (sidecar healthy, jq, defenseclaw CLI)
#   2. run_tool read_file  → allowed, file content printed
#   3. Block read_file     → defenseclaw tool block
#   4. run_tool read_file  → BLOCKED, execution skipped
#   5. defenseclaw tool list --blocked
#   6. Unblock read_file   → defenseclaw tool unblock
#   7. run_tool read_file  → allowed again, file content printed
#
# Requirements: curl, jq, defenseclaw CLI on PATH
# Run inside the sandbox container: docker exec dclaw-test scripts/test-e2e-tool-block-sandbox.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
if [ -f "${SCRIPT_DIR}/.venv/bin/activate" ]; then
    # shellcheck disable=SC1091
    source "${SCRIPT_DIR}/.venv/bin/activate"
fi

DC="defenseclaw"
API_BASE="http://10.200.0.1:18970"
INSPECT_URL="${API_BASE}/api/v1/inspect/tool"
TEST_FILE="/tmp/defenseclaw-e2e-test.txt"
TOOL_NAME="read_file"
ARGS=""

TOKEN=$(grep OPENCLAW_GATEWAY_TOKEN /root/.defenseclaw/.env 2>/dev/null | cut -d= -f2 || true)
AUTH_HEADER=""
if [ -n "${TOKEN}" ]; then
    AUTH_HEADER="Authorization: Bearer ${TOKEN}"
fi

PASSED=0
FAILED=0

# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

pass()  { echo "  ✓  $*"; PASSED=$((PASSED + 1)); }
fail()  { echo "  ✗  $*" >&2; FAILED=$((FAILED + 1)); }
step()  { echo; echo "=== $* ==="; }
info()  { echo "  →  $*"; }

_curl() {
    local extra_headers=(-H "Content-Type: application/json" -H "X-DefenseClaw-Client: e2e-test")
    if [ -n "${AUTH_HEADER}" ]; then
        extra_headers+=(-H "${AUTH_HEADER}")
    fi
    curl -sS --max-time 15 "${extra_headers[@]}" "$@"
}

# run_tool <tool_name> <json_args>
#
# Mirrors the OpenClaw plugin flow:
#   1. Inspect the tool via the gateway
#   2. If allowed  → execute the underlying action for real
#   3. If blocked  → print the reason and return non-zero
run_tool() {
    local tool="$1"
    local args="${2:-{}}"

    info "[plugin] inspect: tool=${tool}"
    local resp
    resp=$(_curl -X POST "${INSPECT_URL}" \
        -d "{\"tool\":\"${tool}\",\"args\":${args}}" 2>&1) || {
        info "[plugin] inspect request failed: ${resp}"
        return 2
    }

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
    # Unblock the tool in case we failed mid-test
    ${DC} tool unblock "${TOOL_NAME}" 2>/dev/null || true
}
trap cleanup EXIT

# --------------------------------------------------------------------------
# Prereq checks
# --------------------------------------------------------------------------

step "Prereq checks"

command -v curl >/dev/null 2>&1         || { fail "curl is required"; exit 1; }
command -v jq   >/dev/null 2>&1         || { fail "jq is required"; exit 1; }
command -v "${DC}" >/dev/null 2>&1      || { fail "'${DC}' CLI not found — run 'make install' first."; exit 1; }

if _curl "${API_BASE}/health" -o /dev/null 2>/dev/null; then
    pass "sidecar healthy at ${API_BASE}"
else
    fail "sidecar not reachable at ${API_BASE} — is the sandbox running?"
    exit 1
fi

# --------------------------------------------------------------------------
# Step 1 — Prepare test file
# --------------------------------------------------------------------------

step "Step 1 — Prepare test environment"
echo "secret_report: all systems nominal" > "${TEST_FILE}"
info "created test file: ${TEST_FILE}"
ARGS="{\"path\":\"${TEST_FILE}\"}"
pass "test environment ready"

# --------------------------------------------------------------------------
# Step 2 — Call the tool (no block in place — should work)
# --------------------------------------------------------------------------

step "Step 2 — Call '${TOOL_NAME}' with no block in place"
if run_tool "${TOOL_NAME}" "${ARGS}"; then
    pass "tool executed successfully"
else
    fail "tool was unexpectedly blocked"
fi

# --------------------------------------------------------------------------
# Step 3 — Block the tool
# --------------------------------------------------------------------------

step "Step 3 — Block tool '${TOOL_NAME}'"
if ${DC} tool block "${TOOL_NAME}" --reason "e2e test: read_file blocked for this environment"; then
    pass "block command succeeded"
else
    fail "block command failed"
fi

# --------------------------------------------------------------------------
# Step 4 — Try to call the same tool — should be refused
# --------------------------------------------------------------------------

step "Step 4 — Call '${TOOL_NAME}' after block — expect refusal"
if run_tool "${TOOL_NAME}" "${ARGS}"; then
    fail "tool executed but should have been blocked"
else
    pass "tool was correctly blocked — execution did not happen"
fi

# --------------------------------------------------------------------------
# Step 5 — Show the block list
# --------------------------------------------------------------------------

step "Step 5 — Block list"
${DC} tool list --blocked
if ${DC} tool list --blocked 2>/dev/null | grep -q "${TOOL_NAME}"; then
    pass "'${TOOL_NAME}' appears in blocked list"
else
    fail "'${TOOL_NAME}' not found in blocked list"
fi

# --------------------------------------------------------------------------
# Step 6 — Unblock the tool
# --------------------------------------------------------------------------

step "Step 6 — Unblock tool '${TOOL_NAME}'"
if ${DC} tool unblock "${TOOL_NAME}"; then
    pass "unblock command succeeded"
else
    fail "unblock command failed"
fi

# --------------------------------------------------------------------------
# Step 7 — Call the tool again — should work
# --------------------------------------------------------------------------

step "Step 7 — Call '${TOOL_NAME}' after unblock — expect success"
if run_tool "${TOOL_NAME}" "${ARGS}"; then
    pass "tool executed successfully after unblock"
else
    fail "tool was still blocked after unblock"
fi

# --------------------------------------------------------------------------
# Done
# --------------------------------------------------------------------------

echo
echo "════════════════════════════════════════"
echo "  ${PASSED} passed  ${FAILED} failed"
echo "════════════════════════════════════════"
[ "${FAILED}" -eq 0 ] || exit 1
