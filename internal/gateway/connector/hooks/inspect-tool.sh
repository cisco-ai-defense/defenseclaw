#!/bin/bash
# defenseclaw-managed-hook v2
# DefenseClaw PreToolUse hook — calls DefenseClaw inspect API before tool execution.
# Used by Claude Code (PreToolUse) and OpenCode (hook command).
# The agent sets CLAUDE_TOOL_NAME (Claude Code) or TOOL_NAME and pipes input to stdin.
set -euo pipefail

# Fail-open guard. See inspect-request.sh for rationale.
DEFENSECLAW_HOME="${DEFENSECLAW_HOME:-${HOME}/.defenseclaw}"
if [ ! -d "${DEFENSECLAW_HOME}" ] || [ -f "${DEFENSECLAW_HOME}/.disabled" ]; then
  exit 0
fi

# Plan B4 / S0.4: shell-side hook hardening. Source the helpers BEFORE
# touching any agent-supplied data so resource caps + env sanitization
# apply to every subprocess this hook spawns.
. "$(dirname "${BASH_SOURCE[0]}")/_hardening.sh"
defenseclaw_harden_resources
defenseclaw_harden_env

TOOL_NAME="${CLAUDE_TOOL_NAME:-${TOOL_NAME:-unknown}}"
TOOL_INPUT=$(cat)

API_ADDR="${DEFENSECLAW_API_ADDR:-{{.APIAddr}}}"
FAIL_MODE="${DEFENSECLAW_FAIL_MODE:-{{.FailMode}}}"

# Transport failures (gateway down / 5xx) always allow unless
# DEFENSECLAW_STRICT_AVAILABILITY=1; a DefenseClaw outage must not
# brick the user's tool calls. Response failures (4xx / parse error)
# respect FAIL_MODE.
fail_unreachable() {
  defenseclaw_log_hook_failure inspect inspect-tool "$1" transport "$FAIL_MODE"
  defenseclaw_emit_unreachable_stderr "tool" "$1"
  if defenseclaw_should_fail_closed_on_unreachable; then
    exit 2
  fi
  exit 0
}

fail_response() {
  defenseclaw_log_hook_failure inspect inspect-tool "$1" response "$FAIL_MODE"
  echo "defenseclaw: inspect-tool hook error: $1" >&2
  if [ "$FAIL_MODE" = "open" ]; then
    exit 0
  fi
  exit 2
}

RESPONSE=$(jq -n --arg tool "$TOOL_NAME" --arg args "$TOOL_INPUT" \
  '{tool: $tool, args: $args}' | \
  curl -s -w "\n%{http_code}" -X POST "http://${API_ADDR}/api/v1/inspect/tool" \
  -H "Content-Type: application/json" \
  -H "X-DefenseClaw-Client: inspect-hook/1.0" \
  --connect-timeout 2 \
  --max-time 5 \
  --data-binary @- 2>/dev/null) || {
  fail_unreachable "gateway unreachable"
}

HTTP_CODE=$(echo "$RESPONSE" | tail -1)
RESULT=$(echo "$RESPONSE" | sed '$d')

if [ -z "$HTTP_CODE" ]; then
  fail_unreachable "gateway returned no HTTP status"
elif [ "$HTTP_CODE" -ge 500 ] 2>/dev/null && [ "$HTTP_CODE" -lt 600 ] 2>/dev/null; then
  fail_unreachable "gateway returned HTTP ${HTTP_CODE}"
elif [ "$HTTP_CODE" -lt 200 ] 2>/dev/null || [ "$HTTP_CODE" -ge 300 ] 2>/dev/null; then
  fail_response "gateway returned HTTP ${HTTP_CODE}"
fi

ACTION=$(echo "$RESULT" | jq -r '.action // "allow"' 2>/dev/null) || {
  fail_response "failed to parse action from response"
}
if [ "$ACTION" = "block" ]; then
  REASON=$(echo "$RESULT" | jq -r '.reason // "blocked by DefenseClaw"' 2>/dev/null)
  echo "DefenseClaw: $REASON" >&2
  exit 2
fi
exit 0
