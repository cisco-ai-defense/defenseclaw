#!/bin/bash
# defenseclaw-managed-hook v2
# DefenseClaw PreRequest hook — inspects user query before it is sent to the LLM.
# Reads the user message content from stdin (JSON with "content" field).
set -euo pipefail

# Fail-open guard. If the operator has disabled the guardrail or fully
# uninstalled DefenseClaw, exit 0 immediately so the agent isn't
# bricked by a hook calling a gateway that no longer exists. The
# sentinel is created by `defenseclaw setup guardrail --disable` and
# is removed by `--enable`. A missing DEFENSECLAW_HOME directory is
# treated as a hard uninstall.
DEFENSECLAW_HOME="${DEFENSECLAW_HOME:-${HOME}/.defenseclaw}"
if [ ! -d "${DEFENSECLAW_HOME}" ] || [ -f "${DEFENSECLAW_HOME}/.disabled" ]; then
  exit 0
fi

CONTENT=$(cat)

API_ADDR="${DEFENSECLAW_API_ADDR:-{{.APIAddr}}}"
FAIL_MODE="${DEFENSECLAW_FAIL_MODE:-closed}"

fail_action() {
  echo "defenseclaw: inspect-request hook error: $1" >&2
  if [ "$FAIL_MODE" = "open" ]; then
    exit 0
  fi
  exit 2
}

RESPONSE=$(printf '%s' "$CONTENT" | curl -s -w "\n%{http_code}" -X POST "http://${API_ADDR}/api/v1/inspect/request" \
  -H "Content-Type: application/json" \
  -H "X-DefenseClaw-Client: inspect-hook/1.0" \
  --connect-timeout 2 \
  --max-time 5 \
  --data-binary @- 2>/dev/null) || {
  fail_action "gateway unreachable"
}

HTTP_CODE=$(echo "$RESPONSE" | tail -1)
RESULT=$(echo "$RESPONSE" | sed '$d')

if [ -z "$HTTP_CODE" ] || [ "$HTTP_CODE" -lt 200 ] 2>/dev/null || [ "$HTTP_CODE" -ge 300 ] 2>/dev/null; then
  fail_action "gateway returned HTTP ${HTTP_CODE:-unknown}"
fi

ACTION=$(echo "$RESULT" | jq -r '.action // "allow"' 2>/dev/null) || {
  fail_action "failed to parse action from response"
}
if [ "$ACTION" = "block" ]; then
  REASON=$(echo "$RESULT" | jq -r '.reason // "blocked by DefenseClaw"' 2>/dev/null)
  echo "DefenseClaw: $REASON" >&2
  exit 2
fi
exit 0
