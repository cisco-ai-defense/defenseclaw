#!/bin/bash
# defenseclaw-managed-hook v6
# DefenseClaw Claude Code hook — forwards the full hook event payload to the
# DefenseClaw gateway's /api/v1/claude-code/hook endpoint. Claude Code pipes
# the structured JSON event to stdin and reads the response from stdout.
#
# Forwards W3C trace context (traceparent / tracestate) when the agent
# has exported it via DEFENSECLAW_TRACEPARENT or OTEL_TRACEPARENT, so
# the hook span links back to the agent's parent span. See
# codex-hook.sh for the validation contract.
set -euo pipefail

# Windows: HOME may be unset when agents spawn hooks. Fall back to USERPROFILE.
HOME="${HOME:-${USERPROFILE:-$(cd ~ 2>/dev/null && pwd)}}"
export HOME

HOOK_SOURCE="${BASH_SOURCE[0]:-$0}"
HOOK_LINK_DEPTH=0
while [ -L "$HOOK_SOURCE" ]; do
  HOOK_LINK_DEPTH=$((HOOK_LINK_DEPTH + 1))
  [ "$HOOK_LINK_DEPTH" -le 40 ] || exit 2
  HOOK_PARENT="${HOOK_SOURCE%/*}"
  [ "$HOOK_PARENT" != "$HOOK_SOURCE" ] || HOOK_PARENT="."
  HOOK_BASE="$(cd -P -- "$HOOK_PARENT" 2>/dev/null && pwd)" || exit 2
  if [ -x /usr/bin/readlink ]; then
    HOOK_TARGET="$(/usr/bin/readlink -- "$HOOK_SOURCE")" || exit 2
  elif [ -x /bin/readlink ]; then
    HOOK_TARGET="$(/bin/readlink -- "$HOOK_SOURCE")" || exit 2
  else
    exit 2
  fi
  case "$HOOK_TARGET" in
    /*) HOOK_SOURCE="$HOOK_TARGET" ;;
    *) HOOK_SOURCE="$HOOK_BASE/$HOOK_TARGET" ;;
  esac
done
HOOK_PARENT="${HOOK_SOURCE%/*}"
[ "$HOOK_PARENT" != "$HOOK_SOURCE" ] || HOOK_PARENT="."
HOOK_DIR="$(cd -P -- "$HOOK_PARENT" 2>/dev/null && pwd)" || exit 2
unset HOOK_SOURCE HOOK_LINK_DEPTH HOOK_PARENT HOOK_BASE HOOK_TARGET
{{if .Managed}}
DEFENSECLAW_MANAGED_HOOK=1
export DEFENSECLAW_MANAGED_HOOK
DEFENSECLAW_HOME="$(cd "${HOOK_DIR}/.." && pwd -P)"
export DEFENSECLAW_HOME
{{else}}
DEFENSECLAW_HOME="${DEFENSECLAW_HOME:-${HOME}/.defenseclaw}"
if [ ! -d "${DEFENSECLAW_HOME}" ] || [ -f "${DEFENSECLAW_HOME}/.disabled" ]; then
  exit 0
fi
{{end}}

# Plan B4 / S0.4: shell-side hook hardening — sourced BEFORE the
# missing-token branch (mirrors codex-hook.sh) so the bypass goes
# through defenseclaw_handle_missing_token and honors
# DEFENSECLAW_STRICT_AVAILABILITY. Hardening only mutates env that
# downstream code controls (HOME, PATH, locale, GIT_*); none of the
# subsequent token-resolution logic depends on the operator's
# original PATH or HOME.
. "${HOOK_DIR}/_hardening.sh"
defenseclaw_harden_resources
defenseclaw_harden_env

# Fail mode set BEFORE the missing-token check so the helper has a
# stable FAIL_MODE to log against. See codex-hook.sh for the full
# response-layer and transport-layer rationale.
FAIL_MODE="${DEFENSECLAW_FAIL_MODE:-{{.FailMode}}}"

# Bail early on missing token: see codex-hook.sh +
# defenseclaw_handle_missing_token in _hardening.sh for rationale.
DEFENSECLAW_HOOK_CONNECTOR="claudecode"
DEFENSECLAW_HOOK_NAME="claude-code-hook"
export DEFENSECLAW_HOOK_CONNECTOR DEFENSECLAW_HOOK_NAME

if [ ! -f "${HOOK_DIR}/{{.TokenFile}}" ] && [ -z "${DEFENSECLAW_GATEWAY_TOKEN:-}" ]; then
  defenseclaw_handle_missing_token claudecode claude-code-hook "claude-code tool"
fi

PAYLOAD="$(defenseclaw_read_stdin_capped)" || {
  echo "defenseclaw: claudecode hook refusing oversized payload" >&2
  if [ "$FAIL_MODE" = "closed" ]; then
    printf '{"decision":"block","reason":"DefenseClaw hook payload too large"}\n'
    exit 2
  fi
  exit 0
}
API_ADDR="{{.APIAddr}}"

# Source the token file written by defenseclaw setup (0o600, never baked
# into this script). Connector-scoped sidecars override an inherited generic
# gateway token; legacy .token files retain the explicit env override.
if [ "{{if .ScopedToken}}1{{else}}0{{end}}" = "1" ]; then
  DEFENSECLAW_GATEWAY_TOKEN=
  if [ -f "${HOOK_DIR}/{{.TokenFile}}" ]; then
    IFS= read -r DEFENSECLAW_GATEWAY_TOKEN < "${HOOK_DIR}/{{.TokenFile}}" || true
  fi
  export DEFENSECLAW_GATEWAY_TOKEN
elif [ -f "${HOOK_DIR}/{{.TokenFile}}" ] && [ -z "${DEFENSECLAW_GATEWAY_TOKEN:-}" ]; then
  # shellcheck source=/dev/null
  . "${HOOK_DIR}/{{.TokenFile}}"
fi
API_TOKEN="${DEFENSECLAW_GATEWAY_TOKEN:-}"

# FAIL_MODE was already set above (before the missing-token branch).
# Response-layer and transport-layer failures both respect FAIL_MODE;
# DEFENSECLAW_STRICT_AVAILABILITY=1 remains a force-closed override.

fail_unreachable() {
  defenseclaw_log_hook_failure claudecode claude-code-hook "$1" transport "$FAIL_MODE"
  defenseclaw_emit_unreachable_stderr "claude-code tool" "$1"
  if defenseclaw_should_fail_closed_on_unreachable; then
    exit 2
  fi
  exit 0
}

fail_response() {
  local reason
  reason="$(defenseclaw_response_failure_reason "$1")"
  defenseclaw_log_hook_failure claudecode claude-code-hook "$reason" response "$FAIL_MODE"
  echo "defenseclaw: claude-code hook error: $reason" >&2
  if [ "$FAIL_MODE" = "open" ]; then
    exit 0
  fi
  exit 2
}

AUTH_HEADER_ARGS=()
if [ -n "${API_TOKEN}" ]; then
  AUTH_HEADER_ARGS=(-H "Authorization: Bearer ${API_TOKEN}")
fi

# W3C trace propagation: forward validated traceparent / tracestate.
TRACE_HEADER_ARGS=()
if command -v mapfile >/dev/null 2>&1; then
  mapfile -t TRACE_HEADER_ARGS < <(defenseclaw_extract_trace_context)
fi

RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "http://${API_ADDR}/api/v1/claude-code/hook" \
  -H "Content-Type: application/json" \
  -H "X-DefenseClaw-Client: claude-code-hook/1.0" \
  "${AUTH_HEADER_ARGS[@]+"${AUTH_HEADER_ARGS[@]}"}" \
  "${TRACE_HEADER_ARGS[@]+"${TRACE_HEADER_ARGS[@]}"}" \
  --connect-timeout 2 \
  --max-time 10 \
  -d "$PAYLOAD" 2>/dev/null) || {
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

OUTPUT=$(echo "$RESULT" | _dc_jq -c '.claude_code_output // empty' 2>/dev/null) || {
  fail_response "invalid JSON response"
}
if [ -n "$OUTPUT" ] && [ "$OUTPUT" != "null" ]; then
  echo "$OUTPUT"
fi

ACTION=$(echo "$RESULT" | _dc_jq -r '.action // empty' 2>/dev/null) || {
  fail_response "failed to parse action from response"
}
case "$ACTION" in
  allow|block|confirm) ;;
  *) fail_response "invalid or missing action in gateway response" ;;
esac

# Anthropic's Claude Code hook protocol — like Codex's — is strictly
# EITHER structured JSON on stdout with exit 0 (Claude parses the
# permissionDecision/decision from the JSON) OR exit 2 with the reason
# on stderr. Doing BOTH is a protocol violation: depending on Claude
# version, either the exit code wins (and the rich JSON reason is
# silently replaced with a generic "Hook exited with code 2" surface),
# or stdout wins inconsistently. This is the same shape bug we hit on
# codex-hook.sh where Codex explicitly logged
# "exited with code 2 but did not write a blocking reason to stderr"
# and then FAILED OPEN. Even where Claude Code currently still blocks
# on the exit code, mixing the protocols means the operator-facing
# reason ("matched: SEC-PRIVKEY:Private key") is at risk of being
# dropped between Claude versions.
#
# Resolution: when the gateway gave us structured claude_code_output
# (every block path in claude_code_hook.go does), trust it and exit 0.
# Fall back to exit-2-plus-stderr only when no structured output is
# present.
if [ "$ACTION" = "block" ]; then
  if [ -n "$OUTPUT" ] && [ "$OUTPUT" != "null" ]; then
    # JSON on stdout already carries permissionDecision=deny /
    # decision=block. Exit 0 so Claude Code honors it.
    exit 0
  fi
  REASON=$(echo "$RESULT" | _dc_jq -r '.reason // empty' 2>/dev/null)
  if [ -z "$REASON" ]; then
    REASON="Blocked by DefenseClaw Claude Code policy."
  fi
  printf '%s\n' "$REASON" >&2
  exit 2
fi
exit 0
