#!/bin/bash
# DefenseClaw shim for curl — inspects URL and flags before executing.
#
# Avarice F-2029 / chain F-3397: pre-fix this shim called the gateway's
# /api/v1/inspect/tool endpoint UNAUTHENTICATED. With a configured
# gateway token the sidecar returns 401 + {"error":"unauthorized"}; the
# shim's `jq -r '.action // "allow"'` then fell back to "allow" and
# exec'd the real curl. Combined with the inspect-request hook also
# being unauthenticated (F-2025), a malicious agent had a complete
# unauthenticated path past every inspection layer.
#
# Fix: load the gateway bearer token from .token (written next to the
# shim) or DEFENSECLAW_GATEWAY_TOKEN, send Authorization on every
# inspection call, and treat HTTP 401/403 OR a {"error":...} response
# WITHOUT a recognized action field as a HARD BLOCK so a misconfigured
# auth path can never be silently downgraded to "allow".
set -euo pipefail
# The real tool inherits this shim's environment, and an assignment keeps the
# export bit of an inherited variable of the same name. So every value the
# shim keeps is in a _DC_SHIM_* name, unset first: a shim value in a common
# name (API_TOKEN, ACTION, ...) would replace the user's own value for the
# real tool and everything it starts, and the bearer would go with it.
unset -v _DC_SHIM_DIR _DC_SHIM_REAL _DC_SHIM_ADDR _DC_SHIM_TOKEN _DC_SHIM_JSON \
  _DC_SHIM_BODY _DC_SHIM_RESPONSE _DC_SHIM_CODE _DC_SHIM_RESULT _DC_SHIM_ACTION \
  _DC_SHIM_REASON
_DC_SHIM_DIR="$(cd "$(dirname "$0")" && pwd)"
_DC_SHIM_REAL=$(PATH="$(echo "$PATH" | sed "s|${_DC_SHIM_DIR}:||g; s|:${_DC_SHIM_DIR}||g")" which curl 2>/dev/null || echo /usr/bin/curl)

_DC_SHIM_ADDR="{{.APIAddr}}"

# The bearer is DEFENSECLAW_GATEWAY_TOKEN or else the one in the .token file
# next to the shim, read in a subshell so that it is never exported either.
_DC_SHIM_TOKEN="${DEFENSECLAW_GATEWAY_TOKEN:-}"
if [ -z "${_DC_SHIM_TOKEN}" ] && [ -f "${_DC_SHIM_DIR}/.token" ]; then
  # shellcheck source=/dev/null
  _DC_SHIM_TOKEN="$(. "${_DC_SHIM_DIR}/.token"; printf '%s' "${DEFENSECLAW_GATEWAY_TOKEN:-}")"
fi

# Reject tokens that could split an HTTP header.
if [ -n "${_DC_SHIM_TOKEN}" ]; then
  case "${_DC_SHIM_TOKEN}" in
    *$'\n'*|*$'\r'*)
      echo "DefenseClaw: shim gateway token is malformed — refusing to exec curl" >&2
      exit 1
      ;;
  esac
fi
_DC_SHIM_BODY="$(jq -cn --arg tool "curl" --args \
  '{tool: $tool, args: {argv: ([$tool] + $ARGS.positional)}}' \
  -- "$@")" || _DC_SHIM_BODY=""

_DC_SHIM_RESPONSE=$(_dc_shim_post "curl" 2>/dev/null) || {
  echo "DefenseClaw: gateway peer is unverified or unavailable — refusing to exec curl" >&2
  exit 1
}

_DC_SHIM_CODE=$(echo "$_DC_SHIM_RESPONSE" | tail -1)
_DC_SHIM_RESULT=$(echo "$_DC_SHIM_RESPONSE" | sed '$d')

if [ "$_DC_SHIM_CODE" = "401" ] || [ "$_DC_SHIM_CODE" = "403" ]; then
  echo "DefenseClaw: shim auth rejected (HTTP ${_DC_SHIM_CODE}) — refusing to exec curl" >&2
  exit 1
fi

_DC_SHIM_ACTION=$(echo "$_DC_SHIM_RESULT" | jq -r '.action // empty' 2>/dev/null) || _DC_SHIM_ACTION=""
if [ -z "${_DC_SHIM_ACTION}" ]; then
  # No recognized action means either the response is malformed or the
  # gateway returned an error envelope. Either way, do NOT default to
  # allow — that was the F-2029 silent-bypass.
  echo "DefenseClaw: shim received unparseable response (HTTP ${_DC_SHIM_CODE}) — refusing to exec curl" >&2
  exit 1
fi
if [ "$_DC_SHIM_ACTION" = "block" ]; then
  _DC_SHIM_REASON=$(echo "$_DC_SHIM_RESULT" | jq -r '.reason // "blocked by DefenseClaw"')
  echo "DefenseClaw: $_DC_SHIM_REASON" >&2
  exit 1
fi
exec "$_DC_SHIM_REAL" "$@"
