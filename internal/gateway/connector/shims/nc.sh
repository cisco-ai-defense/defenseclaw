#!/bin/bash
# DefenseClaw shim for nc/ncat — inspects args for C2 patterns before executing.
# F-2029 / F-3397: see curl.sh for full rationale of the auth + 401
# fail-closed contract; this shim mirrors the same hardening.
set -euo pipefail
# The real tool inherits this shim's environment, and an assignment keeps the
# export bit of an inherited variable of the same name. So every value the
# shim keeps is in a _DC_SHIM_* name, unset first: a shim value in a common
# name (API_TOKEN, ACTION, ...) would replace the user's own value for the
# real tool and everything it starts, and the bearer would go with it.
unset -v _DC_SHIM_DIR _DC_SHIM_REAL _DC_SHIM_CURL _DC_SHIM_ADDR _DC_SHIM_TOKEN _DC_SHIM_AUTH \
  _DC_SHIM_AUTH_ARGS _DC_SHIM_BODY _DC_SHIM_RESPONSE _DC_SHIM_CODE _DC_SHIM_RESULT _DC_SHIM_ACTION \
  _DC_SHIM_REASON
_DC_SHIM_DIR="$(cd "$(dirname "$0")" && pwd)"
_DC_SHIM_REAL=$(PATH="$(echo "$PATH" | sed "s|${_DC_SHIM_DIR}:||g; s|:${_DC_SHIM_DIR}||g")" which nc 2>/dev/null || echo /usr/bin/nc)
_DC_SHIM_CURL=$(PATH="$(echo "$PATH" | sed "s|${_DC_SHIM_DIR}:||g; s|:${_DC_SHIM_DIR}||g")" which curl 2>/dev/null || echo /usr/bin/curl)

_DC_SHIM_ADDR="{{.APIAddr}}"

# The bearer is DEFENSECLAW_GATEWAY_TOKEN or else the one in the .token file
# next to the shim, read in a subshell so that it is never exported either.
_DC_SHIM_TOKEN="${DEFENSECLAW_GATEWAY_TOKEN:-}"
if [ -z "${_DC_SHIM_TOKEN}" ] && [ -f "${_DC_SHIM_DIR}/.token" ]; then
  # shellcheck source=/dev/null
  _DC_SHIM_TOKEN="$(. "${_DC_SHIM_DIR}/.token"; printf '%s' "${DEFENSECLAW_GATEWAY_TOKEN:-}")"
fi

# The bearer and the request body reach curl on descriptors 8 and 9, never on
# its command line, which every local account can read; printf is a shell
# builtin. The descriptor-backed --config form works on curl releases older
# than 7.55.0, which lack -H @file. -q, curl's first argument, keeps a .curlrc
# from the agent's CURL_HOME, XDG_CONFIG_HOME or HOME out of the request. The
# tool arguments are this shim's own.
_DC_SHIM_AUTH=""
_DC_SHIM_AUTH_ARGS=()
if [ -n "${_DC_SHIM_TOKEN}" ]; then
  case "${_DC_SHIM_TOKEN}" in
    *$'\n'*|*$'\r'*)
      echo "DefenseClaw: shim gateway token is malformed — refusing to exec nc" >&2
      exit 1
      ;;
  esac
  # The two characters a quoted curl config value escapes.
  _DC_SHIM_AUTH="${_DC_SHIM_TOKEN//\\/\\\\}"
  _DC_SHIM_AUTH="${_DC_SHIM_AUTH//\"/\\\"}"
  _DC_SHIM_AUTH="header = \"Authorization: Bearer ${_DC_SHIM_AUTH}\""
  _DC_SHIM_AUTH_ARGS=(--config /dev/fd/8)
fi
_DC_SHIM_BODY="$(jq -cn --arg tool "nc" --args \
  '{tool: $tool, args: {argv: ([$tool] + $ARGS.positional)}}' \
  -- "$@")" || _DC_SHIM_BODY=""

_DC_SHIM_RESPONSE=$("$_DC_SHIM_CURL" -q -s --noproxy '*' -w "\n%{http_code}" -X POST "http://${_DC_SHIM_ADDR}/api/v1/inspect/tool" \
  -H "Content-Type: application/json" \
  -H "X-DefenseClaw-Client: shim/nc/2.0" \
  "${_DC_SHIM_AUTH_ARGS[@]+"${_DC_SHIM_AUTH_ARGS[@]}"}" \
  --connect-timeout 2 \
  --max-time 5 \
  --data-binary @/dev/fd/9 2>/dev/null \
  8< <(printf '%s\n' "$_DC_SHIM_AUTH") \
  9< <(printf '%s' "$_DC_SHIM_BODY")) || {
  exec "$_DC_SHIM_REAL" "$@"
}

_DC_SHIM_CODE=$(echo "$_DC_SHIM_RESPONSE" | tail -1)
_DC_SHIM_RESULT=$(echo "$_DC_SHIM_RESPONSE" | sed '$d')

if [ "$_DC_SHIM_CODE" = "401" ] || [ "$_DC_SHIM_CODE" = "403" ]; then
  echo "DefenseClaw: shim auth rejected (HTTP ${_DC_SHIM_CODE}) — refusing to exec nc" >&2
  exit 1
fi

_DC_SHIM_ACTION=$(echo "$_DC_SHIM_RESULT" | jq -r '.action // empty' 2>/dev/null) || _DC_SHIM_ACTION=""
if [ -z "${_DC_SHIM_ACTION}" ]; then
  echo "DefenseClaw: shim received unparseable response (HTTP ${_DC_SHIM_CODE}) — refusing to exec nc" >&2
  exit 1
fi
if [ "$_DC_SHIM_ACTION" = "block" ]; then
  _DC_SHIM_REASON=$(echo "$_DC_SHIM_RESULT" | jq -r '.reason // "blocked by DefenseClaw"')
  echo "DefenseClaw: $_DC_SHIM_REASON" >&2
  exit 1
fi
exec "$_DC_SHIM_REAL" "$@"
