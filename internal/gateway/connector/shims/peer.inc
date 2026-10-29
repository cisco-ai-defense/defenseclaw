# This function is embedded in each generated shim. Never pass the bearer or
# inspection body as an argument to an external program.
_dc_shim_json_escape() {
  _DC_SHIM_JSON="${1//\\/\\\\}"
  _DC_SHIM_JSON="${_DC_SHIM_JSON//\"/\\\"}"
  _DC_SHIM_JSON="${_DC_SHIM_JSON//$'\n'/\\n}"
  _DC_SHIM_JSON="${_DC_SHIM_JSON//$'\r'/\\r}"
  _DC_SHIM_JSON="${_DC_SHIM_JSON//$'\t'/\\t}"
}

_dc_shim_safe_native_path() {
  local path="$1" want="$2" owner mode
  [[ ! -L "$path" && -e "$path" ]] || return 1
  if [[ "$(/usr/bin/uname -s)" == Darwin ]]; then
    owner=$(/usr/bin/stat -f %u "$path") || return 1
    mode=$(/usr/bin/stat -f %Lp "$path") || return 1
  else
    owner=$(/usr/bin/stat -c %u "$path") || return 1
    mode=$(/usr/bin/stat -c %a "$path") || return 1
  fi
  [[ "$owner" == "$EUID" && "$mode" =~ ^[0-7]{3,4}$ ]] || return 1
  (( (8#$mode & 022) == 0 )) || return 1
  if [[ "$want" == dir ]]; then
    [[ -d "$path" ]]
  else
    [[ -f "$path" && -x "$path" ]]
  fi
}

_dc_shim_post() {
  local binary="${HOME:-}/.local/bin/defenseclaw-gateway"
  [[ -n "${HOME:-}" && "$HOME" == /* ]] || return 7
  _dc_shim_safe_native_path "$HOME" dir || return 7
  _dc_shim_safe_native_path "$HOME/.local" dir || return 7
  _dc_shim_safe_native_path "$HOME/.local/bin" dir || return 7
  _dc_shim_safe_native_path "$binary" file || return 7

  # The jq output is compact JSON; its encoded string contains no literal
  # control characters. Bash builtins keep the token and body off argv.
  _dc_shim_json_escape "$_DC_SHIM_BODY"
  local body_json="$_DC_SHIM_JSON" token_json=""
  if [[ -n "$_DC_SHIM_TOKEN" ]]; then
    _dc_shim_json_escape "$_DC_SHIM_TOKEN"
    token_json=",\"Authorization\":\"Bearer ${_DC_SHIM_JSON}\""
  fi
  printf '{"path":"/api/v1/inspect/tool","headers":{"Content-Type":"application/json","X-DefenseClaw-Client":"shim/%s/2.0"%s},"body":"%s"}' \
    "$1" "$token_json" "$body_json" | \
    "$binary" hook-post --api-addr "$_DC_SHIM_ADDR" --max-time 5 --curl-output
}

# The native helper did not verify a connected gateway peer or received no
# answer. A saved open outage choice runs the real tool and leaves a bounded,
# argument-free failure record for the gateway's degraded-audit reporter.
# _dc_shim_outage_mode_now prints the outage mode this install's config gives
# the connector that installed the shims ({{.ConnectorName}}) now (the gateway's hook-outage-mode, which reads the config.yaml
# above the shims folder and closes on a managed host or an install), so
# `guardrail use-pack strict` or a saved closed applies to the next call
# without re-rendering the shims (GAP-1989). It returns 1 when the account's
# gateway cannot be run; the shim then keeps its installed mode.
_dc_shim_outage_mode_now() {
  local binary="${HOME:-}/.local/bin/defenseclaw-gateway" out=""
  [[ -n "${HOME:-}" && "$HOME" == /* ]] || return 1
  _dc_shim_safe_native_path "$HOME" dir || return 1
  _dc_shim_safe_native_path "$HOME/.local" dir || return 1
  _dc_shim_safe_native_path "$HOME/.local/bin" dir || return 1
  _dc_shim_safe_native_path "$binary" file || return 1
  out=$("$binary" hook-outage-mode --connector {{.ConnectorName}} --hook-dir "$_DC_SHIM_DIR" </dev/null 2>/dev/null) || return 1
  case "$out" in
    open|closed) printf '%s' "$out" ;;
    *) return 1 ;;
  esac
}

_dc_shim_transport_failure() {
  local rc="$1" tool="$2" log_dir="${_DC_SHIM_DIR}/../logs" ts mode="{{.FailMode}}" now=""
  shift 2
  if [[ "$rc" == 7 ]] && now="$(_dc_shim_outage_mode_now)"; then
    mode="$now"
  fi
  if [[ "$rc" != 7 || "$mode" != open ]]; then
    echo "DefenseClaw: gateway peer is unverified or unavailable — refusing to exec $tool" >&2
    exit 1
  fi
  echo "DefenseClaw warning: gateway peer is unverified or unavailable; running $tool without inspection" >&2
  ts="$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || true)"
  if ! (umask 077; mkdir -p -- "$log_dir" &&
    printf '{"ts":"%s","connector":"subprocess","hook":"%s-shim","reason":"gateway peer unverified or unavailable","category":"transport","fail_mode":"open","outcome":"fail_open"}\n' \
      "$ts" "$tool" >> "$log_dir/hook-failures.jsonl"); then
    echo "DefenseClaw warning: degraded audit; could not record this uninspected tool call" >&2
  fi
  exec "$_DC_SHIM_REAL" "$@"
}
