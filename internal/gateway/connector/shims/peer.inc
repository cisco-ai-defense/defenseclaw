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
  [[ -n "${HOME:-}" && "$HOME" == /* ]] || return 1
  _dc_shim_safe_native_path "$HOME" dir || return 1
  _dc_shim_safe_native_path "$HOME/.local" dir || return 1
  _dc_shim_safe_native_path "$HOME/.local/bin" dir || return 1
  _dc_shim_safe_native_path "$binary" file || return 1

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
