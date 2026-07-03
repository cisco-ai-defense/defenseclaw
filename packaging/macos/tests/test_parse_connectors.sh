#!/usr/bin/env bash
# parse_connectors: comma-split, trim, lowercase, reject empties.
. "${PKG_DIR}/lib/installer_lib.sh"

t_single() {
  local got
  got="$(parse_connectors "codex")"
  assert_eq "${got}" "codex" "single connector"
}

t_multi() {
  local got
  got="$(parse_connectors "cursor,claudecode,codex" | tr '\n' '|')"
  assert_eq "${got}" "cursor|claudecode|codex|" "multi connector ordering"
}

t_whitespace_and_case() {
  local got
  got="$(parse_connectors "  Cursor , CLAUDECODE  ,  codex" | tr '\n' '|')"
  assert_eq "${got}" "cursor|claudecode|codex|" "whitespace + case"
}

t_empty_entry_rejected() {
  local rc=0
  parse_connectors "cursor,,codex" >/dev/null 2>&1 || rc=$?
  assert_status "${rc}" 1 "empty entry should exit non-zero"
}

t_trailing_comma_rejected() {
  local rc=0
  parse_connectors "cursor," >/dev/null 2>&1 || rc=$?
  assert_status "${rc}" 1 "trailing comma should exit non-zero"
}

t_leading_comma_rejected() {
  local rc=0
  parse_connectors ",cursor" >/dev/null 2>&1 || rc=$?
  assert_status "${rc}" 1 "leading comma should exit non-zero"
}

t_unsafe_token_rejected() {
  # Anything outside [a-z0-9_-]+ must be rejected: it would either
  # break the YAML parser or, worse, get rendered as an unrelated key.
  local rc
  rc=0; parse_connectors "cursor injected: value" >/dev/null 2>&1 || rc=$?
  assert_status "${rc}" 1 "space + colon rejected"
  rc=0; parse_connectors 'cursor\nfoo:bar' >/dev/null 2>&1 || rc=$?
  assert_status "${rc}" 1 "backslash-n literal rejected"
  rc=0; parse_connectors 'a"b' >/dev/null 2>&1 || rc=$?
  assert_status "${rc}" 1 "quote rejected"
  rc=0; parse_connectors 'a/b' >/dev/null 2>&1 || rc=$?
  assert_status "${rc}" 1 "slash rejected"
}

t_empty_string_rejected() {
  local rc=0
  parse_connectors "" >/dev/null 2>&1 || rc=$?
  assert_status "${rc}" 1 "empty arg should exit non-zero"
}

t_is_supported() {
  local rc
  is_supported_connector "codex"; rc=$?
  assert_status "${rc}" 0 "codex supported"
  is_supported_connector "claudecode"; rc=$?
  assert_status "${rc}" 0 "claudecode supported"
  is_supported_connector "cursor"; rc=$?
  assert_status "${rc}" 0 "cursor supported"
  is_supported_connector "geminicli"; rc=$?
  assert_status "${rc}" 1 "geminicli not auto-wired"
}

run_case "single connector" t_single
run_case "multi-connector preserves order" t_multi
run_case "whitespace + case normalization" t_whitespace_and_case
run_case "empty entry rejected" t_empty_entry_rejected
run_case "trailing comma rejected" t_trailing_comma_rejected
run_case "leading comma rejected" t_leading_comma_rejected
run_case "unsafe connector token rejected" t_unsafe_token_rejected
run_case "empty arg rejected" t_empty_string_rejected
run_case "is_supported_connector allow-list" t_is_supported
