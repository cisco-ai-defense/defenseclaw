#!/usr/bin/env bash
# Resilience helpers in installer_lib.sh: dc_marker must print exactly the
# line managed.FormatResilienceEvent prints, and dc_restamp must repair a
# drifted DefenseClaw-owned object without ever following a link or
# aborting its caller.
. "${PKG_DIR}/lib/installer_lib.sh"

DC_RETRY_SLEEP=0

_rh_me() { printf '%s:%s' "$(id -un)" "$(id -gn)"; }

# Golden lines produced by Go's managed.FormatResilienceEvent for the same
# marker and field maps (keys sorted, values strconv.Quote'd).
t_marker_matches_go_format() {
  local DC_MARKER_COMPONENT=""
  local got
  got="$(dc_format_marker defenseclaw_repair reason=mode,owner \
    path=/opt/cisco/secureclient/defenseclaw/etc component=install)"
  assert_eq "${got}" 'defenseclaw_repair component="install" path="/opt/cisco/secureclient/defenseclaw/etc" reason="mode,owner"' \
    "repair marker"

  got="$(dc_format_marker defenseclaw_skip unit=user:alice connector=codex \
    reason=scrub_failed 'path=/Users/alice/My "Docs"\x')"
  assert_eq "${got}" 'defenseclaw_skip connector="codex" path="/Users/alice/My \"Docs\"\\x" reason="scrub_failed" unit="user:alice"' \
    "skip marker with quote and backslash"

  got="$(dc_format_marker defenseclaw_boundary \
    "detail=a"$'\n'"b"$'\t'"c"$'\r'"d"$'\x01'"e"$'\x7f'"f"$'\x1b'"g"$'\a'$'\b'$'\f'$'\v' \
    "path=/tmp/é")"
  assert_eq "${got}" 'defenseclaw_boundary detail="a\nb\tc\rd\x01e\x7ff\x1bg\a\b\f\v" path="/tmp/é"' \
    "control characters escaped like strconv.Quote"

  got="$(dc_format_marker defenseclaw_accept Zeta=1 alpha= _x=y)"
  assert_eq "${got}" 'defenseclaw_accept Zeta="1" _x="y" alpha=""' \
    "keys sorted in byte order"
}

t_marker_adds_component_and_last_value_wins() {
  local DC_MARKER_COMPONENT="uninstall"
  local got
  got="$(dc_format_marker defenseclaw_skip reason=a reason=b 'bad key=x')"
  assert_eq "${got}" 'defenseclaw_skip component="uninstall" reason="b"' \
    "component stamped, duplicate key keeps last value, invalid key dropped"
}

t_marker_goes_to_stderr_and_log_file() {
  local d; d="$(mktest_tmp)"
  local DC_MARKER_COMPONENT="install" DC_MARKER_LOG_FILE="${d}/sink.log"
  local out
  out="$(dc_warn "something drifted" defenseclaw_accept path=/x reason=y 2>&1 >/dev/null)"
  assert_contains "${out}" "[install] WARN: something drifted" "warn line on stderr"
  assert_contains "${out}" 'defenseclaw_accept component="install" path="/x" reason="y"' "marker on stderr"
  assert_contains "$(cat "${d}/sink.log")" 'defenseclaw_accept component="install"' "marker in log file"
}

t_restamp_symlink_unlinks_link_and_leaves_target() {
  local d; d="$(mktest_tmp)"
  printf 'target\n' > "${d}/target"
  chmod 0604 "${d}/target"
  ln -s "${d}/target" "${d}/owned"
  local out rc=0
  out="$(dc_restamp "${d}/owned" "$(_rh_me)" 0640 -f 2>&1)" || rc=$?
  assert_status "${rc}" 0 "symlink restamp returns success"
  if [[ -e "${d}/owned" || -L "${d}/owned" ]]; then
    _fail "symlink should be gone from the owned path"
  fi
  assert_file_mode "${d}/target" 604
  assert_eq "$(cat "${d}/target")" "target" "link target content untouched"
  assert_contains "${out}" "defenseclaw_boundary" "boundary logged"
  assert_contains "${out}" 'reason="symlink"' "reason names the symlink"
  assert_contains "${out}" 'action="unlinked"' "link unlinked, not followed"
}

t_restamp_clears_uchg_and_reports_repair() {
  local d; d="$(mktest_tmp)"
  printf 'x\n' > "${d}/f"
  chmod 0666 "${d}/f"
  chflags uchg "${d}/f"
  local out rc=0
  out="$(dc_restamp "${d}/f" "$(_rh_me)" 0640 -f 2>&1)" || rc=$?
  assert_status "${rc}" 0 "uchg restamp succeeds"
  assert_eq "$(stat -f '%Sf' "${d}/f")" "-" "uchg cleared"
  assert_file_mode "${d}/f" 640
  assert_contains "${out}" "defenseclaw_repair" "repair logged"
  assert_contains "${out}" "flags" "repair names the flags"
  assert_contains "${out}" "mode" "repair names the mode"
}

t_restamp_strips_acl_and_group_write() {
  local d; d="$(mktest_tmp)"
  mkdir "${d}/dir"
  chmod 0775 "${d}/dir"
  chmod +a "everyone allow write,file_inherit,directory_inherit" "${d}/dir"
  local out rc=0
  out="$(dc_restamp "${d}/dir" "$(_rh_me)" 0755 -d 2>&1)" || rc=$?
  assert_status "${rc}" 0 "acl restamp succeeds"
  assert_file_mode "${d}/dir" 755
  assert_eq "$(ls -lde "${d}/dir" | sed -n '2p')" "" "ACL removed"
  assert_contains "${out}" "acl" "repair names the ACL"
}

t_restamp_recursive_does_not_follow_inner_link() {
  local d; d="$(mktest_tmp)"
  mkdir -p "${d}/tree/sub" "${d}/outside"
  printf 'x\n' > "${d}/tree/sub/f"
  printf 'y\n' > "${d}/outside/victim"
  chmod 0666 "${d}/outside/victim"
  chmod 0666 "${d}/tree/sub/f"
  chflags uchg "${d}/tree/sub/f"
  ln -s "${d}/outside" "${d}/tree/sub/link"
  local out rc=0
  out="$(dc_restamp "${d}/tree" "$(_rh_me)" 0750 -R -d 2>&1)" || rc=$?
  assert_status "${rc}" 0 "recursive restamp succeeds"
  assert_eq "$(stat -f '%Sf' "${d}/tree/sub/f")" "-" "nested uchg cleared"
  assert_file_mode "${d}/tree/sub/f" 644
  assert_file_mode "${d}/outside/victim" 666
  assert_file_mode "${d}/tree" 750
  assert_contains "${out}" 'action="not_followed"' "inner link logged, not followed"
}

t_restamp_wrong_type_moves_aside() {
  local d; d="$(mktest_tmp)"
  printf 'not a dir\n' > "${d}/bin"
  local out rc=0
  out="$(dc_restamp "${d}/bin" "$(_rh_me)" 0755 -d 2>&1)" || rc=$?
  assert_status "${rc}" 0 "wrong type handled"
  [[ ! -e "${d}/bin" ]] || _fail "wrong-type object should be moved aside"
  assert_contains "${out}" 'reason="wrong_type"' "boundary names the wrong type"
}

t_restamp_hard_link_moves_aside() {
  local d; d="$(mktest_tmp)"
  printf 'x\n' > "${d}/f"
  ln "${d}/f" "${d}/other"
  local out rc=0
  out="$(dc_restamp "${d}/f" "$(_rh_me)" 0600 -f 2>&1)" || rc=$?
  assert_status "${rc}" 0 "hard link handled"
  [[ ! -e "${d}/f" ]] || _fail "hard-linked name should be moved aside"
  assert_file_mode "${d}/other" 644
  assert_contains "${out}" 'reason="hard_link"' "boundary names the hard link"
}

t_restamp_failure_is_logged_not_fatal() {
  if [[ "$(id -u)" == "0" ]]; then
    return 0
  fi
  local d; d="$(mktest_tmp)"
  printf 'x\n' > "${d}/f"
  local out rc=0
  # An unprivileged caller cannot chown to root: the helper must report
  # it and return non-zero instead of exiting.
  out="$( (set -e; dc_restamp "${d}/f" root:wheel 0600 -f || true; echo still-running) 2>&1)" || rc=$?
  assert_status "${rc}" 0 "caller under set -e keeps running"
  assert_contains "${out}" "still-running" "caller continued"
  assert_contains "${out}" 'defenseclaw_accept' "failure logged as accepted drift"
  assert_contains "${out}" 'reason="restamp_failed"' "failure reason"
}

t_restamp_missing_path_is_noop() {
  local d; d="$(mktest_tmp)"
  local out rc=0
  out="$(dc_restamp "${d}/absent" "$(_rh_me)" 0600 2>&1)" || rc=$?
  assert_status "${rc}" 0 "missing path is a no-op"
  assert_eq "${out}" "" "no output for a missing path"
}

run_case "dc_marker matches the Go marker format"            t_marker_matches_go_format
run_case "dc_marker stamps component, last value wins"       t_marker_adds_component_and_last_value_wins
run_case "dc_warn writes stderr and the log file"            t_marker_goes_to_stderr_and_log_file
run_case "dc_restamp unlinks a symlink, target untouched"    t_restamp_symlink_unlinks_link_and_leaves_target
run_case "dc_restamp clears uchg and reports the repair"     t_restamp_clears_uchg_and_reports_repair
run_case "dc_restamp strips ACL and group write"             t_restamp_strips_acl_and_group_write
run_case "dc_restamp -R never follows an inner link"         t_restamp_recursive_does_not_follow_inner_link
run_case "dc_restamp moves a wrong-type object aside"        t_restamp_wrong_type_moves_aside
run_case "dc_restamp moves a hard-linked file aside"         t_restamp_hard_link_moves_aside
run_case "dc_restamp failure is logged, never fatal"         t_restamp_failure_is_logged_not_fatal
run_case "dc_restamp on a missing path is a no-op"           t_restamp_missing_path_is_noop
