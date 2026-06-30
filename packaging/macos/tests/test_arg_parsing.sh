#!/usr/bin/env bash
# Drive install.sh's arg-parsing & preflight surface without going past
# the root check. We invoke install.sh as a non-root user with --help
# (exits 0 before root check) and with bad flags (exits non-zero with
# a clear message). We do not exercise the side-effecting branches.
INSTALL_SH="${PKG_DIR}/install.sh"
UNINSTALL_SH="${PKG_DIR}/uninstall.sh"

t_install_help() {
  local out
  out="$("${INSTALL_SH}" --help 2>&1)" || _fail "--help should exit 0"
  assert_contains "${out}" "--mode {observe|action}" "mode flag in help"
  assert_contains "${out}" "--connector LIST"        "connector flag in help"
  assert_contains "${out}" "comma-separated"         "comma-separated note in help"
  assert_contains "${out}" "Per-user hook wiring"    "per-user section header"
}

t_install_bad_mode_exits_nonzero() {
  local out rc=0
  out="$("${INSTALL_SH}" --mode garbage 2>&1)" || rc=$?
  assert_status "${rc}" 1 "bad --mode should exit non-zero"
  assert_contains "${out}" "must be 'observe' or 'action'" "explains valid modes"
}

t_install_unknown_flag_exits_nonzero() {
  local out rc=0
  out="$("${INSTALL_SH}" --bogus 2>&1)" || rc=$?
  assert_status "${rc}" 1 "unknown flag should exit non-zero"
  assert_contains "${out}" "unknown flag" "messages unknown flag"
}

t_install_empty_connector_entry_exits_nonzero() {
  # `--connector cursor,,codex` should die() with the explicit message,
  # not crash silently or proceed.
  local out rc=0
  out="$("${INSTALL_SH}" --connector "cursor,,codex" 2>&1)" || rc=$?
  assert_status "${rc}" 1 "empty list entry should exit non-zero"
  assert_contains "${out}" "empty entry" "messages empty entry"
}

t_install_warns_unsupported_connector() {
  # Unsupported connector should NOT die, just warn. But we can't get
  # past the root-check on a clean install. We rely on the fact that
  # the warning is emitted BEFORE the root check.
  local out rc=0
  out="$("${INSTALL_SH}" --connector "geminicli" 2>&1)" || rc=$?
  assert_contains "${out}" "is not in the auto-wire list" "warns about unsupported"
}

t_install_requires_root() {
  # As non-root, after arg parsing the script must die on the root check.
  if [[ $EUID -eq 0 ]]; then
    if [[ "${VERBOSE:-false}" == "true" ]]; then printf '  skip (running as root)\n'; fi
    return 0
  fi
  local out rc=0
  out="$("${INSTALL_SH}" --connector codex 2>&1)" || rc=$?
  assert_status "${rc}" 1 "non-root should exit non-zero"
  assert_contains "${out}" "must run as root" "explains root requirement"
}

t_uninstall_help() {
  local out
  out="$("${UNINSTALL_SH}" --help 2>&1)" || _fail "uninstall --help should exit 0"
  assert_contains "${out}" "--purge"                 "purge flag documented"
  assert_contains "${out}" "audit DB"                "preservation note"
  assert_contains "${out}" "--keep-agent-configs"    "scrub opt-out documented"
  assert_contains "${out}" "scrub DefenseClaw"        "scrub behavior documented"
}

t_uninstall_unknown_flag() {
  local out rc=0
  out="$("${UNINSTALL_SH}" --bogus 2>&1)" || rc=$?
  assert_status "${rc}" 1 "uninstall unknown flag exits non-zero"
}

t_uninstall_requires_root() {
  if [[ $EUID -eq 0 ]]; then
    if [[ "${VERBOSE:-false}" == "true" ]]; then printf '  skip (running as root)\n'; fi
    return 0
  fi
  local out rc=0
  out="$("${UNINSTALL_SH}" 2>&1)" || rc=$?
  assert_status "${rc}" 1 "uninstall non-root exits non-zero"
  assert_contains "${out}" "must run as root" "explains root requirement"
}

run_case "install --help"                 t_install_help
run_case "install --mode garbage"         t_install_bad_mode_exits_nonzero
run_case "install --bogus"                t_install_unknown_flag_exits_nonzero
run_case "install --connector cursor,,X"  t_install_empty_connector_entry_exits_nonzero
run_case "install unsupported connector"  t_install_warns_unsupported_connector
run_case "install non-root rejected"      t_install_requires_root
run_case "uninstall --help"               t_uninstall_help
run_case "uninstall --bogus"              t_uninstall_unknown_flag
run_case "uninstall non-root rejected"    t_uninstall_requires_root
