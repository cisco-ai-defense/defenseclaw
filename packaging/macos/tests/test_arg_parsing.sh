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
  # The help string interpolates DEFAULT_MODE; assert the interpolated
  # value so a silent DEFAULT_MODE flip in install.sh doesn't diverge
  # from what operators see in --help.
  assert_contains "${out}" "default: action"         "mode default in help is action"
  assert_contains "${out}" "--connector LIST"        "connector flag in help"
  assert_contains "${out}" "--disable-redaction"     "disable redaction flag in help"
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
  # Pass --override-endpoint so the resolver's fail-closed on the
  # (test-host-missing) AVC env_config.json path doesn't preempt the
  # root check we're actually asserting.
  if [[ $EUID -eq 0 ]]; then
    [[ "${VERBOSE:-false}" == "true" ]] && printf '  skip (running as root)\n'
    return 0
  fi
  local out rc=0
  out="$("${INSTALL_SH}" --connector codex \
    --override-endpoint https://ci.example.test 2>&1)" || rc=$?
  assert_status "${rc}" 1 "non-root should exit non-zero"
  assert_contains "${out}" "must run as root" "explains root requirement"
}

t_install_help_omits_service_user() {
  # DefenseClaw's macOS daemon runs as root (see the plist rationale in
  # packaging/launchd/com.cisco.secureclient.defenseclaw.plist); the --service-user
  # flag was removed with the switch. Guard against reintroducing it —
  # a reappearance means someone re-plumbed a non-root path without
  # solving the managed cloud auth provider's root requirement.
  local out
  out="$("${INSTALL_SH}" --help 2>&1)" || _fail "--help should exit 0"
  assert_not_contains "${out}" "--service-user" "install --help must not mention --service-user (root-mode daemon)"
}

t_uninstall_help_omits_service_user() {
  local out
  out="$("${UNINSTALL_SH}" --help 2>&1)" || _fail "uninstall --help should exit 0"
  assert_not_contains "${out}" "--service-user" "uninstall --help must not mention --service-user (root-mode daemon)"
}

t_install_default_redaction_is_on() {
  # Parse install.sh's own defaults section directly so we're asserting
  # the actual install-time contract, not just what render_config emits
  # when handed a value. If a future edit flips this back to
  # "true" (redaction off by default), this test catches it before
  # anything ships.
  local default
  default="$(awk '
    /^DISABLE_REDACTION=/ {
      # DISABLE_REDACTION="false"
      match($0, /"([^"]+)"/, m)
      print m[1]
      exit
    }' "${INSTALL_SH}" 2>/dev/null)"
  # awk on macOS has no `match` capture — fall back to a portable parse.
  if [[ -z "${default}" ]]; then
    default="$(grep -E '^DISABLE_REDACTION=' "${INSTALL_SH}" | head -1 \
      | sed -E 's/^DISABLE_REDACTION="?([^"]+)"?.*/\1/')"
  fi
  assert_eq "${default}" "false" "install.sh DISABLE_REDACTION default is false (redaction ON)"
}

t_install_bad_port_exits_nonzero() {
  local out rc=0
  out="$("${INSTALL_SH}" --port 99999 2>&1)" || rc=$?
  assert_status "${rc}" 1 "out-of-range --port should exit non-zero"
  assert_contains "${out}" "--port must be" "explains port range"
  rc=0
  out="$("${INSTALL_SH}" --port foo 2>&1)" || rc=$?
  assert_status "${rc}" 1 "non-numeric --port should exit non-zero"
  assert_contains "${out}" "--port must be" "explains port must be numeric"
}

t_uninstall_help() {
  local out
  out="$("${UNINSTALL_SH}" --help 2>&1)" || _fail "uninstall --help should exit 0"
  assert_contains "${out}" "--purge"                 "purge flag documented"
  assert_contains "${out}" "config + runtime"        "purge target preserved-state note"
  assert_contains "${out}" "--keep-agent-configs"    "scrub opt-out documented"
  assert_contains "${out}" "scrub DefenseClaw"        "scrub behavior documented"
}

t_install_help_documents_config_file() {
  # AVC ships env_config.json at a stable path under the managed
  # install tree; --config-file lets operators override it (test
  # fixtures, fleet overlays). The --help block must name both the
  # flag and the default path so operators can find the file without
  # reading install.sh source.
  local out
  out="$("${INSTALL_SH}" --help 2>&1)" || _fail "--help should exit 0"
  assert_contains "${out}" "--config-file PATH" "config-file flag in help"
  assert_contains "${out}" "/opt/cisco/secureclient/defenseclaw/env_config.json" \
    "help names the default AVC-authored path"
  assert_contains "${out}" "cisco_ai_defense_endpoint" \
    "help names the JSON field the installer reads"
}

t_install_help_omits_env_flag() {
  # --env {prod|preview} is retired in favor of --config-file. If it
  # comes back the file-based flow was regressed.
  local out
  out="$("${INSTALL_SH}" --help 2>&1)" || _fail "--help should exit 0"
  assert_not_contains "${out}" "--env {prod|preview}" \
    "--env keyword mapping must be gone (replaced by --config-file)"
  # Also confirm the DEFAULT_ENV constant is no longer defined in
  # install.sh — a silent reintroduction would drag the keyword
  # mapping back in.
  local install_sh_body
  install_sh_body="$(cat "${INSTALL_SH}")"
  assert_not_contains "${install_sh_body}" "DEFAULT_ENV=" \
    "install.sh DEFAULT_ENV must not be defined (managed by --config-file now)"
}

t_install_help_documents_override_endpoint() {
  local out
  out="$("${INSTALL_SH}" --help 2>&1)" || _fail "--help should exit 0"
  assert_contains "${out}" "--override-endpoint URL" "override-endpoint flag in help"
  assert_contains "${out}" "Takes precedence"        "override-endpoint precedence note in help"
}

t_install_bad_override_endpoint_exits_nonzero() {
  # A malformed --override-endpoint must be rejected at arg-validation
  # time (before the root check) and name the offending flag so operators
  # don't silently install a daemon pointed at a bogus host. The
  # tightened contract (post PR-579 review): HTTPS bare origin only —
  # no plaintext http://, no userinfo, no path/query/fragment.
  local out rc=0
  out="$("${INSTALL_SH}" --override-endpoint "not-a-url" 2>&1)" || rc=$?
  assert_status "${rc}" 1 "malformed --override-endpoint should exit non-zero"
  assert_contains "${out}" "--override-endpoint must be an HTTPS bare origin" "explains override URL requirement"
}

t_install_override_endpoint_rejects_plaintext_http() {
  # http:// would let a CMID bearer token traverse the wire in
  # cleartext — reject at arg-validation time.
  local out rc=0
  out="$("${INSTALL_SH}" --override-endpoint "http://example.com" 2>&1)" || rc=$?
  assert_status "${rc}" 1 "plaintext http:// must be rejected"
  assert_contains "${out}" "HTTPS bare origin" "names the contract"
}

t_install_override_endpoint_rejects_userinfo() {
  # URL userinfo (user@host / user:pass@host) is the wrong place to
  # encode auth for the AID endpoint AND is silently dropped by
  # net/http on some redirect paths — reject.
  local out rc=0
  out="$("${INSTALL_SH}" --override-endpoint "https://user@example.com" 2>&1)" || rc=$?
  assert_status "${rc}" 1 "userinfo must be rejected"
  assert_contains "${out}" "HTTPS bare origin" "names the contract"
  rc=0
  out="$("${INSTALL_SH}" --override-endpoint "https://user:pass@example.com" 2>&1)" || rc=$?
  assert_status "${rc}" 1 "user:pass userinfo must be rejected"
  assert_contains "${out}" "HTTPS bare origin" "names the contract"
}

t_install_override_endpoint_rejects_path_query_fragment() {
  # The daemon appends its own path (/api/v1/inspect/defense_claw
  # etc.); an operator-supplied path would double-append. Query and
  # fragment on a bare-origin endpoint are equally nonsensical.
  local out rc=0
  for bad in \
    "https://example.com/api" \
    "https://example.com/api/v1/inspect" \
    "https://example.com?tenant=x" \
    "https://example.com#frag"; do
    rc=0
    out="$("${INSTALL_SH}" --override-endpoint "${bad}" 2>&1)" || rc=$?
    assert_status "${rc}" 1 "rejects ${bad}"
    assert_contains "${out}" "HTTPS bare origin" "names the contract for ${bad}"
  done
}

t_install_missing_config_file_exits_nonzero() {
  # No --override-endpoint AND a --config-file path that doesn't
  # exist → fail-closed with a message that names the missing file
  # and points operators at either the AVC drop or --override-endpoint.
  local case_dir; case_dir="$(mktest_tmp)"
  local out rc=0
  out="$("${INSTALL_SH}" --config-file "${case_dir}/does-not-exist.json" 2>&1)" || rc=$?
  assert_status "${rc}" 1 "missing --config-file should exit non-zero"
  assert_contains "${out}" "env_config.json not found at" "names the missing file"
  assert_contains "${out}" "AVC module must drop this file" "explains next step"
  assert_contains "${out}" "--override-endpoint URL for adhoc testing" \
    "points operators at the adhoc-testing seam"
}

t_install_malformed_config_file_exits_nonzero() {
  # Config file exists but is not a JSON object with a valid
  # "cisco_ai_defense_endpoint" URL. Installer must die() before any
  # mutation with a message that names the offending file. Skips the
  # trust check via DC_INSTALLER_SKIP_ROOT_CHECK=1 (test fixtures under
  # a tmpdir cannot be root-owned; the trust check is exercised end-
  # to-end in the manual verification steps).
  local case_dir; case_dir="$(mktest_tmp)"
  local cfg="${case_dir}/env_config.json"
  printf '{"cisco_ai_defense_endpoint":"not-a-url"}\n' >"${cfg}"
  local out rc=0
  out="$(DC_INSTALLER_SKIP_ROOT_CHECK=1 "${INSTALL_SH}" --config-file "${cfg}" 2>&1)" || rc=$?
  assert_status "${rc}" 1 "malformed --config-file should exit non-zero"
  assert_contains "${out}" "--config-file ${cfg} is malformed" "names the offending file"
  assert_contains "${out}" "cisco_ai_defense_endpoint" \
    "identifies the required field"
}

t_install_config_file_trust_check_fires_on_world_writable() {
  # Managed_enterprise trust contract: --config-file must be
  # non-writable by group/other and root-owned; every ancestor must
  # be too. The trust check runs in install.sh (not installer_lib.sh)
  # under the DC_INSTALLER_SKIP_ROOT_CHECK=0 seam. This test stages a
  # world-writable fixture and asserts the installer dies with a
  # message that names the trust label — proving the check actually
  # fires. Skipping the root check (which would also bypass the
  # trust check) is not used here; we instead assert the trust check
  # dies BEFORE the root check by observing which message appears.
  #
  # Runs as non-root; the trust check will die on the non-root file
  # owner before the euid check gets a chance. That's the exact
  # ordering we want: on a real host, a tampered env_config.json is
  # rejected before ANY installer state mutates.
  if [[ $EUID -eq 0 ]]; then
    [[ "${VERBOSE:-false}" == "true" ]] && printf '  skip (running as root)\n'
    return 0
  fi
  local case_dir; case_dir="$(mktest_tmp)"
  local cfg="${case_dir}/env_config.json"
  printf '{"cisco_ai_defense_endpoint": "https://us.api.inspect.aidefense.security.cisco.com"}\n' >"${cfg}"
  chmod 0666 "${cfg}"
  local out rc=0
  out="$("${INSTALL_SH}" --config-file "${cfg}" 2>&1)" || rc=$?
  assert_status "${rc}" 1 "world-writable env_config.json rejected"
  # The trust label ("AVC env_config.json") appears verbatim in the
  # error message emitted by _assert_trusted_env_config_file_or_die.
  assert_contains "${out}" "AVC env_config.json" "error names the trust label"
}

t_install_default_config_file_path() {
  # Parse install.sh's own defaults directly to catch a silent flip
  # from the AVC-authored path to something else.
  local default
  default="$(grep -E '^DEFAULT_CONFIG_FILE=' "${INSTALL_SH}" | head -1 | cut -d'"' -f2)"
  if [[ -z "${default}" ]]; then
    _fail "could not find DEFAULT_CONFIG_FILE in install.sh"
    return 1
  fi
  assert_eq "${default}" "/opt/cisco/secureclient/defenseclaw/env_config.json" \
    "install.sh DEFAULT_CONFIG_FILE must be the AVC-authored path"
}

t_install_default_mode_is_action() {
  # Managed-enterprise installs default to enforcing (action) mode.
  # This installer only ever writes deployment_mode: managed_enterprise
  # (see installer_lib.sh:render_config), so the default here drives
  # every managed rollout unless the operator explicitly passes
  # --mode observe. A silent flip back to observe would put the whole
  # managed fleet into logging-only mode on the next install run.
  # Unmanaged installers keep observe — see scripts/install.sh and
  # cli/defenseclaw/commands/cmd_quickstart.py; nothing in this test
  # asserts against those.
  local default
  default="$(grep -E '^DEFAULT_MODE=' "${INSTALL_SH}" | head -1 | cut -d'"' -f2)"
  if [[ -z "${default}" ]]; then
    _fail "could not find DEFAULT_MODE in install.sh"
    return 1
  fi
  assert_eq "${default}" "action" "install.sh DEFAULT_MODE must be action for managed_enterprise"
}

t_uninstall_unknown_flag() {
  local out rc=0
  out="$("${UNINSTALL_SH}" --bogus 2>&1)" || rc=$?
  assert_status "${rc}" 1 "uninstall unknown flag exits non-zero"
}

t_uninstall_requires_root() {
  if [[ $EUID -eq 0 ]]; then
    [[ "${VERBOSE:-false}" == "true" ]] && printf '  skip (running as root)\n'
    return 0
  fi
  local out rc=0
  out="$("${UNINSTALL_SH}" 2>&1)" || rc=$?
  assert_status "${rc}" 1 "uninstall non-root exits non-zero"
  assert_contains "${out}" "must run as root" "explains root requirement"
}

run_case "install --help"                 t_install_help
run_case "install --help omits --service-user (root-mode)" t_install_help_omits_service_user
run_case "uninstall --help omits --service-user (root-mode)" t_uninstall_help_omits_service_user
run_case "install --mode garbage"         t_install_bad_mode_exits_nonzero
run_case "install --bogus"                t_install_unknown_flag_exits_nonzero
run_case "install --connector cursor,,X"  t_install_empty_connector_entry_exits_nonzero
run_case "install --port out-of-range"    t_install_bad_port_exits_nonzero
run_case "install unsupported connector"  t_install_warns_unsupported_connector
run_case "install non-root rejected"      t_install_requires_root
run_case "install default redaction on"   t_install_default_redaction_is_on
run_case "install --config-file flag documented"        t_install_help_documents_config_file
run_case "install --env flag removed (replaced by --config-file)" t_install_help_omits_env_flag
run_case "install --override-endpoint documented"        t_install_help_documents_override_endpoint
run_case "install --override-endpoint garbage rejected"  t_install_bad_override_endpoint_exits_nonzero
run_case "install --override-endpoint plaintext http:// rejected" t_install_override_endpoint_rejects_plaintext_http
run_case "install --override-endpoint userinfo rejected"          t_install_override_endpoint_rejects_userinfo
run_case "install --override-endpoint path/query/fragment rejected" t_install_override_endpoint_rejects_path_query_fragment
run_case "install missing --config-file rejected"        t_install_missing_config_file_exits_nonzero
run_case "install malformed --config-file rejected"      t_install_malformed_config_file_exits_nonzero
run_case "install world-writable --config-file rejected" t_install_config_file_trust_check_fires_on_world_writable
run_case "install DEFAULT_CONFIG_FILE=AVC path"          t_install_default_config_file_path
run_case "install DEFAULT_MODE=action (managed_enterprise)" t_install_default_mode_is_action
run_case "uninstall --help"               t_uninstall_help
run_case "uninstall --bogus"              t_uninstall_unknown_flag
run_case "uninstall non-root rejected"    t_uninstall_requires_root
