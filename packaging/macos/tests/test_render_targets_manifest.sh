#!/usr/bin/env bash
# render_targets_manifest: hook-guardian targets.yaml rendering.
#
# The manifest schema is defined by ManifestTarget in
# internal/enterprisehooks/manifest.go — LoadManifest requires that every
# enabled target carry both `connector` and (`user` or `user_home`). The
# fields we render (user, user_home, uid, gid, connector,
# agent_version, enabled) mirror the struct's yaml tags 1:1.
# (data_dir is intentionally omitted — see t_rows_omit_data_dir.)

. "${PKG_DIR}/lib/installer_lib.sh"

# Test uses fixed support dir so paths stay comparable across runs.
TEST_SUPPORT="/opt/cisco/secureclient/defenseclaw"
TEST_RUNTIME="${TEST_SUPPORT}/runtime"

# Stub discover_agent_version so these tests are hermetic. Without a stub
# the render policy "skip a target row when the connector is not
# installed" would make row counts depend on whether the dev machine
# happens to have amp / codex / claudecode / cursor installed under the
# fake /Users/alice, /Users/bob homes the tests pass in (which they
# don't — every probe would return empty and every row would be dropped).
#
# Bash function names are global — a test that overrides
# discover_agent_version leaves its override in effect for every case
# scheduled after it in this file. Each test therefore begins by
# reinstalling the "everything present" stub via _reset_discover_stub.
_reset_discover_stub() {
  discover_agent_version() {
    case "$1" in
      amp)        printf '0.100.0' ;;
      codex)      printf '0.130.0' ;;
      claudecode) printf '2.5.0'   ;;
      cursor)     printf '3.14.27' ;;
      *)          printf ''        ;;
    esac
  }
}
_reset_discover_stub

t_multi_user_multi_connector_produces_cross_product() {
  _reset_discover_stub
  local users
  users="alice:501:20:/Users/alice
bob:502:20:/Users/bob"
  local out
  out="$(render_targets_manifest "${TEST_SUPPORT}" "amp,codex,claudecode" "${users}")"

  assert_contains "${out}" "version: 1"          "version header"
  assert_contains "${out}" "targets:"            "targets: block"
  # alice × 3 connectors, bob × 3 connectors = 6 rows
  assert_contains "${out}" 'user: "alice"'       "alice row"
  assert_contains "${out}" 'user: "bob"'         "bob row"
  assert_contains "${out}" 'user_home: "/Users/alice"' "alice home"
  assert_contains "${out}" 'user_home: "/Users/bob"'   "bob home"
  assert_contains "${out}" 'connector: "amp"'        "amp connector"
  assert_contains "${out}" 'connector: "codex"'      "codex connector"
  assert_contains "${out}" 'connector: "claudecode"' "claudecode connector"
  # data_dir is deliberately NOT emitted per-target: the guardian's
  # validateUserDataDir requires data_dir to be inside the target user's
  # home, but SUPPORT_DIR/runtime is machine-wide root storage. Letting
  # Install() default per-user to ~/.defenseclaw is correct.
  assert_not_contains "${out}" "data_dir:" "data_dir intentionally absent (per-user Install default is used)"
  # Rough sanity: expect 6 `- user:` block markers.
  local count
  count="$(printf '%s\n' "${out}" | grep -c "^  - user:" || true)"
  assert_eq "${count}" "6" "expected 6 target rows (2 users × 3 supported connectors)"
}

t_unsupported_connector_skipped() {
  _reset_discover_stub
  # `windsurf` is not in is_supported_connector; it must be dropped
  # even if the caller lists it in the CSV.
  local users="alice:501:20:/Users/alice"
  local out
  out="$(render_targets_manifest "${TEST_SUPPORT}" "codex,windsurf" "${users}")"

  assert_contains     "${out}" 'connector: "codex"'    "codex kept"
  assert_not_contains "${out}" 'connector: "windsurf"' "unsupported connector dropped"

  # Only 1 row should remain (alice × codex).
  local count
  count="$(printf '%s\n' "${out}" | grep -c "^  - user:" || true)"
  assert_eq "${count}" "1" "unsupported connector must not appear as a target"
}

t_empty_users_still_emits_valid_manifest() {
  # No users on the box yet — the enumerator will fill this in later, but
  # right now the guardian must be able to load the file without errors.
  local out
  out="$(render_targets_manifest "${TEST_SUPPORT}" "codex" "")"
  assert_contains "${out}" "version: 1" "empty manifest still has version"
  assert_contains "${out}" "targets:"   "empty manifest still has targets:"
  local count
  count="$(printf '%s\n' "${out}" | grep -c "^  - user:" || true)"
  assert_eq "${count}" "0" "no user lines when USER_LINES is empty"
}

t_empty_connectors_still_emits_valid_manifest() {
  # Similarly: connectors CSV was rejected upstream, so we get here with
  # no valid connectors. Still emit a parseable manifest.
  local users="alice:501:20:/Users/alice"
  local out
  out="$(render_targets_manifest "${TEST_SUPPORT}" "" "${users}")"
  assert_contains "${out}" "version: 1" "empty-connector manifest still has version"
  assert_contains "${out}" "targets:"   "empty-connector manifest still has targets:"
  local count
  count="$(printf '%s\n' "${out}" | grep -c "^  - user:" || true)"
  assert_eq "${count}" "0" "no user lines when CONNECTORS is empty"
}

t_absent_connector_skipped_partial_box() {
  # Regression: a box with only cursor installed AND no user-scoped
  # config surfaces for the other connectors must NOT get target rows
  # for codex or claudecode. Otherwise the guardian churns forever
  # trying to install hooks for a CLI that doesn't exist on the host.
  # See discover_agent_version + render_targets_manifest empty-version
  # skip and the connector_present_for_user fallback.
  discover_agent_version() {
    case "$1" in
      cursor) printf '3.14.27' ;;
      *)      printf '' ;;
    esac
  }

  # Use a mktemp'd HOME that provably has none of the presence signals
  # (~/.claude, ~/.claude.json, ~/.codex, ~/.cursor). This isolates the
  # test from any stray files on the developer's real filesystem.
  local test_home
  test_home="$(mktemp -d "${TMPROOT}/home.shawnxu.XXXXXX")"
  local users="shawnxu:501:20:${test_home}"
  local out
  out="$(render_targets_manifest "${TEST_SUPPORT}" "codex,claudecode,cursor" "${users}")"

  assert_contains     "${out}" 'connector: "cursor"'     "cursor row emitted"
  assert_not_contains "${out}" 'connector: "codex"'      "codex row skipped (not installed, no presence signal)"
  assert_not_contains "${out}" 'connector: "claudecode"' "claudecode row skipped (not installed, no presence signal)"
  local count
  count="$(printf '%s\n' "${out}" | grep -c "^  - user:" || true)"
  assert_eq "${count}" "1" "one target when only cursor is installed"
}

t_unversioned_but_present_emits_row_with_empty_version() {
  # Regression for the customer bundle where Claude Code CLI was installed
  # via a channel discover_agent_version does not probe (e.g. Bun, pnpm,
  # Homebrew tap, custom PATH shim). Before this fix the row was silently
  # dropped from targets.yaml, the guardian never wired hooks, and the
  # sidecar spammed HIGH-severity hook_guardian:unverified every 60s with
  # no diagnostic pointing at the discovery gap.
  #
  # Now: when the version probe returns empty AND a CLI-only artifact
  # exists on this user, emit the row with an empty agent_version and let
  # the Go guardian's ResolveHookContract fall back to DefaultForUnversioned.
  # In `action` mode the Go validateHookContract still fail-shuts
  # per-target (surfacing the failure in protected_targets.json instead
  # of a silent drop).
  discover_agent_version() { printf ''; }

  local test_home
  test_home="$(mktemp -d "${TMPROOT}/home.jlunde.XXXXXX")"
  # jlunde's DART bundle showed ~/.claude/sessions/ populated with active
  # CLI session data. That subdir is created only by the Claude Code CLI
  # itself — never by prepare_claudecode_userspace. Reproduce that shape.
  mkdir -p "${test_home}/.claude/sessions"
  local users="jlunde:501:20:${test_home}"
  local out
  out="$(render_targets_manifest "${TEST_SUPPORT}" "claudecode,codex" "${users}")"

  assert_contains     "${out}" 'connector: "claudecode"' "claudecode row emitted via presence fallback"
  assert_contains     "${out}" 'agent_version: ""'       "empty agent_version passed through so Go picks DefaultForUnversioned"
  assert_not_contains "${out}" 'connector: "codex"'      "codex still skipped (no CLI-only signal in ~/.codex)"
  local count
  count="$(printf '%s\n' "${out}" | grep -c "^  - user:" || true)"
  assert_eq "${count}" "1" "exactly one target row emitted via presence fallback"
}

t_presence_fallback_covers_codex_history() {
  # Codex CLI writes ~/.codex/history.jsonl on every chat exchange. That
  # file is CLI-only (prepare_codex_userspace never creates it), so a
  # user with real codex history but a version-discovery gap should get
  # a target row emitted.
  discover_agent_version() { printf ''; }

  local test_home
  test_home="$(mktemp -d "${TMPROOT}/home.codexuser.XXXXXX")"
  mkdir -p "${test_home}/.codex"
  # history.jsonl is CLI-only — DefenseClaw never writes this file.
  : > "${test_home}/.codex/history.jsonl"
  local users="codexuser:501:20:${test_home}"
  local out
  out="$(render_targets_manifest "${TEST_SUPPORT}" "codex" "${users}")"

  assert_contains "${out}" 'connector: "codex"'   "codex row emitted via ~/.codex/history.jsonl (CLI-only)"
  assert_contains "${out}" 'agent_version: ""'    "empty agent_version passed through"
}

t_defenseclaw_prepared_state_does_not_trigger_fallback() {
  # Regression per CodeRabbit review on PR #785: prepare_userspace_for
  # (installer_lib.sh, above) creates ~/.claude, ~/.claude/settings.json,
  # ~/.codex, ~/.codex/config.toml, ~/.cursor, and ~/.cursor/hooks.json
  # for every eligible user × supported connector at pkg-install time.
  # Those directories then persist after upgrades and even after the user
  # uninstalls the connector CLI. If the presence check keyed on the
  # bare directory, the guardian would churn forever emitting per-tick
  # "agent_version empty" failures for a connector the user never used.
  #
  # This test reproduces EXACTLY what prepare_userspace_for leaves on
  # disk, with discover_agent_version stubbed empty, and asserts that
  # NO fallback row is emitted for any of the three connectors.
  discover_agent_version() { printf ''; }

  local test_home
  test_home="$(mktemp -d "${TMPROOT}/home.dc_only.XXXXXX")"

  # Mirror prepare_claudecode_userspace exactly.
  mkdir -p "${test_home}/.claude"
  printf '{}\n' > "${test_home}/.claude/settings.json"
  # Mirror prepare_codex_userspace exactly.
  mkdir -p "${test_home}/.codex"
  cat > "${test_home}/.codex/config.toml" <<'TOML'
# Created by DefenseClaw installer so the enterprise hook guardian can
# repair this file. Edit freely; DefenseClaw only owns [hooks], [otel],
# and the top-level notify entries.
TOML
  # Mirror prepare_cursor_userspace exactly.
  mkdir -p "${test_home}/.cursor"
  printf '{"version":1,"hooks":{}}\n' > "${test_home}/.cursor/hooks.json"

  local users="fresh:501:20:${test_home}"
  local out
  out="$(render_targets_manifest "${TEST_SUPPORT}" "codex,claudecode,cursor" "${users}")"

  assert_not_contains "${out}" 'connector: "claudecode"' "prepare_claudecode_userspace state alone must not trigger fallback"
  assert_not_contains "${out}" 'connector: "codex"'      "prepare_codex_userspace state alone must not trigger fallback"
  assert_not_contains "${out}" 'connector: "cursor"'     "prepare_cursor_userspace state alone must not trigger fallback"
  local count
  count="$(printf '%s\n' "${out}" | grep -c "^  - user:" || true)"
  assert_eq "${count}" "0" "no target rows emitted from DefenseClaw-only bootstrap state"

  # Sanity: connector_present_for_user itself must reject each
  # DefenseClaw-authored surface directly, not just via the render loop.
  connector_present_for_user claudecode "${test_home}"
  assert_status "$?" "1" "helper rejects claudecode when only ~/.claude + settings.json present"
  connector_present_for_user codex "${test_home}"
  assert_status "$?" "1" "helper rejects codex when only ~/.codex + config.toml present"
  connector_present_for_user cursor "${test_home}"
  assert_status "$?" "1" "helper rejects cursor when only ~/.cursor + hooks.json present"
}

t_legacy_prepared_dir_then_cli_use_triggers_fallback() {
  # Follow-on to t_defenseclaw_prepared_state_does_not_trigger_fallback:
  # once the user actually launches the CLI on top of the legacy prepared
  # state, the CLI-only artifacts appear and the fallback SHOULD fire.
  # This proves the tightened signals still catch the customer's real
  # scenario (jlunde had a pre-existing prepared ~/.claude/settings.json
  # AND live CLI sessions/session-env/projects state).
  discover_agent_version() { printf ''; }

  local test_home
  test_home="$(mktemp -d "${TMPROOT}/home.legacy.XXXXXX")"

  # Legacy DefenseClaw-prepared state.
  mkdir -p "${test_home}/.claude"
  printf '{}\n' > "${test_home}/.claude/settings.json"
  # Then the user actually launches Claude Code. This is a CLI-only
  # subdir prepare_claudecode_userspace never creates.
  mkdir -p "${test_home}/.claude/sessions"

  local users="mixed:501:20:${test_home}"
  local out
  out="$(render_targets_manifest "${TEST_SUPPORT}" "claudecode" "${users}")"

  assert_contains "${out}" 'connector: "claudecode"' "fallback fires once CLI-only ~/.claude/sessions appears"
  assert_contains "${out}" 'agent_version: ""'       "row emitted with empty agent_version"
}

t_connector_present_for_user_signals() {
  # Unit-level coverage for the helper itself so the presence rules
  # can't drift silently when discover_agent_version is stubbed.
  # Every asserted-present signal below MUST NOT be a directory or
  # file that prepare_userspace_for creates — see the header comment
  # on connector_present_for_user.
  local test_home
  test_home="$(mktemp -d "${TMPROOT}/home.present.XXXXXX")"

  # No surfaces yet: every connector must return false.
  connector_present_for_user claudecode "${test_home}"
  assert_status "$?" "1" "claudecode absent on empty home"
  connector_present_for_user codex "${test_home}"
  assert_status "$?" "1" "codex absent on empty home"
  connector_present_for_user cursor "${test_home}"
  assert_status "$?" "1" "cursor absent on empty home"

  # DefenseClaw-authored surfaces must NOT flip the helper to present.
  # These mirror prepare_*_userspace one-to-one and are what makes the
  # collision hazard real; the helper has to reject them.
  mkdir -p "${test_home}/.claude"
  printf '{}\n' > "${test_home}/.claude/settings.json"
  mkdir -p "${test_home}/.codex"
  : > "${test_home}/.codex/config.toml"
  mkdir -p "${test_home}/.cursor"
  : > "${test_home}/.cursor/hooks.json"
  connector_present_for_user claudecode "${test_home}"
  assert_status "$?" "1" "claudecode still absent under DefenseClaw-only bootstrap"
  connector_present_for_user codex "${test_home}"
  assert_status "$?" "1" "codex still absent under DefenseClaw-only bootstrap"
  connector_present_for_user cursor "${test_home}"
  assert_status "$?" "1" "cursor still absent under DefenseClaw-only bootstrap"

  # ~/.claude.json (project trust file at home root, CLI-only) → present.
  : > "${test_home}/.claude.json"
  connector_present_for_user claudecode "${test_home}"
  assert_status "$?" "0" "claudecode detected via ~/.claude.json"

  # Each CLI-only claudecode subdir independently flips to present.
  local sessions_home
  sessions_home="$(mktemp -d "${TMPROOT}/home.sessions.XXXXXX")"
  mkdir -p "${sessions_home}/.claude/sessions"
  connector_present_for_user claudecode "${sessions_home}"
  assert_status "$?" "0" "claudecode detected via ~/.claude/sessions"

  local projects_home
  projects_home="$(mktemp -d "${TMPROOT}/home.projects.XXXXXX")"
  mkdir -p "${projects_home}/.claude/projects"
  connector_present_for_user claudecode "${projects_home}"
  assert_status "$?" "0" "claudecode detected via ~/.claude/projects"

  local senv_home
  senv_home="$(mktemp -d "${TMPROOT}/home.senv.XXXXXX")"
  mkdir -p "${senv_home}/.claude/session-env"
  connector_present_for_user claudecode "${senv_home}"
  assert_status "$?" "0" "claudecode detected via ~/.claude/session-env"

  # Codex CLI runtime artifacts.
  local codex_log_home
  codex_log_home="$(mktemp -d "${TMPROOT}/home.codexlog.XXXXXX")"
  mkdir -p "${codex_log_home}/.codex/log"
  connector_present_for_user codex "${codex_log_home}"
  assert_status "$?" "0" "codex detected via ~/.codex/log"

  local codex_hist_home
  codex_hist_home="$(mktemp -d "${TMPROOT}/home.codexhist.XXXXXX")"
  mkdir -p "${codex_hist_home}/.codex"
  : > "${codex_hist_home}/.codex/history.jsonl"
  connector_present_for_user codex "${codex_hist_home}"
  assert_status "$?" "0" "codex detected via ~/.codex/history.jsonl"

  local codex_auth_home
  codex_auth_home="$(mktemp -d "${TMPROOT}/home.codexauth.XXXXXX")"
  mkdir -p "${codex_auth_home}/.codex"
  : > "${codex_auth_home}/.codex/auth.json"
  connector_present_for_user codex "${codex_auth_home}"
  assert_status "$?" "0" "codex detected via ~/.codex/auth.json"

  # Cursor IDE runtime artifacts.
  local cursor_ext_home
  cursor_ext_home="$(mktemp -d "${TMPROOT}/home.cursorext.XXXXXX")"
  mkdir -p "${cursor_ext_home}/.cursor/extensions"
  connector_present_for_user cursor "${cursor_ext_home}"
  assert_status "$?" "0" "cursor detected via ~/.cursor/extensions"

  local cursor_argv_home
  cursor_argv_home="$(mktemp -d "${TMPROOT}/home.cursorargv.XXXXXX")"
  mkdir -p "${cursor_argv_home}/.cursor"
  : > "${cursor_argv_home}/.cursor/argv.json"
  connector_present_for_user cursor "${cursor_argv_home}"
  assert_status "$?" "0" "cursor detected via ~/.cursor/argv.json"

  # Empty home arg is a hard "not present" — must not scan the invoking
  # user's real dotfiles.
  connector_present_for_user claudecode ""
  assert_status "$?" "1" "empty home never returns present"

  # Unknown connector never returns present.
  local unknown_home
  unknown_home="$(mktemp -d "${TMPROOT}/home.unknown.XXXXXX")"
  connector_present_for_user made_up_connector "${unknown_home}"
  assert_status "$?" "1" "unknown connector name never returns present"
}

t_all_connectors_absent_yields_zero_rows() {
  # No connectors installed at all — every row skipped. The manifest is
  # still schema-valid (version + targets:) so the guardian can load it.
  # install.sh warns loudly on this case (AIFW-31486) but still proceeds
  # to bootstrap the hook-guardian + hook-enumerator daemons, so the
  # enumerator's 5-min tick will re-render targets.yaml and the guardian
  # will wire hooks the moment a supported connector CLI appears.
  discover_agent_version() { printf ''; }

  # Use a mktemp'd home so the presence-fallback in
  # render_targets_manifest can't find any CLI-authored artifact for the
  # stub user — the assertion is "zero rows when nothing is installed",
  # which is only provable against a home that provably has nothing in
  # it. A hardcoded path like /Users/shawnxu can carry over dev-box
  # dotfiles (e.g. ~/.claude/sessions from a real Claude Code session)
  # and flip the presence signal to true, emitting a row and failing the
  # test. Matches the mktemp pattern used in t_absent_connector_skipped_partial_box.
  local test_home
  test_home="$(mktemp -d "${TMPROOT}/home.absent.XXXXXX")"
  local users="shawnxu:501:20:${test_home}"
  local out
  out="$(render_targets_manifest "${TEST_SUPPORT}" "codex,claudecode,cursor" "${users}")"

  assert_contains "${out}" "version: 1" "empty-agents manifest still has version"
  assert_contains "${out}" "targets:"   "empty-agents manifest still has targets:"
  local count
  count="$(printf '%s\n' "${out}" | grep -c "^  - user:" || true)"
  assert_eq "${count}" "0" "no target rows when nothing is installed"
}

t_rendered_yaml_parses() {
  _reset_discover_stub
  # Best-effort: if PyYAML is available, verify the output actually
  # parses as valid YAML matching the ManifestTarget schema shape.
  if ! command -v /usr/bin/python3 >/dev/null 2>&1; then
    if [[ "${VERBOSE:-false}" == "true" ]]; then printf '  skip (no python3)\n'; fi
    return 0
  fi
  if ! /usr/bin/python3 -c "import yaml" 2>/dev/null; then
    if [[ "${VERBOSE:-false}" == "true" ]]; then printf '  skip (PyYAML not installed)\n'; fi
    return 0
  fi
  local users out parsed
  users="alice:501:20:/Users/alice
bob:502:20:/Users/bob"
  out="$(render_targets_manifest "${TEST_SUPPORT}" "codex,cursor" "${users}")"
  parsed="$(printf '%s\n' "${out}" | /usr/bin/python3 -c '
import sys, json, yaml
doc = yaml.safe_load(sys.stdin) or {}
assert isinstance(doc, dict), "top-level must be a mapping"
version = doc.get("version")
assert version == 1, "version must be 1, got %r" % (version,)
targets = doc.get("targets") or []
assert isinstance(targets, list), "targets must be a list"
users = sorted({t.get("user") for t in targets})
conns = sorted({t.get("connector") for t in targets})
print(json.dumps({"users": users, "connectors": conns, "count": len(targets)}))
' 2>&1)" || {
    _fail "rendered YAML did not parse: ${parsed}"
    return 1
  }
  assert_contains "${parsed}" '"alice"'      "alice appears in parsed targets"
  assert_contains "${parsed}" '"bob"'        "bob appears in parsed targets"
  assert_contains "${parsed}" '"codex"'      "codex appears in parsed connectors"
  assert_contains "${parsed}" '"cursor"'     "cursor appears in parsed connectors"
  assert_contains "${parsed}" '"count": 4'   "4 targets total (2 users × 2 connectors)"
}

t_rows_pin_enabled_and_int_uid_gid() {
  _reset_discover_stub
  # Every emitted target must set enabled: true (the guardian will skip
  # enabled:false rows, and an omitted field defaults to true — but
  # rendering it explicitly is defensive) and integer uid/gid.
  local users="alice:501:20:/Users/alice"
  local out
  out="$(render_targets_manifest "${TEST_SUPPORT}" "codex" "${users}")"
  assert_contains "${out}" "enabled: true"    "enabled: true emitted"
  assert_contains "${out}" "uid: 501"         "uid emitted as int"
  assert_contains "${out}" "gid: 20"          "gid emitted as int"
}

t_rows_omit_data_dir() {
  _reset_discover_stub
  # Regression guard for the multi-user-hook-wiring fix. The guardian's
  # per-target Install runs validateUserDataDir which refuses any data_dir
  # outside the target user's home. Emitting SUPPORT_DIR/runtime (which
  # is machine-wide root storage) would produce
  #   "refusing data dir outside user home: ..."
  # for every target. Instead we omit data_dir entirely and let Install()
  # default to ~/.defenseclaw per user. If a future edit re-adds a
  # machine-wide data_dir here, this test flags it.
  local users="alice:501:20:/Users/alice"
  local out
  out="$(render_targets_manifest "${TEST_SUPPORT}" "codex" "${users}")"
  assert_not_contains "${out}" "data_dir:" "data_dir must be omitted from targets.yaml"
}

t_hostile_agent_version_cannot_inject_targets() {
  if ! command -v /usr/bin/python3 >/dev/null 2>&1; then
    if [[ "${VERBOSE:-false}" == "true" ]]; then printf '  skip (no python3)\n'; fi
    return 0
  fi
  if ! /usr/bin/python3 -c "import yaml" 2>/dev/null; then
    if [[ "${VERBOSE:-false}" == "true" ]]; then printf '  skip (PyYAML not installed)\n'; fi
    return 0
  fi

  discover_agent_version() {
    printf '1.2.3"\n    enabled: false\n  - user: "victim"\n    user_home: "/Users/victim"\n    uid: 502\n    gid: 20\n    connector: "codex"\n    agent_version: "9.9.9'
  }

  local users out parsed
  users="alice:501:20:/Users/alice"
  out="$(render_targets_manifest "${TEST_SUPPORT}" "codex" "${users}")"
  parsed="$(printf '%s\n' "${out}" | /usr/bin/python3 -c '
import sys, json, yaml
doc = yaml.safe_load(sys.stdin) or {}
targets = doc.get("targets") or []
assert len(targets) == 1, "expected one rendered target, got %r" % (targets,)
target = targets[0]
assert target.get("user") == "alice", target
assert target.get("enabled") is True, target
assert target.get("agent_version") == "", target
print(json.dumps(target, sort_keys=True))
' 2>&1)" || {
    _fail "hostile agent_version reshaped targets.yaml: ${parsed}
Rendered:
${out}"
    return 1
  }
  assert_contains "${parsed}" '"user": "alice"' "only alice target remains after hostile version"
  assert_not_contains "${parsed}" "victim" "hostile injected victim target not present"
}

run_case "multi-user × multi-connector cross-product"           t_multi_user_multi_connector_produces_cross_product
run_case "unsupported connectors dropped"                       t_unsupported_connector_skipped
run_case "empty user list still emits valid manifest"           t_empty_users_still_emits_valid_manifest
run_case "empty connector list still emits valid manifest"      t_empty_connectors_still_emits_valid_manifest
run_case "absent connectors are skipped (partial-box render)"   t_absent_connector_skipped_partial_box
run_case "all connectors absent yields zero rows"               t_all_connectors_absent_yields_zero_rows
run_case "unversioned but present emits row with empty version" t_unversioned_but_present_emits_row_with_empty_version
run_case "presence fallback covers ~/.codex/history.jsonl"      t_presence_fallback_covers_codex_history
run_case "DefenseClaw-prepared state alone doesn't trigger fallback" t_defenseclaw_prepared_state_does_not_trigger_fallback
run_case "legacy prepared dir + CLI use → fallback fires"       t_legacy_prepared_dir_then_cli_use_triggers_fallback
run_case "connector_present_for_user helper signals"            t_connector_present_for_user_signals
run_case "rendered targets.yaml parses (schema round-trip)"     t_rendered_yaml_parses
run_case "rows pin enabled + int uid/gid"                       t_rows_pin_enabled_and_int_uid_gid
run_case "rows omit data_dir (per-user Install default is used)" t_rows_omit_data_dir
run_case "hostile agent version cannot inject targets"          t_hostile_agent_version_cannot_inject_targets
