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
  # Regression: a box with only cursor installed must NOT get target rows
  # for codex or claudecode. Otherwise the guardian churns forever trying
  # to install hooks for a CLI that doesn't exist on the host. See
  # discover_agent_version + render_targets_manifest empty-version skip.
  discover_agent_version() {
    case "$1" in
      cursor) printf '3.14.27' ;;
      *)      printf '' ;;
    esac
  }

  local users="shawnxu:501:20:/Users/shawnxu"
  local out
  out="$(render_targets_manifest "${TEST_SUPPORT}" "codex,claudecode,cursor" "${users}")"

  assert_contains     "${out}" 'connector: "cursor"'     "cursor row emitted"
  assert_not_contains "${out}" 'connector: "codex"'      "codex row skipped (not installed)"
  assert_not_contains "${out}" 'connector: "claudecode"' "claudecode row skipped (not installed)"
  local count
  count="$(printf '%s\n' "${out}" | grep -c "^  - user:" || true)"
  assert_eq "${count}" "1" "one target when only cursor is installed"
}

t_all_connectors_absent_yields_zero_rows() {
  # No connectors installed at all — every row skipped. The manifest is
  # still schema-valid (version + targets:) so the guardian can load it;
  # install.sh's MANIFEST_TARGETS==0 preflight is what turns this into a
  # user-visible die() so an operator isn't left with a silently-empty
  # deployment.
  discover_agent_version() { printf ''; }

  local users="shawnxu:501:20:/Users/shawnxu"
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
run_case "rendered targets.yaml parses (schema round-trip)"     t_rendered_yaml_parses
run_case "rows pin enabled + int uid/gid"                       t_rows_pin_enabled_and_int_uid_gid
run_case "rows omit data_dir (per-user Install default is used)" t_rows_omit_data_dir
run_case "hostile agent version cannot inject targets"          t_hostile_agent_version_cannot_inject_targets
