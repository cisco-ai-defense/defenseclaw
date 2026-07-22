#!/usr/bin/env bash
# render_config: single vs multi-connector YAML output.
. "${PKG_DIR}/lib/installer_lib.sh"

# Fixed prod endpoint for tests that don't care about --env resolution.
# t_aid_endpoint_env_selection covers preview/prod switching.
TEST_AID_ENDPOINT_PROD="https://us.api.inspect.aidefense.security.cisco.com"
TEST_AID_ENDPOINT_PREVIEW="https://preview.api.inspect.aidefense.aiteam.cisco.com"

t_single_connector() {
  local out
  out="$(render_config action cursor 18970 false "/opt/cisco/secureclient/defenseclaw" "${TEST_AID_ENDPOINT_PROD}" cursor)"

  assert_contains "${out}" "config_version: 6"                  "config_version present"
  assert_contains "${out}" "deployment_mode: managed_enterprise" "managed_enterprise mode"
  assert_contains "${out}" "data_dir: \"/opt/cisco/secureclient/defenseclaw/runtime\"" "data_dir points at runtime subdir (matches docs-site/setup/enterprise-deployment.mdx)"
  assert_contains "${out}" "audit_db: \"/opt/cisco/secureclient/defenseclaw/runtime/audit.db\"" "audit_db under runtime"
  assert_contains "${out}" "judge_bodies_db: \"/opt/cisco/secureclient/defenseclaw/runtime/judge_bodies.db\"" "judge_bodies_db under runtime"
  assert_contains "${out}" "api_port: 18970"                    "api_port"
  assert_contains "${out}" "disable_redaction: false"           "redaction disabled flag"
  assert_contains "${out}" "mode: action"                       "guardrail mode"
  assert_contains "${out}" "scanner_mode: both"                 "scanner_mode"
  assert_contains "${out}" "connector: cursor"                  "primary connector"
  assert_not_contains "${out}" "  connectors:"                  "no multi-connector map when single"
  # Managed_enterprise rollout posture: only AID cloud + local regex
  # contribute verdicts. asset_policy is disabled at the config
  # surface, the watcher/component scanner is off, the judge is off,
  # and detection_strategy pins regex_only so nothing tries to route
  # findings through an LLM.
  assert_contains     "${out}" "asset_policy:"                   "asset_policy block present"
  assert_not_contains "${out}" "mcp:"                            "no asset_policy mcp sub-block (asset_policy disabled)"
  assert_not_contains "${out}" "default: deny"                   "no default: deny (asset_policy disabled)"
  assert_contains     "${out}" "watcher:"                        "gateway.watcher block present"
  assert_contains     "${out}" "detection_strategy: regex_only"  "regex_only detection strategy"
  assert_contains     "${out}" "judge:"                          "judge block present"
  assert_contains     "${out}" "application_protection:"         "application_protection block"
}

t_multi_connector() {
  local out
  out="$(render_config observe cursor 18970 true "/opt/cisco/secureclient/defenseclaw" "${TEST_AID_ENDPOINT_PROD}" cursor claudecode codex)"

  assert_contains "${out}" "connector: cursor"        "primary is first arg"
  assert_contains "${out}" "  connectors:"            "multi-connector map present"
  assert_contains "${out}" "    cursor:"              "cursor entry under connectors"
  assert_contains "${out}" "    claudecode:"          "claudecode entry under connectors"
  assert_contains "${out}" "    codex:"               "codex entry under connectors"
  assert_contains "${out}" "disable_redaction: true"  "redaction explicit opt-out"
  assert_contains "${out}" "mode: observe"            "observe mode"
}

t_runtime_paths_disjoint_from_config_parent() {
  # Regression guard: managed_enterprise trust check walks every ancestor
  # of config.yaml and requires each to be root-owned with no group/other
  # write bits. data_dir cannot be the same dir that holds config.yaml,
  # because install.sh needs to chown data_dir to the service user for
  # writes. Assert the renderer places data_dir strictly BELOW the
  # support dir, matching the docs-site recommendation.
  local out support runtime
  support="/opt/cisco/secureclient/defenseclaw"
  runtime="${support}/runtime"
  out="$(render_config observe cursor 18970 false "${support}" "${TEST_AID_ENDPOINT_PROD}" cursor)"
  assert_contains     "${out}" "data_dir: \"${runtime}\"" "data_dir under support"
  assert_not_contains "${out}" "data_dir: \"${support}\"" "data_dir MUST NOT equal support dir (trust check fails)"
}

t_device_key_file_under_runtime_dir() {
  # Regression guard: on macOS, the plist sets DEFENSECLAW_HOME to
  # SUPPORT_DIR so the managed_enterprise trust check accepts every
  # ancestor of config.yaml. But SUPPORT_DIR itself is root:defenseclaw
  # 0750 — no group write — so the daemon (running as defenseclaw)
  # cannot create files there. If the config leaves gateway.device_key_file
  # unset, Go defaults compute it as \${DEFENSECLAW_HOME}/device.key,
  # which points at SUPPORT_DIR and the first-boot write crashes with
  # "permission denied". The renderer MUST explicitly pin it into
  # RUNTIME_DIR so that first-boot write lands in the service-user-owned
  # subdirectory.
  local out support runtime
  support="/opt/cisco/secureclient/defenseclaw"
  runtime="${support}/runtime"
  out="$(render_config observe cursor 18970 false "${support}" "${TEST_AID_ENDPOINT_PROD}" cursor)"
  assert_contains     "${out}" "device_key_file: \"${runtime}/device.key\"" "device_key_file under runtime dir"
  assert_not_contains "${out}" "device_key_file: \"${support}/device.key\"" "device_key_file MUST NOT land in SUPPORT_DIR (no group-write there)"
}

t_redaction_pass_through_on() {
  # Pure rendering check: given "false", the block emits redaction on.
  # This proves the rendering layer respects the caller's choice; the
  # install.sh default-arg-parsing contract is asserted in
  # test_arg_parsing.sh::t_install_default_redaction_is_on so we don't
  # duplicate the "what's the default" check at two layers.
  local out
  out="$(render_config observe codex 18970 false "/var/lib/dc" "${TEST_AID_ENDPOINT_PROD}" codex)"
  assert_contains "${out}" "disable_redaction: false" "renderer emits redaction ON when false is passed"
}

t_redaction_pass_through_off() {
  local out
  out="$(render_config action codex 18970 true "/var/lib/dc" "${TEST_AID_ENDPOINT_PROD}" codex)"
  assert_contains "${out}" "disable_redaction: true" "renderer emits redaction OFF when true is passed"
}

t_yaml_parses() {
  # Best-effort: if python3 + a yaml module exist, parse the output to
  # catch indentation regressions.
  if ! command -v /usr/bin/python3 >/dev/null 2>&1; then
    if [[ "${VERBOSE:-false}" == "true" ]]; then printf '  skip (no python3)\n'; fi
    return 0
  fi
  if ! /usr/bin/python3 -c "import yaml" 2>/dev/null; then
    if [[ "${VERBOSE:-false}" == "true" ]]; then printf '  skip (PyYAML not installed)\n'; fi
    return 0
  fi
  local out parsed
  out="$(render_config action cursor 18970 false "/opt/cisco/secureclient/defenseclaw" "${TEST_AID_ENDPOINT_PROD}" cursor claudecode)"
  parsed="$(printf '%s\n' "${out}" | /usr/bin/python3 -c 'import sys,yaml,json; print(json.dumps(yaml.safe_load(sys.stdin)))' 2>&1)" || {
    _fail "rendered YAML did not parse: ${parsed}"
    return 1
  }
  assert_contains "${parsed}" '"deployment_mode": "managed_enterprise"' "parsed yaml has managed_enterprise"
  assert_contains "${parsed}" '"connector": "cursor"' "parsed yaml has primary connector"
  assert_contains "${parsed}" '"connectors":' "parsed yaml has connectors map"
}

t_cisco_ai_defense_block_emitted() {
  # The managed CMID inspection client refuses to construct when
  # cisco_ai_defense.endpoint is empty. Guard the invariant that
  # render_config emits the block with a non-empty endpoint.
  local out
  out="$(render_config action cursor 18970 false "/opt/cisco/secureclient/defenseclaw" "${TEST_AID_ENDPOINT_PREVIEW}" cursor)"
  assert_contains "${out}" "cisco_ai_defense:"                             "cisco_ai_defense: block present"
  assert_contains "${out}" "endpoint: \"${TEST_AID_ENDPOINT_PREVIEW}\""    "endpoint value threaded through"
}

t_read_json_field_semantics() {
  # _read_json_field is the pure-function reader the resolver leans on
  # for the AVC-authored env_config.json. Assert the field-name-driven
  # semantics: valid field → value, missing field → empty, malformed
  # JSON → empty, missing file → empty, non-string value → empty.
  local case_dir; case_dir="$(mktest_tmp)"
  local cfg="${case_dir}/env_config.json"

  # Valid string field.
  printf '{"cisco_ai_defense_endpoint": "https://us.api.inspect.aidefense.security.cisco.com"}\n' >"${cfg}"
  local got
  got="$(_read_json_field "${cfg}" cisco_ai_defense_endpoint)"
  assert_eq "${got}" "https://us.api.inspect.aidefense.security.cisco.com" \
    "reads a top-level string field"

  # Missing field → empty (rc still 0; callers gate on empty).
  got="$(_read_json_field "${cfg}" other_key)"
  assert_eq "${got}" "" "missing field returns empty"

  # Malformed JSON → empty.
  printf '{malformed' >"${cfg}"
  got="$(_read_json_field "${cfg}" cisco_ai_defense_endpoint)"
  assert_eq "${got}" "" "malformed JSON returns empty"

  # Missing file → empty.
  got="$(_read_json_field "${case_dir}/does-not-exist.json" cisco_ai_defense_endpoint)"
  assert_eq "${got}" "" "missing file returns empty"

  # Non-string value (number) → empty.
  printf '{"cisco_ai_defense_endpoint": 42}\n' >"${cfg}"
  got="$(_read_json_field "${cfg}" cisco_ai_defense_endpoint)"
  assert_eq "${got}" "" "non-string field value returns empty"
}

t_otel_block_enabled_for_managed_sink() {
  # render_config must emit an otel block with enabled: true so the managed
  # Cisco AI Defense log sink is active on a fresh install. The sink itself is
  # gated on managed_enterprise + cisco_ai_defense.endpoint (no user
  # destination required — see config.hasManagedAIDLogSink), so no
  # otel.destinations[] entry is rendered.
  local out
  out="$(render_config action cursor 18970 false "/opt/cisco/secureclient/defenseclaw" "${TEST_AID_ENDPOINT_PROD}" cursor)"
  assert_contains     "${out}" "$(printf 'otel:\n  enabled: true')" "otel block enables telemetry"
  assert_not_contains "${out}" "destinations:"                       "no user otel destinations rendered"
}

t_ai_discovery_enabled_for_endpoint_inventory() {
  # render_config must emit an ai_discovery block with enabled: true so the
  # continuous discovery scanner runs and ships the endpoint inventory to AI
  # Defense as discovery events over the managed AID log sink. Without this the
  # scanner is a no-op (NewContinuousDiscoveryService returns nil when
  # ai_discovery.enabled is false) and no inventory flows.
  local out
  out="$(render_config action cursor 18970 false "/opt/cisco/secureclient/defenseclaw" "${TEST_AID_ENDPOINT_PROD}" cursor)"
  assert_contains "${out}" "$(printf 'ai_discovery:\n  enabled: true')" "ai_discovery block enables the inventory scanner"
}

t_resolve_aid_endpoint_precedence() {
  # resolve_aid_endpoint now takes (OVERRIDE, CONFIG_FILE) and reads
  # the AI Defense endpoint from the AVC-authored env_config.json.
  # --override-endpoint (arg 1) wins over the file (arg 2). Distinct
  # return codes let callers emit per-source errors:
  #   rc 0 success, rc 1 config file missing, rc 2 config file
  #   malformed, rc 3 override malformed.
  local case_dir; case_dir="$(mktest_tmp)"
  local cfg="${case_dir}/env_config.json"
  printf '{"cisco_ai_defense_endpoint": "%s"}\n' "${TEST_AID_ENDPOINT_PROD}" >"${cfg}"

  local out rc

  # Fallback to config file when no override.
  out="$(resolve_aid_endpoint "" "${cfg}")"
  assert_eq "${out}" "${TEST_AID_ENDPOINT_PROD}" "empty override reads from config file"

  # A different endpoint value in the config file also resolves.
  printf '{"cisco_ai_defense_endpoint": "%s"}\n' "${TEST_AID_ENDPOINT_PREVIEW}" >"${cfg}"
  out="$(resolve_aid_endpoint "" "${cfg}")"
  assert_eq "${out}" "${TEST_AID_ENDPOINT_PREVIEW}" \
    "config file swap re-resolves the endpoint"

  # Override wins over the config file (even a valid config file).
  out="$(resolve_aid_endpoint "https://sam-aid-004864.api.inspect.aidefense.aiteam.cisco.com" "${cfg}")"
  assert_eq "${out}" "https://sam-aid-004864.api.inspect.aidefense.aiteam.cisco.com" \
    "override takes precedence over --config-file"

  # Trailing slash stripped from either source for consistent path
  # joining downstream.
  out="$(resolve_aid_endpoint "https://host.example.com/" "${cfg}")"
  assert_eq "${out}" "https://host.example.com" "trailing slash stripped from override"
  printf '{"cisco_ai_defense_endpoint": "https://host.example.com/"}\n' >"${cfg}"
  out="$(resolve_aid_endpoint "" "${cfg}")"
  assert_eq "${out}" "https://host.example.com" "trailing slash stripped from config-file value"

  # http:// is allowed (adhoc/local) — the plaintext warning is
  # emitted by install.sh, not this pure helper.
  out="$(resolve_aid_endpoint "http://localhost:8080" "${cfg}")"
  assert_eq "${out}" "http://localhost:8080" "plaintext http override accepted by resolver"

  # Malformed override -> rc 3 so the caller can attribute the error
  # to --override-endpoint specifically.
  rc=0; resolve_aid_endpoint "not-a-url"        "${cfg}" >/dev/null 2>&1 || rc=$?
  assert_status "${rc}" 3 "override without scheme -> rc 3"
  rc=0; resolve_aid_endpoint "ftp://host"       "${cfg}" >/dev/null 2>&1 || rc=$?
  assert_status "${rc}" 3 "non-http(s) scheme -> rc 3"
  rc=0; resolve_aid_endpoint "https://a b.com"  "${cfg}" >/dev/null 2>&1 || rc=$?
  assert_status "${rc}" 3 "override with whitespace -> rc 3"
  rc=0; resolve_aid_endpoint 'https://a".com'   "${cfg}" >/dev/null 2>&1 || rc=$?
  assert_status "${rc}" 3 "override with double-quote -> rc 3"
  rc=0; resolve_aid_endpoint 'https://a\.com'   "${cfg}" >/dev/null 2>&1 || rc=$?
  assert_status "${rc}" 3 "override with backslash -> rc 3"

  # Hostless overrides.
  rc=0; resolve_aid_endpoint "https:///"          "${cfg}" >/dev/null 2>&1 || rc=$?
  assert_status "${rc}" 3 "override with empty authority -> rc 3"
  rc=0; resolve_aid_endpoint "https:///api"       "${cfg}" >/dev/null 2>&1 || rc=$?
  assert_status "${rc}" 3 "override with empty authority + path -> rc 3"
  rc=0; resolve_aid_endpoint "https://?tenant=x"  "${cfg}" >/dev/null 2>&1 || rc=$?
  assert_status "${rc}" 3 "override with query but no host -> rc 3"
  rc=0; resolve_aid_endpoint "https://#frag"      "${cfg}" >/dev/null 2>&1 || rc=$?
  assert_status "${rc}" 3 "override with fragment but no host -> rc 3"

  # No override + missing config file -> rc 1.
  rc=0; resolve_aid_endpoint "" "${case_dir}/does-not-exist.json" >/dev/null 2>&1 || rc=$?
  assert_status "${rc}" 1 "missing config file with no override -> rc 1"

  # No override + malformed JSON -> rc 2.
  printf '{malformed' >"${cfg}"
  rc=0; resolve_aid_endpoint "" "${cfg}" >/dev/null 2>&1 || rc=$?
  assert_status "${rc}" 2 "malformed JSON in config file -> rc 2"

  # No override + missing field -> rc 2.
  printf '{"other_key": "x"}\n' >"${cfg}"
  rc=0; resolve_aid_endpoint "" "${cfg}" >/dev/null 2>&1 || rc=$?
  assert_status "${rc}" 2 "config file missing cisco_ai_defense_endpoint -> rc 2"

  # No override + malformed URL in the JSON value -> rc 2 (the URL
  # regex runs on the file's payload too).
  printf '{"cisco_ai_defense_endpoint": "not-a-url"}\n' >"${cfg}"
  rc=0; resolve_aid_endpoint "" "${cfg}" >/dev/null 2>&1 || rc=$?
  assert_status "${rc}" 2 "config file with malformed URL -> rc 2"
}

t_managed_enterprise_verdict_sources_locked() {
  # The managed_enterprise rollout intentionally enables only two
  # verdict sources:
  #   1. Cisco AI Defense cloud (via CMID) — the only enforceable
  #      block source (see mergeVerdict + demoteLocalBlockForManaged
  #      in internal/gateway/guardrail.go).
  #   2. Local regex — telemetry-only; Findings surface in the audit
  #      trail but the Action is capped at 'alert' by the demoter.
  #
  # Everything else (asset_policy, LLM judge, component/plugin
  # scanner via watcher) must be OFF at the config surface so future
  # edits to the rendered YAML can't silently reactivate a source
  # that would produce independent block verdicts.
  local out
  out="$(render_config action cursor 18970 false "/opt/cisco/secureclient/defenseclaw" "${TEST_AID_ENDPOINT_PROD}" cursor)"

  # Cloud enforcement source: the cisco_ai_defense block must be
  # emitted with a non-empty endpoint (see NewCiscoDefenseClawInspectClient
  # which refuses to construct without one).
  assert_contains     "${out}" "cisco_ai_defense:"                            "AID cloud block present"
  assert_contains     "${out}" "endpoint: \"${TEST_AID_ENDPOINT_PROD}\""      "AID endpoint threaded through"

  # Local regex: guardrail block present + regex_only pin.
  assert_contains     "${out}" "guardrail:"                                   "guardrail block present"
  assert_contains     "${out}" "detection_strategy: regex_only"               "detection_strategy: regex_only"

  # Sources that must NOT be active:
  assert_contains     "${out}" "asset_policy:"                                "asset_policy stub present"
  assert_not_contains "${out}" "default: deny"                                "asset_policy mcp/skill/plugin default: deny MUST NOT appear"
  assert_contains     "${out}" "watcher:"                                     "gateway.watcher stub present"
  # judge.enabled=false is set inside the guardrail block.
  # The daemon defaults guardrail.judge.enabled=false too, so a
  # missing entry would be safe — but pinning it explicitly means
  # someone reading config.yaml can see 'the judge is off' without
  # having to know the sidecar defaults.
  assert_contains     "${out}" "judge:"                                       "guardrail.judge stub present"
}

run_case "managed_enterprise verdict sources locked (AID + local regex only)" t_managed_enterprise_verdict_sources_locked
run_case "single-connector config"  t_single_connector
run_case "multi-connector config"   t_multi_connector
run_case "runtime paths under support (trust-check invariant)" t_runtime_paths_disjoint_from_config_parent
run_case "device_key_file pinned under runtime dir (SUPPORT_DIR is not writable by service user)" \
  t_device_key_file_under_runtime_dir
run_case "renderer pass-through: redaction on"  t_redaction_pass_through_on
run_case "renderer pass-through: redaction off" t_redaction_pass_through_off
run_case "cisco_ai_defense block emitted with installer endpoint" t_cisco_ai_defense_block_emitted
run_case "_read_json_field reads AVC env_config.json shape"       t_read_json_field_semantics
run_case "otel block enabled for managed AID sink"               t_otel_block_enabled_for_managed_sink
run_case "ai_discovery enabled for endpoint inventory"           t_ai_discovery_enabled_for_endpoint_inventory
run_case "resolve_aid_endpoint precedence + validation"           t_resolve_aid_endpoint_precedence
run_case "rendered YAML parses"     t_yaml_parses
