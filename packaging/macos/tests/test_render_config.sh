#!/usr/bin/env bash
# render_config: single vs multi-connector YAML output.
. "${PKG_DIR}/lib/installer_lib.sh"

# Fixed prod endpoint for tests that don't care about --env resolution.
# t_aid_endpoint_env_selection covers preview/prod switching.
TEST_AID_ENDPOINT_PROD="https://us.api.inspect.aidefense.security.cisco.com"
TEST_AID_ENDPOINT_PREVIEW="https://preview.api.inspect.aidefense.aiteam.cisco.com"

t_single_connector() {
  local out
  out="$(render_config action cursor 18970 "/opt/cisco/secureclient/defenseclaw" "${TEST_AID_ENDPOINT_PROD}" cursor)"

  assert_contains "${out}" "config_version: 8"                  "config_version present"
  assert_contains "${out}" "deployment_mode: managed_enterprise" "managed_enterprise mode"
  assert_contains "${out}" "data_dir: \"/opt/cisco/secureclient/defenseclaw/runtime\"" "data_dir points at runtime subdir (matches docs-site/setup/enterprise-deployment.mdx)"
  assert_contains "${out}" "path: \"/opt/cisco/secureclient/defenseclaw/runtime/audit.db\"" "v8 local history under runtime"
  assert_contains "${out}" "judge_bodies_path: \"/opt/cisco/secureclient/defenseclaw/runtime/judge_bodies.db\"" "v8 judge bodies under runtime"
  assert_contains "${out}" "api_port: 18970"                    "api_port"
  assert_contains "${out}" "redaction_profile: sensitive"       "managed redaction profile"
  assert_not_contains "${out}" "disable_redaction"               "removed global redaction bypass"
  assert_not_contains "${out}" $'\naudit_db:'                     "removed top-level audit DB field"
  assert_not_contains "${out}" $'\njudge_bodies_db:'              "removed top-level judge DB field"
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
  out="$(render_config observe cursor 18970 "/opt/cisco/secureclient/defenseclaw" "${TEST_AID_ENDPOINT_PROD}" cursor claudecode codex)"

  assert_contains "${out}" "connector: cursor"        "primary is first arg"
  assert_contains "${out}" "  connectors:"            "multi-connector map present"
  assert_contains "${out}" "    cursor:"              "cursor entry under connectors"
  assert_contains "${out}" "    claudecode:"          "claudecode entry under connectors"
  assert_contains "${out}" "    codex:"               "codex entry under connectors"
  assert_contains "${out}" "redaction_profile: sensitive" "managed redaction profile"
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
  out="$(render_config observe cursor 18970 "${support}" "${TEST_AID_ENDPOINT_PROD}" cursor)"
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
  out="$(render_config observe cursor 18970 "${support}" "${TEST_AID_ENDPOINT_PROD}" cursor)"
  assert_contains     "${out}" "device_key_file: \"${runtime}/device.key\"" "device_key_file under runtime dir"
  assert_not_contains "${out}" "device_key_file: \"${support}/device.key\"" "device_key_file MUST NOT land in SUPPORT_DIR (no group-write there)"
}

t_managed_redaction_is_sensitive() {
  local out
  out="$(render_config observe codex 18970 "/var/lib/dc" "${TEST_AID_ENDPOINT_PROD}" codex)"
  assert_contains "${out}" "redaction_profile: sensitive" "renderer emits the secure managed profile"
  assert_not_contains "${out}" "privacy:" "renderer does not emit the retired v7 privacy block"
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
  out="$(render_config action cursor 18970 "/opt/cisco/secureclient/defenseclaw" "${TEST_AID_ENDPOINT_PROD}" cursor claudecode)"
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
  out="$(render_config action cursor 18970 "/opt/cisco/secureclient/defenseclaw" "${TEST_AID_ENDPOINT_PREVIEW}" cursor)"
  assert_contains "${out}" "cisco_ai_defense:"                             "cisco_ai_defense: block present"
  assert_contains "${out}" "endpoint: \"${TEST_AID_ENDPOINT_PREVIEW}\""    "endpoint value threaded through"
}

t_aid_endpoint_env_selection() {
  # Helper is the single source of truth mapping installer --env to a
  # host. Adding a new environment MUST update this helper (and this
  # test).
  local prod preview bogus_rc
  prod="$(aid_endpoint_for_env prod)"
  preview="$(aid_endpoint_for_env preview)"
  assert_eq "${prod}"    "${TEST_AID_ENDPOINT_PROD}"    "prod maps to us prod host"
  assert_eq "${preview}" "${TEST_AID_ENDPOINT_PREVIEW}" "preview maps to aiteam preview host"

  # Unknown env must be a non-zero exit for --env validation to reject
  # it at install time.
  bogus_rc=0
  aid_endpoint_for_env staging >/dev/null 2>&1 || bogus_rc=$?
  if [[ "${bogus_rc}" == "0" ]]; then
    _fail "aid_endpoint_for_env staging exited 0; expected non-zero for unknown env"
    return 1
  fi
}

t_v8_managed_sink_is_release_owned() {
  # Observability v8 injects the managed Cisco AI Defense log sink from the
  # validated deployment_mode + cisco_ai_defense.endpoint. The macOS renderer
  # must not restore the removed v7 otel block or render an operator-controlled
  # destination that could retarget or disable that release-owned route.
  local out
  out="$(render_config action cursor 18970 "/opt/cisco/secureclient/defenseclaw" "${TEST_AID_ENDPOINT_PROD}" cursor)"
  assert_contains     "${out}" "config_version: 8"                    "v8 config is rendered"
  assert_contains     "${out}" "observability:"                       "v8 observability block is present"
  assert_contains     "${out}" "redaction_profile: sensitive"         "managed route defaults to sensitive"
  assert_not_contains "${out}" "$(printf '\notel:')"                  "removed v7 otel block stays absent"
  assert_not_contains "${out}" "destinations:"                        "no user destination is rendered"
}

t_ai_discovery_enabled_for_endpoint_inventory() {
  # render_config must emit an ai_discovery block with enabled: true so the
  # continuous discovery scanner runs and ships the endpoint inventory to AI
  # Defense as discovery events over the managed AID log sink. Without this the
  # scanner is a no-op (NewContinuousDiscoveryService returns nil when
  # ai_discovery.enabled is false) and no inventory flows.
  local out
  out="$(render_config action cursor 18970 "/opt/cisco/secureclient/defenseclaw" "${TEST_AID_ENDPOINT_PROD}" cursor)"
  assert_contains "${out}" "$(printf 'ai_discovery:\n  enabled: true')" "ai_discovery block enables the inventory scanner"
}

t_resolve_aid_endpoint_precedence() {
  # resolve_aid_endpoint backs the --override-endpoint adhoc-testing seam.
  # An empty override falls back to the --env-derived host; a non-empty
  # override wins outright, has its trailing slash stripped, and is
  # validated as an http(s) URL.
  local out rc

  # Fallback to --env when no override.
  out="$(resolve_aid_endpoint prod "")"
  assert_eq "${out}" "${TEST_AID_ENDPOINT_PROD}"    "empty override falls back to --env prod host"
  out="$(resolve_aid_endpoint preview "")"
  assert_eq "${out}" "${TEST_AID_ENDPOINT_PREVIEW}" "empty override falls back to --env preview host"

  # Override wins over --env (even a valid --env).
  out="$(resolve_aid_endpoint prod "https://sam-aid-004864.api.inspect.aidefense.aiteam.cisco.com")"
  assert_eq "${out}" "https://sam-aid-004864.api.inspect.aidefense.aiteam.cisco.com" \
    "override takes precedence over --env"

  # Trailing slash stripped for consistent path joining downstream.
  out="$(resolve_aid_endpoint prod "https://host.example.com/")"
  assert_eq "${out}" "https://host.example.com" "trailing slash stripped from override"

  # http:// is allowed (adhoc/local) — the plaintext warning is emitted by
  # install.sh, not this pure helper.
  out="$(resolve_aid_endpoint preview "http://localhost:8080")"
  assert_eq "${out}" "http://localhost:8080" "plaintext http override accepted by resolver"

  # Malformed override -> rc 2 (distinct from unknown-env rc 1) so the
  # caller can attribute the error to the right flag.
  rc=0; resolve_aid_endpoint prod "not-a-url"        >/dev/null 2>&1 || rc=$?
  assert_status "${rc}" 2 "override without scheme -> rc 2"
  rc=0; resolve_aid_endpoint prod "ftp://host"       >/dev/null 2>&1 || rc=$?
  assert_status "${rc}" 2 "non-http(s) scheme -> rc 2"
  rc=0; resolve_aid_endpoint prod "https://a b.com"  >/dev/null 2>&1 || rc=$?
  assert_status "${rc}" 2 "override with whitespace -> rc 2"
  rc=0; resolve_aid_endpoint prod 'https://a".com'   >/dev/null 2>&1 || rc=$?
  assert_status "${rc}" 2 "override with double-quote -> rc 2"
  rc=0; resolve_aid_endpoint prod 'https://a\.com'   >/dev/null 2>&1 || rc=$?
  assert_status "${rc}" 2 "override with backslash -> rc 2"

  # Hostless overrides must be rejected: without an authority the rendered
  # cisco_ai_defense.endpoint has no usable host and inspection/export
  # silently fails at runtime.
  rc=0; resolve_aid_endpoint prod "https:///"          >/dev/null 2>&1 || rc=$?
  assert_status "${rc}" 2 "override with empty authority -> rc 2"
  rc=0; resolve_aid_endpoint prod "https:///api"       >/dev/null 2>&1 || rc=$?
  assert_status "${rc}" 2 "override with empty authority + path -> rc 2"
  rc=0; resolve_aid_endpoint prod "https://?tenant=x"  >/dev/null 2>&1 || rc=$?
  assert_status "${rc}" 2 "override with query but no host -> rc 2"
  rc=0; resolve_aid_endpoint prod "https://#frag"      >/dev/null 2>&1 || rc=$?
  assert_status "${rc}" 2 "override with fragment but no host -> rc 2"

  # No override + unknown env -> rc 1 (delegates to aid_endpoint_for_env).
  rc=0; resolve_aid_endpoint staging "" >/dev/null 2>&1 || rc=$?
  assert_status "${rc}" 1 "unknown env with no override -> rc 1"
}

t_preview_env_endpoint_ends_up_in_config() {
  # End-to-end at the render layer: an installer running with --env
  # preview must produce a config.yaml whose cisco_ai_defense.endpoint
  # points at the preview host. This is the whole point of --env.
  local endpoint out
  endpoint="$(aid_endpoint_for_env preview)"
  out="$(render_config action cursor 18970 "/opt/cisco/secureclient/defenseclaw" "${endpoint}" cursor)"
  assert_contains "${out}" "endpoint: \"${TEST_AID_ENDPOINT_PREVIEW}\"" "preview host lands in rendered config"
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
  local endpoint out
  endpoint="$(aid_endpoint_for_env prod)"
  out="$(render_config action cursor 18970 "/opt/cisco/secureclient/defenseclaw" "${endpoint}" cursor)"

  # Cloud enforcement source: the cisco_ai_defense block must be
  # emitted with a non-empty endpoint (see NewCiscoDefenseClawInspectClient
  # which refuses to construct without one).
  assert_contains     "${out}" "cisco_ai_defense:"                        "AID cloud block present"
  assert_contains     "${out}" "endpoint: \"${endpoint}\""                "AID endpoint threaded through"

  # Local regex: guardrail block present + regex_only pin.
  assert_contains     "${out}" "guardrail:"                               "guardrail block present"
  assert_contains     "${out}" "detection_strategy: regex_only"           "detection_strategy: regex_only"

  # Sources that must NOT be active:
  assert_contains     "${out}" "asset_policy:"                            "asset_policy stub present"
  assert_not_contains "${out}" "default: deny"                            "asset_policy mcp/skill/plugin default: deny MUST NOT appear"
  assert_contains     "${out}" "watcher:"                                 "gateway.watcher stub present"
  # judge.enabled=false is set inside the guardrail block.
  # The daemon defaults guardrail.judge.enabled=false too, so a
  # missing entry would be safe — but pinning it explicitly means
  # someone reading config.yaml can see 'the judge is off' without
  # having to know the sidecar defaults.
  assert_contains     "${out}" "judge:"                                   "guardrail.judge stub present"
}

run_case "managed_enterprise verdict sources locked (AID + local regex only)" t_managed_enterprise_verdict_sources_locked
run_case "single-connector config"  t_single_connector
run_case "multi-connector config"   t_multi_connector
run_case "runtime paths under support (trust-check invariant)" t_runtime_paths_disjoint_from_config_parent
run_case "device_key_file pinned under runtime dir (SUPPORT_DIR is not writable by service user)" \
  t_device_key_file_under_runtime_dir
run_case "managed redaction profile" t_managed_redaction_is_sensitive
run_case "cisco_ai_defense block emitted with installer endpoint" t_cisco_ai_defense_block_emitted
run_case "aid_endpoint_for_env maps flags to hosts"               t_aid_endpoint_env_selection
run_case "v8 managed AID sink remains release-owned"             t_v8_managed_sink_is_release_owned
run_case "ai_discovery enabled for endpoint inventory"           t_ai_discovery_enabled_for_endpoint_inventory
run_case "resolve_aid_endpoint override precedence + validation"  t_resolve_aid_endpoint_precedence
run_case "--env preview lands in rendered config"                 t_preview_env_endpoint_ends_up_in_config
run_case "rendered YAML parses"     t_yaml_parses
