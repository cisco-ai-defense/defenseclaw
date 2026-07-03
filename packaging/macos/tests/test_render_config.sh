#!/usr/bin/env bash
# render_config: single vs multi-connector YAML output.
. "${PKG_DIR}/lib/installer_lib.sh"

t_single_connector() {
  local out
  out="$(render_config action cursor 18970 false "/Library/Application Support/DefenseClaw" cursor)"

  assert_contains "${out}" "config_version: 6"                  "config_version present"
  assert_contains "${out}" "deployment_mode: managed_enterprise" "managed_enterprise mode"
  assert_contains "${out}" "data_dir: \"/Library/Application Support/DefenseClaw/runtime\"" "data_dir points at runtime subdir (config-adjacent path stays root-only)"
  assert_contains "${out}" "audit_db: \"/Library/Application Support/DefenseClaw/runtime/audit.db\"" "audit_db under runtime"
  assert_contains "${out}" "judge_bodies_db: \"/Library/Application Support/DefenseClaw/runtime/judge_bodies.db\"" "judge_bodies_db under runtime"
  assert_contains "${out}" "api_port: 18970"                    "api_port"
  assert_contains "${out}" "disable_redaction: false"           "redaction disabled flag"
  assert_contains "${out}" "mode: action"                       "guardrail mode"
  assert_contains "${out}" "scanner_mode: both"                 "scanner_mode"
  assert_contains "${out}" "connector: cursor"                  "primary connector"
  assert_not_contains "${out}" "  connectors:"                  "no multi-connector map when single"
  assert_contains "${out}" "mcp:"                               "asset_policy mcp block"
  assert_contains "${out}" "default: deny"                      "mcp default deny"
  assert_contains "${out}" "application_protection:"            "application_protection block"
  assert_contains "${out}" "enabled: false"                     "application_protection disabled"
}

t_multi_connector() {
  local out
  out="$(render_config observe cursor 18970 true "/Library/Application Support/DefenseClaw" cursor claudecode codex)"

  assert_contains "${out}" "connector: cursor"        "primary is first arg"
  assert_contains "${out}" "  connectors:"            "multi-connector map present"
  assert_contains "${out}" "    cursor:"              "cursor entry under connectors"
  assert_contains "${out}" "    claudecode:"          "claudecode entry under connectors"
  assert_contains "${out}" "    codex:"               "codex entry under connectors"
  assert_contains "${out}" "disable_redaction: true"  "redaction explicit opt-out"
  assert_contains "${out}" "mode: observe"            "observe mode"
}

t_runtime_paths_disjoint_from_config_parent() {
  # Regression guard: the managed_enterprise trust check walks every
  # ancestor of config.yaml and requires each to be root-owned with
  # no group/other write bits. That means data_dir CANNOT be the same
  # directory that holds config.yaml (installer needs to chown it to
  # the service user). Assert the renderer places data_dir strictly
  # BELOW the support dir.
  local out support runtime
  support="/Library/Application Support/DefenseClaw"
  runtime="${support}/runtime"
  out="$(render_config observe cursor 18970 false "${support}" cursor)"
  assert_contains "${out}" "data_dir: \"${runtime}\"" "data_dir under support"
  # If data_dir was ever set back to support itself, trust check fails.
  assert_not_contains "${out}" "data_dir: \"${support}\"" "data_dir MUST NOT equal support dir"
}

t_redaction_pass_through_on() {
  # Pure rendering check: given "false", the block emits redaction on.
  # This proves the rendering layer respects the caller's choice; the
  # install.sh default-arg-parsing contract is asserted in
  # test_arg_parsing.sh::t_install_default_redaction_is_on so we don't
  # duplicate the "what's the default" check at two layers.
  local out
  out="$(render_config observe codex 18970 false "/var/lib/dc" codex)"
  assert_contains "${out}" "disable_redaction: false" "renderer emits redaction ON when false is passed"
}

t_redaction_pass_through_off() {
  local out
  out="$(render_config action codex 18970 true "/var/lib/dc" codex)"
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
  out="$(render_config action cursor 18970 false "/Library/Application Support/DefenseClaw" cursor claudecode)"
  parsed="$(printf '%s\n' "${out}" | /usr/bin/python3 -c 'import sys,yaml,json; print(json.dumps(yaml.safe_load(sys.stdin)))' 2>&1)" || {
    _fail "rendered YAML did not parse: ${parsed}"
    return 1
  }
  assert_contains "${parsed}" '"deployment_mode": "managed_enterprise"' "parsed yaml has managed_enterprise"
  assert_contains "${parsed}" '"connector": "cursor"' "parsed yaml has primary connector"
  assert_contains "${parsed}" '"connectors":' "parsed yaml has connectors map"
}

run_case "single-connector config"  t_single_connector
run_case "multi-connector config"   t_multi_connector
run_case "runtime paths under support (trust-check invariant)" t_runtime_paths_disjoint_from_config_parent
run_case "renderer pass-through: redaction on"  t_redaction_pass_through_on
run_case "renderer pass-through: redaction off" t_redaction_pass_through_off
run_case "rendered YAML parses"     t_yaml_parses
