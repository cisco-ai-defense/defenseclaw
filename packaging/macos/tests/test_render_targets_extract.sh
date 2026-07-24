#!/usr/bin/env bash
# extract_connectors: regex scan of render_config output MUST NOT
# produce duplicates when both the `connector:` scalar (the primary)
# and the `connectors:` map are present in guardrail.yaml. This is the
# shape render_config emits for multi-connector installs — a naive
# scanner would add the primary once, then re-add every map key
# (including the primary), producing e.g. [codex, codex, claudecode,
# cursor]. That garbage feeds into the hook-guardian's Install loop
# which then reconciles the same target twice per tick.
#
# The extractor lives inside packaging/macos/lib/render-targets.sh
# because the daemon that invokes it (hook-enumerator) runs as root
# and cannot see PyYAML if it's installed only under a user's
# ~/Library/Python site-packages. render-targets.sh therefore uses a
# regex-only scanner deliberately.

. "${PKG_DIR}/lib/installer_lib.sh"

RENDER_TARGETS_SH="${PKG_DIR}/lib/render-targets.sh"

# Extract the extract_connectors function body into a callable file so
# we can drive it against synthetic config.yaml fixtures without
# running the full render-targets.sh script (which asserts root + real
# support-dir paths).
_seed_extract_wrapper() {
  local dir="$1" cfg="$2"
  local wrapper="${dir}/extract-wrapper.sh"
  cat > "${wrapper}" <<EOF
#!/usr/bin/env bash
CONFIG_PATH="${cfg}"
$(/usr/bin/awk '/^extract_connectors\(\)/{found=1} found{print} /^}$/{if(found){exit}}' "${RENDER_TARGETS_SH}")
extract_connectors
EOF
  chmod 0755 "${wrapper}"
  printf '%s' "${wrapper}"
}

t_extract_connectors_multi_connector_no_duplicates() {
  # This is the exact shape render_config emits for a
  # --connector codex,claudecode,cursor install (see t_multi_connector
  # in test_render_config.sh). Both the primary scalar AND the map are
  # present. The extractor must return each connector exactly once.
  local dir cfg wrapper out lines
  dir="$(mktest_tmp)"
  cfg="${dir}/config.yaml"
  cat > "${cfg}" <<'YAML'
config_version: 6
deployment_mode: managed_enterprise
guardrail:
  enabled: true
  mode: action
  scanner_mode: both
  detection_strategy: regex_only
  judge:
    enabled: false
  connector: codex
  connectors:
    codex:
      enabled: true
      mode: action
    claudecode:
      enabled: true
      mode: action
    cursor:
      enabled: true
      mode: action

cisco_ai_defense:
  endpoint: "https://preview.example.com"
YAML
  wrapper="$(_seed_extract_wrapper "${dir}" "${cfg}")"
  out="$(bash "${wrapper}" 2>&1)"
  lines="$(printf '%s\n' "${out}" | grep -c . || true)"
  assert_contains "${out}" "codex"      "codex extracted"
  assert_contains "${out}" "claudecode" "claudecode extracted"
  assert_contains "${out}" "cursor"     "cursor extracted"
  assert_eq "${lines}" "3" "exactly 3 connectors extracted (no duplicate from primary + map both present)"
}

t_extract_connectors_single_connector_scalar_only() {
  # When the operator picks a single connector, render_config emits ONLY
  # the `connector:` scalar (no `connectors:` map). Extractor must fall
  # back to the scalar in that case.
  local dir cfg wrapper out lines
  dir="$(mktest_tmp)"
  cfg="${dir}/config.yaml"
  cat > "${cfg}" <<'YAML'
config_version: 6
deployment_mode: managed_enterprise
guardrail:
  enabled: true
  mode: action
  scanner_mode: both
  connector: codex

cisco_ai_defense:
  endpoint: "https://preview.example.com"
YAML
  wrapper="$(_seed_extract_wrapper "${dir}" "${cfg}")"
  out="$(bash "${wrapper}" 2>&1)"
  lines="$(printf '%s\n' "${out}" | grep -c . || true)"
  assert_eq "${lines}" "1" "single-connector install extracts exactly one entry"
  assert_contains "${out}" "codex" "codex extracted from single scalar"
}

t_extract_connectors_ignores_top_level_connector_lookalike() {
  # Regression guard: another top-level block that happens to contain a
  # `connector:` key must NOT be picked up. Only the guardrail: block
  # counts. This is defence-in-depth against a future edit to
  # render_config adding e.g. an `openclaw.connector: something` block.
  local dir cfg wrapper out lines
  dir="$(mktest_tmp)"
  cfg="${dir}/config.yaml"
  cat > "${cfg}" <<'YAML'
config_version: 6
deployment_mode: managed_enterprise
openclaw:
  connector: bogus
guardrail:
  enabled: true
  connector: codex
YAML
  wrapper="$(_seed_extract_wrapper "${dir}" "${cfg}")"
  out="$(bash "${wrapper}" 2>&1)"
  lines="$(printf '%s\n' "${out}" | grep -c . || true)"
  assert_eq "${lines}" "1" "only guardrail.connector is picked up"
  assert_contains     "${out}" "codex" "codex extracted"
  assert_not_contains "${out}" "bogus" "top-level connector: outside guardrail is ignored"
}

run_case "extract_connectors: multi-connector no duplicates"     t_extract_connectors_multi_connector_no_duplicates
run_case "extract_connectors: single-connector scalar fallback"  t_extract_connectors_single_connector_scalar_only
run_case "extract_connectors: ignores non-guardrail connector:"  t_extract_connectors_ignores_top_level_connector_lookalike
