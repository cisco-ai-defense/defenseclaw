#!/usr/bin/env bash
# Scrub helper: remove DefenseClaw entries from user agent configs while
# preserving the user's own state. Driven by lib/scrub_agent_configs.py.
SCRUB="${PKG_DIR}/lib/scrub_agent_configs.py"
# Prefer a PATH-resolved python3 for portability across Linux distros
# where /usr/bin/python3 may not exist; fall back to the macOS system
# python if PATH lookup fails.
PY="$(command -v python3 || printf '/usr/bin/python3')"

t_cursor_drops_dc_keeps_user_entry() {
  local d; d="$(mktest_tmp)"
  cat > "${d}/hooks.json" <<'JSON'
{
  "version": 1,
  "hooks": {
    "preToolUse": [
      {"type":"command","command":"/Users/u/.defenseclaw/hooks/cursor-hook.sh","timeout":30000,"failClosed":true},
      {"type":"command","command":"/Users/u/.local/bin/my-other-hook.sh","timeout":5000}
    ],
    "sessionStart": [
      {"type":"command","command":"/Users/u/.defenseclaw/hooks/cursor-hook.sh"}
    ]
  }
}
JSON
  ${PY} "${SCRUB}" cursor "${d}/hooks.json"
  local rc=$?; assert_status "${rc}" 0 "scrub exit 0"
  local out; out="$(cat "${d}/hooks.json")"
  assert_not_contains "${out}" "defenseclaw" "DefenseClaw refs removed"
  assert_contains     "${out}" "my-other-hook.sh" "user hook preserved"
  assert_not_contains "${out}" "sessionStart"     "DC-only event key removed"
  # Idempotent: second run is a no-op.
  ${PY} "${SCRUB}" cursor "${d}/hooks.json"
  local rc2=$?; assert_status "${rc2}" 0 "second run also exit 0"
  local out2; out2="$(cat "${d}/hooks.json")"
  assert_eq "${out}" "${out2}" "idempotent (no further changes)"
}

t_cursor_no_op_when_no_dc_entries() {
  local d; d="$(mktest_tmp)"
  cat > "${d}/hooks.json" <<'JSON'
{"version":1,"hooks":{"preToolUse":[{"type":"command","command":"/Users/u/my-hook.sh"}]}}
JSON
  ${PY} "${SCRUB}" cursor "${d}/hooks.json"
  local rc=$?; assert_status "${rc}" 0 "scrub exit 0"
  local out; out="$(cat "${d}/hooks.json")"
  assert_contains "${out}" "my-hook.sh" "user hook preserved"
}

t_claudecode_strips_managed_env_keys() {
  # DefenseClaw's Claude connector writes a specific set of env keys
  # (see claudeCodeOtelEnvKeys in the Go connector). Scrub must drop
  # them and preserve unrelated user env entries.
  local d; d="$(mktest_tmp)"
  cat > "${d}/settings.json" <<'JSON'
{
  "hooks": {},
  "env": {
    "MY_USER_VAR": "keep-me",
    "CLAUDE_CODE_ENABLE_TELEMETRY": "1",
    "OTEL_EXPORTER_OTLP_ENDPOINT": "http://127.0.0.1:18970",
    "OTEL_EXPORTER_OTLP_HEADERS": "x-defenseclaw-token=abc",
    "DEFENSECLAW_FAIL_MODE": "open"
  }
}
JSON
  ${PY} "${SCRUB}" claudecode "${d}/settings.json"
  local rc=$?; assert_status "${rc}" 0
  local out; out="$(cat "${d}/settings.json")"
  assert_contains     "${out}" "MY_USER_VAR"                 "user env preserved"
  assert_contains     "${out}" "keep-me"                     "user env value preserved"
  assert_not_contains "${out}" "CLAUDE_CODE_ENABLE_TELEMETRY" "managed env key removed"
  assert_not_contains "${out}" "OTEL_EXPORTER_OTLP_ENDPOINT"  "managed env key removed"
  assert_not_contains "${out}" "OTEL_EXPORTER_OTLP_HEADERS"   "managed env key removed"
  assert_not_contains "${out}" "DEFENSECLAW_FAIL_MODE"        "managed env key removed"
}

t_claudecode_drops_all_managed_env() {
  # When every env entry is DefenseClaw-owned, the whole env block
  # should be removed (leaving the file tidy).
  local d; d="$(mktest_tmp)"
  cat > "${d}/settings.json" <<'JSON'
{
  "hooks": {},
  "env": {
    "CLAUDE_CODE_ENABLE_TELEMETRY": "1",
    "OTEL_EXPORTER_OTLP_ENDPOINT": "http://127.0.0.1:18970"
  }
}
JSON
  ${PY} "${SCRUB}" claudecode "${d}/settings.json"
  local rc=$?; assert_status "${rc}" 0 "scrub exit 0"
  local out; out="$(cat "${d}/settings.json")"
  assert_not_contains "${out}" "\"env\"" "empty env block removed"
}

t_claudecode_preserves_non_hook_state() {
  local d; d="$(mktest_tmp)"
  cat > "${d}/settings.json" <<'JSON'
{
  "theme": "dark",
  "env": {"FOO":"bar"},
  "hooks": {
    "PreToolUse": [
      {"matcher":"Bash","hooks":[{"type":"command","command":"/Users/u/.defenseclaw/hooks/claudecode-hook.sh"}]}
    ],
    "UserPromptSubmit": [
      {"hooks":[{"type":"command","command":"/Users/u/.defenseclaw/hooks/claudecode-hook.sh"}]},
      {"hooks":[{"type":"command","command":"/Users/u/my-prompt-hook.sh"}]}
    ]
  }
}
JSON
  ${PY} "${SCRUB}" claudecode "${d}/settings.json"
  local rc=$?; assert_status "${rc}" 0
  local out; out="$(cat "${d}/settings.json")"
  assert_contains     "${out}" "\"theme\""           "non-hook state preserved (theme)"
  assert_contains     "${out}" "\"env\""             "non-hook state preserved (env)"
  assert_contains     "${out}" "\"FOO\": \"bar\""    "env values preserved"
  assert_not_contains "${out}" "defenseclaw"         "DC refs removed"
  assert_contains     "${out}" "my-prompt-hook.sh"   "user prompt hook preserved"
  assert_not_contains "${out}" "PreToolUse"          "DC-only event key removed"
}

t_codex_strips_managed_sections() {
  local d; d="$(mktest_tmp)"
  cat > "${d}/config.toml" <<'TOML'
model = "gpt-5"
personality = "pragmatic"

[projects."/Users/u/dev"]
trust_level = "trusted"

[hooks]
PreToolUse = "/Users/u/.defenseclaw/hooks/codex-hook.sh"
SessionStart = "/Users/u/.defenseclaw/hooks/codex-hook.sh"

[otel]
otlp_endpoint = "http://127.0.0.1:18970/v1/logs"

notify = ["bash", "/Users/u/.defenseclaw/notify-bridge.sh"]
TOML
  ${PY} "${SCRUB}" codex "${d}/config.toml"
  local rc=$?; assert_status "${rc}" 0
  local out; out="$(cat "${d}/config.toml")"
  assert_contains     "${out}" "model = \"gpt-5\""        "model preserved"
  assert_contains     "${out}" "personality = \"pragmatic\"" "personality preserved"
  assert_contains     "${out}" "[projects.\"/Users/u/dev\"]" "projects preserved"
  assert_contains     "${out}" "trust_level = \"trusted\""  "project trust preserved"
  assert_not_contains "${out}" "[hooks]"                    "[hooks] section removed"
  assert_not_contains "${out}" "[otel]"                     "[otel] section removed"
  assert_not_contains "${out}" "notify ="                   "notify array removed"
  assert_not_contains "${out}" "defenseclaw"                "no DC refs"
}

t_codex_stops_at_dotted_table_header() {
  # Regression: the previous scrub's "next section" regex only matched
  # simple [name] headers, so if [projects.foo] appeared after
  # a DefenseClaw-owned [hooks] with no intervening blank line, the
  # scrub could eat unrelated user state under [projects.foo].
  local d; d="$(mktest_tmp)"
  cat > "${d}/config.toml" <<'TOML'
model = "gpt-5"

[hooks]
PreToolUse = "/Users/u/.defenseclaw/hooks/codex-hook.sh"
[projects."/Users/u/dev"]
trust_level = "trusted"
model = "override"

[[some.array.of.tables]]
name = "user-owned-array-entry"
TOML
  ${PY} "${SCRUB}" codex "${d}/config.toml"
  local rc=$?; assert_status "${rc}" 0 "scrub exit 0"
  local out; out="$(cat "${d}/config.toml")"
  assert_not_contains "${out}" "[hooks]"                        "[hooks] removed"
  assert_not_contains "${out}" "defenseclaw"                    "no DC refs"
  assert_contains     "${out}" "[projects.\"/Users/u/dev\"]"    "dotted table preserved"
  assert_contains     "${out}" "trust_level = \"trusted\""      "dotted table content preserved"
  assert_contains     "${out}" "[[some.array.of.tables]]"       "array-of-tables preserved"
  assert_contains     "${out}" "user-owned-array-entry"         "array-of-tables content preserved"
}

t_codex_strips_notify_before_any_table_header() {
  # Regression guard: `notify = [...]` at the very top of the file
  # (before any table header) exercises the top-level notify path in
  # scrub_codex, separate from the [otel]/[hooks] handling. Earlier
  # fixtures placed notify after [otel] where TOML treats it as part
  # of the [otel] table and the [otel] scrub swallowed it as a
  # side-effect.
  local d; d="$(mktest_tmp)"
  cat > "${d}/config.toml" <<'TOML'
notify = ["bash", "/Users/u/.defenseclaw/notify-bridge.sh"]

model = "gpt-5"

[projects."/Users/u/dev"]
trust_level = "trusted"
TOML
  ${PY} "${SCRUB}" codex "${d}/config.toml"
  local rc=$?; assert_status "${rc}" 0 "scrub exit 0"
  local out; out="$(cat "${d}/config.toml")"
  assert_not_contains "${out}" "notify ="                     "top-level notify removed"
  assert_not_contains "${out}" "defenseclaw"                  "no DC refs"
  assert_contains     "${out}" "model = \"gpt-5\""            "model preserved"
  assert_contains     "${out}" "[projects.\"/Users/u/dev\"]"  "projects table preserved"
}

t_codex_skips_unrelated_otel_or_hooks_blocks() {
  # If the user has their own [otel] block that does NOT reference
  # DefenseClaw, we must leave it alone. (DefenseClaw owns these blocks
  # in managed installs, so in practice they always do reference DC,
  # but we should not assume.)
  local d; d="$(mktest_tmp)"
  cat > "${d}/config.toml" <<'TOML'
model = "gpt-5"

[otel]
otlp_endpoint = "https://my-vendor.example/v1"

[hooks]
PreToolUse = "/Users/u/my-own-hook.sh"
TOML
  ${PY} "${SCRUB}" codex "${d}/config.toml"
  local rc=$?; assert_status "${rc}" 0
  local out; out="$(cat "${d}/config.toml")"
  assert_contains "${out}" "[otel]"     "user [otel] preserved"
  assert_contains "${out}" "my-vendor"  "user otel endpoint preserved"
  assert_contains "${out}" "[hooks]"    "user [hooks] preserved"
  assert_contains "${out}" "my-own-hook.sh" "user hook script preserved"
}

_make_managed_plugin_fixture() {
  local connector="$1"
  local home="$2"
  local managed="$3"
  local existed="$4"
  local pristine="$5"
  local mode="${6:-384}" # decimal 0600
  local config_root="${7:-${home}/.config/${connector}}"
  local extension="ts"
  [[ "${connector}" == "opencode" ]] && extension="js"
  local plugin="${config_root}/plugins/defenseclaw.${extension}"
  local backup="${home}/.defenseclaw/connector_backups/${connector}/config.json"
  local pristine_file="${home}/pristine.fixture"
  mkdir -p "$(dirname "${plugin}")" "$(dirname "${backup}")"
  chmod 0700 \
    "${home}/.defenseclaw" \
    "${home}/.defenseclaw/connector_backups" \
    "$(dirname "${backup}")"
  printf '%s' "${managed}" > "${plugin}"
  printf '%s' "${pristine}" > "${pristine_file}"
  chmod 0600 "${plugin}"
  "${PY}" - "${connector}" "${plugin}" "${backup}" "${existed}" "${mode}" "${pristine_file}" <<'PY'
import base64
import hashlib
import json
import os
import sys

connector, plugin, backup, existed_raw, mode_raw, pristine_path = sys.argv[1:]
managed = open(plugin, "rb").read()
pristine = open(pristine_path, "rb").read()
existed = existed_raw == "true"
document = {
    "version": 1,
    "connector": connector,
    "logical_name": "config",
    "path": plugin,
    "existed": existed,
    "pristine_sha256": hashlib.sha256(pristine).hexdigest() if existed else "missing",
    "post_sha256": hashlib.sha256(managed).hexdigest(),
}
if existed:
    document["mode"] = int(mode_raw)
    if pristine:
        document["pristine_bytes"] = base64.b64encode(pristine).decode("ascii")
with open(backup, "w", encoding="utf-8") as stream:
    json.dump(document, stream, indent=2, sort_keys=True)
    stream.write("\n")
PY
  chmod 0600 "${backup}"
  rm -f "${pristine_file}"
}

_make_amp_fixture() {
  _make_managed_plugin_fixture amp "$@"
}

_make_opencode_fixture() {
  _make_managed_plugin_fixture opencode "$@"
}

_mutate_amp_backup() {
  local backup="$1"
  local key="$2"
  local value="$3"
  "${PY}" - "${backup}" "${key}" "${value}" <<'PY'
import json
import sys

path, key, value = sys.argv[1:]
with open(path, "r", encoding="utf-8") as stream:
    document = json.load(stream)
document[key] = value
with open(path, "w", encoding="utf-8") as stream:
    json.dump(document, stream, indent=2, sort_keys=True)
    stream.write("\n")
PY
  chmod 0600 "${backup}"
}

_mutate_managed_backup_json() {
  local backup="$1"
  local key="$2"
  local value_json="$3"
  "${PY}" - "${backup}" "${key}" "${value_json}" <<'PY'
import json
import sys

path, key, value_json = sys.argv[1:]
with open(path, "r", encoding="utf-8") as stream:
    document = json.load(stream)
document[key] = json.loads(value_json)
with open(path, "w", encoding="utf-8") as stream:
    json.dump(document, stream, indent=2, sort_keys=True)
    stream.write("\n")
PY
  chmod 0600 "${backup}"
}

t_amp_removes_unchanged_plugin_created_by_setup() {
  local home plugin backup rc
  home="$(mktest_tmp)"
  plugin="${home}/.config/amp/plugins/defenseclaw.ts"
  backup="${home}/.defenseclaw/connector_backups/amp/config.json"
  _make_amp_fixture "${home}" "// defenseclaw managed amp plugin" false ""
  ${PY} "${SCRUB}" amp "${plugin}" "${backup}"
  rc=$?; assert_status "${rc}" 0 "unchanged managed Amp plugin cleanup"
  if [[ -e "${plugin}" || -L "${plugin}" ]]; then
    _fail "Amp plugin created by setup was not removed"
  fi
  if [[ -e "${backup}" || -L "${backup}" ]]; then
    _fail "consumed Amp backup authority was not removed"
  fi
}

t_amp_restores_exact_pristine_plugin_and_mode() {
  local home plugin backup rc out mode
  home="$(mktest_tmp)"
  plugin="${home}/.config/amp/plugins/defenseclaw.ts"
  backup="${home}/.defenseclaw/connector_backups/amp/config.json"
  _make_amp_fixture \
    "${home}" "// defenseclaw replacement" true "// operator pristine" 416
  ${PY} "${SCRUB}" amp "${plugin}" "${backup}"
  rc=$?; assert_status "${rc}" 0 "pre-existing Amp plugin restore"
  out="$(cat "${plugin}")"
  assert_eq "${out}" "// operator pristine" "pristine Amp bytes restored"
  mode="$(stat -f '%Lp' "${plugin}" 2>/dev/null || stat -c '%a' "${plugin}")"
  assert_eq "${mode}" "640" "pristine Amp mode restored"
  if [[ -e "${backup}" ]]; then
    _fail "consumed Amp restore metadata was not removed"
  fi
}

t_amp_drift_refuses_and_preserves_plugin_and_backup() {
  local home plugin backup rc out
  home="$(mktest_tmp)"
  plugin="${home}/.config/amp/plugins/defenseclaw.ts"
  backup="${home}/.defenseclaw/connector_backups/amp/config.json"
  _make_amp_fixture "${home}" "// installed managed plugin" false ""
  printf '%s' "// operator edited after setup" > "${plugin}"
  rc=0
  ${PY} "${SCRUB}" amp "${plugin}" "${backup}" >/dev/null 2>&1 || rc=$?
  assert_status "${rc}" 4 "drifted Amp plugin must refuse cleanup"
  out="$(cat "${plugin}")"
  assert_eq "${out}" "// operator edited after setup" "drifted Amp plugin preserved"
  assert_file_exists "${backup}"
}

t_amp_invalid_backup_identity_refuses() {
  local home plugin backup rc out
  home="$(mktest_tmp)"
  plugin="${home}/.config/amp/plugins/defenseclaw.ts"
  backup="${home}/.defenseclaw/connector_backups/amp/config.json"
  _make_amp_fixture "${home}" "// unchanged managed plugin" false ""
  _mutate_amp_backup "${backup}" connector codex
  rc=0
  ${PY} "${SCRUB}" amp "${plugin}" "${backup}" >/dev/null 2>&1 || rc=$?
  assert_status "${rc}" 4 "mismatched connector identity must refuse cleanup"
  out="$(cat "${plugin}")"
  assert_eq "${out}" "// unchanged managed plugin" "plugin preserved on identity mismatch"
  assert_file_exists "${backup}"
}

t_amp_invalid_captured_path_refuses() {
  local home plugin backup rc out
  home="$(mktest_tmp)"
  plugin="${home}/.config/amp/plugins/defenseclaw.ts"
  backup="${home}/.defenseclaw/connector_backups/amp/config.json"
  _make_amp_fixture "${home}" "// unchanged managed plugin" false ""
  _mutate_amp_backup "${backup}" path "${home}/elsewhere/defenseclaw.ts"
  rc=0
  ${PY} "${SCRUB}" amp "${plugin}" "${backup}" >/dev/null 2>&1 || rc=$?
  assert_status "${rc}" 4 "captured path mismatch must refuse cleanup"
  out="$(cat "${plugin}")"
  assert_eq "${out}" "// unchanged managed plugin" "plugin preserved on path mismatch"
  assert_file_exists "${backup}"
}

t_amp_invalid_pristine_hash_refuses_before_restore() {
  local home plugin backup rc out
  home="$(mktest_tmp)"
  plugin="${home}/.config/amp/plugins/defenseclaw.ts"
  backup="${home}/.defenseclaw/connector_backups/amp/config.json"
  _make_amp_fixture "${home}" "// managed replacement" true "// pristine" 384
  _mutate_amp_backup "${backup}" pristine_sha256 \
    aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  rc=0
  ${PY} "${SCRUB}" amp "${plugin}" "${backup}" >/dev/null 2>&1 || rc=$?
  assert_status "${rc}" 4 "corrupt pristine hash must refuse restore"
  out="$(cat "${plugin}")"
  assert_eq "${out}" "// managed replacement" "managed plugin preserved on corrupt backup"
  assert_file_exists "${backup}"
}

t_amp_missing_post_hash_refuses_before_removal() {
  local home plugin backup rc out
  home="$(mktest_tmp)"
  plugin="${home}/.config/amp/plugins/defenseclaw.ts"
  backup="${home}/.defenseclaw/connector_backups/amp/config.json"
  _make_amp_fixture "${home}" "// unchanged managed plugin" false ""
  _mutate_amp_backup "${backup}" post_sha256 ""
  rc=0
  ${PY} "${SCRUB}" amp "${plugin}" "${backup}" >/dev/null 2>&1 || rc=$?
  assert_status "${rc}" 4 "missing post hash must refuse plugin removal"
  out="$(cat "${plugin}")"
  assert_eq "${out}" "// unchanged managed plugin" "plugin preserved without post hash"
  assert_file_exists "${backup}"
}

t_amp_symlink_plugin_refuses_without_touching_target() {
  local home plugin backup target rc out
  home="$(mktest_tmp)"
  plugin="${home}/.config/amp/plugins/defenseclaw.ts"
  backup="${home}/.defenseclaw/connector_backups/amp/config.json"
  _make_amp_fixture "${home}" "// managed plugin" false ""
  target="${home}/outside-plugin.ts"
  printf '%s' "// outside target" > "${target}"
  rm -f "${plugin}"
  ln -s "${target}" "${plugin}"
  rc=0
  ${PY} "${SCRUB}" amp "${plugin}" "${backup}" >/dev/null 2>&1 || rc=$?
  assert_status "${rc}" 4 "symlinked Amp plugin must refuse cleanup"
  out="$(cat "${target}")"
  assert_eq "${out}" "// outside target" "Amp symlink target preserved"
  if [[ ! -L "${plugin}" ]]; then
    _fail "unsafe Amp plugin symlink was not preserved"
  fi
  assert_file_exists "${backup}"
}

t_amp_hardlinked_plugin_refuses() {
  local home plugin backup alias rc out
  home="$(mktest_tmp)"
  plugin="${home}/.config/amp/plugins/defenseclaw.ts"
  backup="${home}/.defenseclaw/connector_backups/amp/config.json"
  alias="${home}/hardlink-alias.ts"
  _make_amp_fixture "${home}" "// managed plugin" false ""
  ln "${plugin}" "${alias}"
  rc=0
  ${PY} "${SCRUB}" amp "${plugin}" "${backup}" >/dev/null 2>&1 || rc=$?
  assert_status "${rc}" 4 "hard-linked Amp plugin must refuse cleanup"
  out="$(cat "${alias}")"
  assert_eq "${out}" "// managed plugin" "hard-linked Amp bytes preserved"
  assert_file_exists "${plugin}"
  assert_file_exists "${backup}"
}

t_amp_nonprivate_or_missing_backup_refuses() {
  local home plugin backup rc out
  home="$(mktest_tmp)"
  plugin="${home}/.config/amp/plugins/defenseclaw.ts"
  backup="${home}/.defenseclaw/connector_backups/amp/config.json"
  _make_amp_fixture "${home}" "// managed plugin" false ""
  chmod 0644 "${backup}"
  rc=0
  ${PY} "${SCRUB}" amp "${plugin}" "${backup}" >/dev/null 2>&1 || rc=$?
  assert_status "${rc}" 4 "non-private Amp backup must refuse cleanup"
  out="$(cat "${plugin}")"
  assert_eq "${out}" "// managed plugin" "plugin preserved with non-private backup"
  chmod 0600 "${backup}"
  rm -f "${backup}"
  rc=0
  ${PY} "${SCRUB}" amp "${plugin}" "${backup}" >/dev/null 2>&1 || rc=$?
  assert_status "${rc}" 4 "missing Amp backup must refuse cleanup"
  out="$(cat "${plugin}")"
  assert_eq "${out}" "// managed plugin" "plugin preserved without backup authority"
}

t_managed_backup_parser_rejects_noncanonical_types() {
  local home plugin backup rc
  home="$(mktest_tmp)"
  plugin="${home}/.config/amp/plugins/defenseclaw.ts"
  backup="${home}/.defenseclaw/connector_backups/amp/config.json"
  _make_amp_fixture "${home}" "// managed plugin" false ""

  _mutate_managed_backup_json "${backup}" version '1.0'
  rc=0
  ${PY} "${SCRUB}" amp "${plugin}" "${backup}" >/dev/null 2>&1 || rc=$?
  assert_status "${rc}" 4 "floating-point backup version must refuse cleanup"
  assert_file_exists "${plugin}"
  assert_file_exists "${backup}"

  _mutate_managed_backup_json "${backup}" version '1'
  _mutate_managed_backup_json "${backup}" mode '511'
  rc=0
  ${PY} "${SCRUB}" amp "${plugin}" "${backup}" >/dev/null 2>&1 || rc=$?
  assert_status "${rc}" 4 "missing-file backup with nonzero mode must refuse cleanup"
  assert_file_exists "${plugin}"
  assert_file_exists "${backup}"
}

t_darwin_acl_output_parser_is_fail_closed() {
  local rc=0
  "${PY}" - "${SCRUB}" <<'PY' || rc=$?
import importlib.util
import sys

path = sys.argv[1]
name = "defenseclaw_scrub_acl_test"
spec = importlib.util.spec_from_file_location(name, path)
module = importlib.util.module_from_spec(spec)
sys.modules[name] = module
assert spec.loader is not None
spec.loader.exec_module(module)

validate = module._validate_darwin_acl_output
plain = "-rw------- 1 user staff 0 Jan 1 00:00 config.json\n"
deny = "-rw-------+ 1 user staff 0 Jan 1 00:00 config.json\n 0: everyone deny write\n"
read_allow = "-rw-------+ 1 user staff 0 Jan 1 00:00 plugin.js\n 0: everyone allow read\n"
xattr_only = "-rw-------@ 1 user staff 0 Jan 1 00:00 plugin.js\n"
deny_with_keywords_in_name = (
    "-rw-------+ 1 user staff 0 Jan 1 00:00 plugin.js\n"
    " 0: user:display allow name deny write\n"
)
validate(plain, "/fixture", "fixture", private=True)
validate(deny, "/fixture", "fixture", private=True)
validate(read_allow, "/fixture", "fixture", private=False)
validate(xattr_only, "/fixture", "fixture", private=True)
validate(deny_with_keywords_in_name, "/fixture", "fixture", private=True)

refused = (
    ("not-a-mode 1 user staff 0 Jan 1 00:00 fixture\n", False),
    ("-ww------- 1 user staff 0 Jan 1 00:00 fixture\n", False),
    ("-rw-------+ 1 user staff 0 Jan 1 00:00 fixture\n", False),
    ("-rw-------@ 1 user staff 0 Jan 1 00:00 fixture\n 0: everyone deny write\n", False),
    (deny + "future: everyone allow write\n", False),
    ("-rw-------+ 1 user staff 0 Jan 1 00:00 fixture\n 1: everyone deny write\n", False),
    ("-rw-------+ 1 user staff 0 Jan 1 00:00 fixture\n 0: everyone unknown write\n", False),
    ("-rw-------+ 1 user staff 0 Jan 1 00:00 fixture\n 0: everyone allow future_write\n", False),
    ("-rw-------+ 1 user staff 0 Jan 1 00:00 fixture\n 0: everyone deny read,\n", False),
    ("-rw-------+ 1 user staff 0 Jan 1 00:00 fixture\n 0: everyone allow write\n", False),
    (read_allow, True),
)
for output, private in refused:
    try:
        validate(output, "/fixture", "fixture", private=private)
    except OSError:
        continue
    raise SystemExit(f"ACL parser accepted unsafe/malformed output: {output!r}")
PY
  assert_status "${rc}" 0 "macOS ACL output parser rejects unknown syntax and authority allows"
}

t_managed_in_place_mutations_refuse_before_commit() {
  local target_home target_plugin target_backup
  local authority_home authority_plugin authority_backup
  local consume_home consume_plugin consume_backup rc
  target_home="$(mktest_tmp)"
  target_plugin="${target_home}/.config/amp/plugins/defenseclaw.ts"
  target_backup="${target_home}/.defenseclaw/connector_backups/amp/config.json"
  _make_amp_fixture "${target_home}" "// managed target" false ""

  authority_home="$(mktest_tmp)"
  authority_plugin="${authority_home}/.config/amp/plugins/defenseclaw.ts"
  authority_backup="${authority_home}/.defenseclaw/connector_backups/amp/config.json"
  _make_amp_fixture "${authority_home}" "// managed authority" false ""

  consume_home="$(mktest_tmp)"
  consume_plugin="${consume_home}/.config/amp/plugins/defenseclaw.ts"
  consume_backup="${consume_home}/.defenseclaw/connector_backups/amp/config.json"
  _make_amp_fixture "${consume_home}" "// managed replacement" true "// restored pristine"
  printf '%s' "// restored pristine" > "${consume_plugin}"
  chmod 0600 "${consume_plugin}"

  rc=0
  "${PY}" - "${SCRUB}" \
    "${target_plugin}" "${target_backup}" \
    "${authority_plugin}" "${authority_backup}" \
    "${consume_plugin}" "${consume_backup}" <<'PY' || rc=$?
import importlib.util
import os
import sys

(
    scrub_path,
    target,
    target_backup,
    authority_target,
    authority,
    consume_target,
    consume_authority,
) = sys.argv[1:]
name = "defenseclaw_scrub_race_test"
spec = importlib.util.spec_from_file_location(name, scrub_path)
module = importlib.util.module_from_spec(spec)
sys.modules[name] = module
assert spec.loader is not None
spec.loader.exec_module(module)

original_revalidate = module._revalidate_open_file_digest


def mutate_same_inode(path):
    with open(path, "r+b", buffering=0) as stream:
        first = stream.read(1)
        stream.seek(0)
        stream.write(b"!" if first != b"!" else b"?")
        stream.flush()
        os.fsync(stream.fileno())


def exercise(
    mutated_path,
    plugin_path,
    backup_path,
    expect_target_unchanged,
    mutate_on_match=1,
):
    expected = os.stat(mutated_path, follow_symlinks=False)
    fired = False
    matches = 0

    def hooked(fd, *args, **kwargs):
        nonlocal fired, matches
        if os.path.samestat(os.fstat(fd), expected):
            matches += 1
            if not fired and matches == mutate_on_match:
                mutate_same_inode(mutated_path)
                fired = True
        return original_revalidate(fd, *args, **kwargs)

    module._revalidate_open_file_digest = hooked
    before_target = open(plugin_path, "rb").read()
    try:
        module.scrub_managed_plugin(module.AMP_PLUGIN_SPEC, plugin_path, backup_path)
    except OSError:
        pass
    else:
        raise SystemExit(f"same-inode mutation of {mutated_path} was accepted")
    finally:
        module._revalidate_open_file_digest = original_revalidate
    if not fired:
        raise SystemExit(f"same-inode mutation hook did not fire for {mutated_path}")
    if not os.path.exists(backup_path):
        raise SystemExit("backup authority was consumed after an in-place mutation")
    if expect_target_unchanged and open(plugin_path, "rb").read() != before_target:
        raise SystemExit("target changed after in-place authority mutation")


exercise(target, target, target_backup, False)
exercise(authority, authority_target, authority, True)
exercise(consume_authority, consume_target, consume_authority, True, mutate_on_match=2)
PY
  assert_status "${rc}" 0 "same-inode target/authority mutation is detected before mutation or receipt consumption"
  assert_file_exists "${target_plugin}"
  assert_file_exists "${target_backup}"
  assert_file_exists "${authority_plugin}"
  assert_file_exists "${authority_backup}"
  assert_file_exists "${consume_plugin}"
  assert_file_exists "${consume_backup}"
}

t_opencode_removes_unchanged_plugin_created_by_setup() {
  local home plugin backup rc
  home="$(mktest_tmp)"
  plugin="${home}/.config/opencode/plugins/defenseclaw.js"
  backup="${home}/.defenseclaw/connector_backups/opencode/config.json"
  _make_opencode_fixture "${home}" "// defenseclaw managed OpenCode plugin" false ""
  ${PY} "${SCRUB}" opencode --target-from-authority "${backup}"
  rc=$?; assert_status "${rc}" 0 "unchanged managed OpenCode plugin cleanup"
  if [[ -e "${plugin}" || -L "${plugin}" ]]; then
    _fail "OpenCode plugin created by setup was not removed"
  fi
  if [[ -e "${backup}" || -L "${backup}" ]]; then
    _fail "consumed OpenCode backup authority was not removed"
  fi
}

t_opencode_restores_exact_pristine_plugin_and_mode() {
  local home plugin backup rc out mode
  home="$(mktest_tmp)"
  plugin="${home}/.config/opencode/plugins/defenseclaw.js"
  backup="${home}/.defenseclaw/connector_backups/opencode/config.json"
  _make_opencode_fixture \
    "${home}" "// defenseclaw replacement" true "// operator pristine" 416
  ${PY} "${SCRUB}" opencode --target-from-authority "${backup}"
  rc=$?; assert_status "${rc}" 0 "pre-existing OpenCode plugin restore"
  out="$(cat "${plugin}")"
  assert_eq "${out}" "// operator pristine" "pristine OpenCode bytes restored"
  mode="$(stat -f '%Lp' "${plugin}" 2>/dev/null || stat -c '%a' "${plugin}")"
  assert_eq "${mode}" "640" "pristine OpenCode mode restored"
  if [[ -e "${backup}" ]]; then
    _fail "consumed OpenCode restore metadata was not removed"
  fi
}

t_opencode_drift_refuses_and_preserves_authority() {
  local home plugin backup rc out
  home="$(mktest_tmp)"
  plugin="${home}/.config/opencode/plugins/defenseclaw.js"
  backup="${home}/.defenseclaw/connector_backups/opencode/config.json"
  _make_opencode_fixture "${home}" "// installed managed plugin" false ""
  printf '%s' "// operator edited after setup" > "${plugin}"
  rc=0
  ${PY} "${SCRUB}" opencode "${plugin}" "${backup}" >/dev/null 2>&1 || rc=$?
  assert_status "${rc}" 4 "drifted OpenCode plugin must refuse cleanup"
  out="$(cat "${plugin}")"
  assert_eq "${out}" "// operator edited after setup" "drifted OpenCode plugin preserved"
  assert_file_exists "${backup}"
}

t_opencode_manifest_identity_and_path_mismatches_refuse() {
  local home plugin backup rc out
  home="$(mktest_tmp)"
  plugin="${home}/.config/opencode/plugins/defenseclaw.js"
  backup="${home}/.defenseclaw/connector_backups/opencode/config.json"
  _make_opencode_fixture "${home}" "// unchanged managed plugin" false ""
  _mutate_amp_backup "${backup}" connector amp
  rc=0
  ${PY} "${SCRUB}" opencode "${plugin}" "${backup}" >/dev/null 2>&1 || rc=$?
  assert_status "${rc}" 4 "mismatched OpenCode connector identity must refuse cleanup"
  out="$(cat "${plugin}")"
  assert_eq "${out}" "// unchanged managed plugin" "plugin preserved on identity mismatch"

  _mutate_amp_backup "${backup}" connector opencode
  _mutate_amp_backup "${backup}" path "${home}/elsewhere/defenseclaw.js"
  rc=0
  ${PY} "${SCRUB}" opencode "${plugin}" "${backup}" >/dev/null 2>&1 || rc=$?
  assert_status "${rc}" 4 "captured OpenCode target mismatch must refuse cleanup"
  out="$(cat "${plugin}")"
  assert_eq "${out}" "// unchanged managed plugin" "plugin preserved on path mismatch"
  assert_file_exists "${backup}"
}

t_opencode_caller_target_and_authority_binding_refuse() {
  local home other plugin backup wrong_target rc out
  home="$(mktest_tmp)"
  other="$(mktest_tmp)"
  plugin="${home}/.config/opencode/plugins/defenseclaw.js"
  backup="${home}/.defenseclaw/connector_backups/opencode/config.json"
  wrong_target="${home}/.config/opencode/plugins/not-defenseclaw.js"
  _make_opencode_fixture "${home}" "// unchanged managed plugin" false ""
  printf '%s' "// wrong target" > "${wrong_target}"

  rc=0
  ${PY} "${SCRUB}" opencode "${wrong_target}" "${backup}" >/dev/null 2>&1 || rc=$?
  assert_status "${rc}" 4 "caller-selected OpenCode target must be exact"
  rc=0
  mkdir -p "${other}/not-authority"
  cp "${backup}" "${other}/not-authority/config.json"
  chmod 0600 "${other}/not-authority/config.json"
  ${PY} "${SCRUB}" opencode "${plugin}" "${other}/not-authority/config.json" >/dev/null 2>&1 || rc=$?
  assert_status "${rc}" 4 "OpenCode authority must use the fixed per-user backup suffix"
  out="$(cat "${plugin}")"
  assert_eq "${out}" "// unchanged managed plugin" "plugin preserved on caller binding mismatch"
  assert_file_exists "${backup}"
}

t_opencode_authority_resolves_custom_config_root() {
  local home custom plugin backup rc
  home="$(mktest_tmp)"
  custom="${home}/custom/opencode"
  plugin="${custom}/plugins/defenseclaw.js"
  backup="${home}/.defenseclaw/connector_backups/opencode/config.json"
  _make_opencode_fixture "${home}" "// custom managed plugin" false "" 384 "${custom}"

  ${PY} "${SCRUB}" opencode --target-from-authority "${backup}"
  rc=$?; assert_status "${rc}" 0 "custom OpenCode target resolved from authority"
  if [[ -e "${plugin}" || -L "${plugin}" ]]; then
    _fail "custom OpenCode plugin created by setup was not removed"
  fi
  if [[ -e "${backup}" || -L "${backup}" ]]; then
    _fail "custom OpenCode authority was not consumed"
  fi

  _make_opencode_fixture "${home}" "// custom replacement" true "// custom pristine" 416 "${custom}"
  ${PY} "${SCRUB}" opencode --target-from-authority "${backup}"
  rc=$?; assert_status "${rc}" 0 "custom OpenCode pristine target restored from authority"
  assert_eq "$(cat "${plugin}")" "// custom pristine" "custom OpenCode pristine bytes restored"
}

t_opencode_cleanup_reentry_is_idempotent() {
  local home plugin backup rc
  home="$(mktest_tmp)"
  plugin="${home}/.config/opencode/plugins/defenseclaw.js"
  backup="${home}/.defenseclaw/connector_backups/opencode/config.json"

  _make_opencode_fixture "${home}" "// managed plugin" false ""
  rm -f "${plugin}"
  ${PY} "${SCRUB}" opencode --target-from-authority "${backup}"
  rc=$?; assert_status "${rc}" 0 "reentry consumes create-only authority after prior unlink"
  if [[ -e "${backup}" || -L "${backup}" ]]; then
    _fail "create-only authority survived idempotent reentry"
  fi

  _make_opencode_fixture "${home}" "// managed replacement" true "// pristine bytes" 416
  printf '%s' "// pristine bytes" > "${plugin}"
  chmod 0640 "${plugin}"
  ${PY} "${SCRUB}" opencode --target-from-authority "${backup}"
  rc=$?; assert_status "${rc}" 0 "reentry consumes restore authority after prior atomic restore"
  assert_eq "$(cat "${plugin}")" "// pristine bytes" "reentry preserves already-restored bytes"
  if [[ -e "${backup}" || -L "${backup}" ]]; then
    _fail "restore authority survived idempotent reentry"
  fi
}

t_opencode_missing_restore_target_refuses() {
  local home plugin backup rc
  home="$(mktest_tmp)"
  plugin="${home}/.config/opencode/plugins/defenseclaw.js"
  backup="${home}/.defenseclaw/connector_backups/opencode/config.json"
  _make_opencode_fixture "${home}" "// managed replacement" true "// pristine"
  rm -f "${plugin}"
  rc=0
  ${PY} "${SCRUB}" opencode --target-from-authority "${backup}" >/dev/null 2>&1 || rc=$?
  assert_status "${rc}" 4 "missing target with required restore state must refuse"
  assert_file_exists "${backup}"
}

t_opencode_darwin_write_acls_refuse() {
  [[ "$(uname -s)" == "Darwin" ]] || return 0
  local home plugin backup rc
  home="$(mktest_tmp)"
  plugin="${home}/.config/opencode/plugins/defenseclaw.js"
  backup="${home}/.defenseclaw/connector_backups/opencode/config.json"
  _make_opencode_fixture "${home}" "// managed plugin" false ""

  chmod +a "everyone allow write" "${plugin}"
  rc=0
  ${PY} "${SCRUB}" opencode --target-from-authority "${backup}" >/dev/null 2>&1 || rc=$?
  assert_status "${rc}" 4 "write-capable plugin ACL must refuse cleanup"
  chmod -N "${plugin}"

  chmod +a "everyone allow add_file" "$(dirname "${plugin}")"
  rc=0
  ${PY} "${SCRUB}" opencode --target-from-authority "${backup}" >/dev/null 2>&1 || rc=$?
  assert_status "${rc}" 4 "write-capable plugin-directory ACL must refuse cleanup"
  chmod -N "$(dirname "${plugin}")"

  chmod +a "everyone allow read" "${backup}"
  rc=0
  ${PY} "${SCRUB}" opencode --target-from-authority "${backup}" >/dev/null 2>&1 || rc=$?
  assert_status "${rc}" 4 "allow ACL on private authority must refuse cleanup"
  chmod -N "${backup}"
  assert_file_exists "${plugin}"
  assert_file_exists "${backup}"
}

t_opencode_nonprivate_authority_directory_refuses() {
  local home plugin backup rc
  home="$(mktest_tmp)"
  plugin="${home}/.config/opencode/plugins/defenseclaw.js"
  backup="${home}/.defenseclaw/connector_backups/opencode/config.json"
  _make_opencode_fixture "${home}" "// managed plugin" false ""
  chmod 0755 "$(dirname "${backup}")"
  rc=0
  ${PY} "${SCRUB}" opencode --target-from-authority "${backup}" >/dev/null 2>&1 || rc=$?
  assert_status "${rc}" 4 "non-private OpenCode authority directory must refuse cleanup"
  assert_file_exists "${plugin}"
  assert_file_exists "${backup}"
}

t_managed_restore_retains_authority_across_batch_retry() {
  local home amp_plugin amp_backup opencode_plugin opencode_backup rc
  home="$(mktest_tmp)"
  amp_plugin="${home}/.config/amp/plugins/defenseclaw.ts"
  amp_backup="${home}/.defenseclaw/connector_backups/amp/config.json"
  opencode_plugin="${home}/.config/opencode/plugins/defenseclaw.js"
  opencode_backup="${home}/.defenseclaw/connector_backups/opencode/config.json"
  _make_amp_fixture "${home}" "// managed replacement" true "// operator pristine" 416
  _make_opencode_fixture "${home}" "// managed opencode" false ""
  printf '%s' "// drifted opencode" > "${opencode_plugin}"

  # Production order runs Amp immediately before OpenCode. A later OpenCode
  # refusal must not strand an already-restored Amp file without its receipt.
  ${PY} "${SCRUB}" amp "${amp_plugin}" "${amp_backup}" --retain-authority
  rc=$?; assert_status "${rc}" 0 "batch scrub restores the managed plugin"
  assert_eq "$(cat "${amp_plugin}")" "// operator pristine" "batch scrub restores exact pristine bytes"
  assert_file_exists "${amp_backup}"

  rc=0
  ${PY} "${SCRUB}" opencode --target-from-authority "${opencode_backup}" \
    --retain-authority >/dev/null 2>&1 || rc=$?
  assert_status "${rc}" 4 "a later OpenCode refusal aborts the first batch"
  assert_eq "$(cat "${opencode_plugin}")" "// drifted opencode" \
    "the later refusal preserves the drifted OpenCode plugin"
  assert_file_exists "${amp_backup}"
  assert_file_exists "${opencode_backup}"

  printf '%s' "// managed opencode" > "${opencode_plugin}"
  chmod 0600 "${opencode_plugin}"
  ${PY} "${SCRUB}" amp "${amp_plugin}" "${amp_backup}" --retain-authority
  rc=$?; assert_status "${rc}" 0 "the restored managed plugin is safe on batch retry"
  ${PY} "${SCRUB}" opencode --target-from-authority "${opencode_backup}" --retain-authority
  rc=$?; assert_status "${rc}" 0 "the repaired later OpenCode scrub succeeds"
  if [[ -e "${opencode_plugin}" || -L "${opencode_plugin}" ]]; then
    _fail "the repaired managed OpenCode plugin survived its batch retry scrub"
  fi
  assert_file_exists "${amp_backup}"
  assert_file_exists "${opencode_backup}"

  rm -rf "${home}/.defenseclaw"
  if [[ -e "${amp_backup}" || -L "${amp_backup}" \
     || -e "${opencode_backup}" || -L "${opencode_backup}" ]]; then
    _fail "outer batch commit did not consume retained managed-plugin authority"
  fi
}

t_missing_file_returns_2() {
  ${PY} "${SCRUB}" cursor "/nonexistent/$(date +%s).json" 2>/dev/null
  local rc=$?; assert_status "${rc}" 2 "missing file returns 2"
}

t_unsupported_connector_returns_3() {
  local d; d="$(mktest_tmp)"
  printf '{}\n' > "${d}/x.json"
  ${PY} "${SCRUB}" geminicli "${d}/x.json" 2>/dev/null
  local rc=$?; assert_status "${rc}" 3 "unsupported connector returns 3"
}

t_garbage_json_returns_4() {
  local d; d="$(mktest_tmp)"
  printf 'this is not json\n' > "${d}/broken.json"
  ${PY} "${SCRUB}" cursor "${d}/broken.json" 2>/dev/null
  local rc=$?; assert_status "${rc}" 4 "garbage JSON returns 4"
}

t_empty_object_safe() {
  local d; d="$(mktest_tmp)"
  printf '{}\n' > "${d}/empty.json"
  ${PY} "${SCRUB}" cursor "${d}/empty.json"
  local rc=$?; assert_status "${rc}" 0 "empty JSON is a no-op"
}

run_case "cursor: drops DC, keeps user entry (idempotent)" t_cursor_drops_dc_keeps_user_entry
run_case "cursor: no-op without DC entries"                 t_cursor_no_op_when_no_dc_entries
run_case "claudecode: strips managed env keys"              t_claudecode_strips_managed_env_keys
run_case "claudecode: drops env block if only DC keys"      t_claudecode_drops_all_managed_env
run_case "claudecode: preserves theme/env"                  t_claudecode_preserves_non_hook_state
run_case "codex: strips managed sections"                   t_codex_strips_managed_sections
run_case "codex: stops at dotted/array table headers"       t_codex_stops_at_dotted_table_header
run_case "codex: strips top-level notify before any table" t_codex_strips_notify_before_any_table_header
run_case "codex: leaves unrelated [otel]/[hooks] alone"     t_codex_skips_unrelated_otel_or_hooks_blocks
run_case "amp: removes unchanged plugin created by setup"   t_amp_removes_unchanged_plugin_created_by_setup
run_case "amp: restores exact pristine plugin and mode"     t_amp_restores_exact_pristine_plugin_and_mode
run_case "amp: drift refuses and preserves authority"       t_amp_drift_refuses_and_preserves_plugin_and_backup
run_case "amp: invalid connector identity refuses"          t_amp_invalid_backup_identity_refuses
run_case "amp: captured path mismatch refuses"              t_amp_invalid_captured_path_refuses
run_case "amp: corrupt pristine hash refuses"               t_amp_invalid_pristine_hash_refuses_before_restore
run_case "amp: missing post hash refuses"                    t_amp_missing_post_hash_refuses_before_removal
run_case "amp: symlink target is never followed"            t_amp_symlink_plugin_refuses_without_touching_target
run_case "amp: hard-linked plugin refuses"                  t_amp_hardlinked_plugin_refuses
run_case "amp: non-private/missing backup refuses"          t_amp_nonprivate_or_missing_backup_refuses
run_case "managed plugin: exact backup schema types"         t_managed_backup_parser_rejects_noncanonical_types
run_case "managed plugin: ACL output parser fails closed"    t_darwin_acl_output_parser_is_fail_closed
run_case "managed plugin: in-place mutation refuses"         t_managed_in_place_mutations_refuse_before_commit
run_case "opencode: removes unchanged setup plugin"         t_opencode_removes_unchanged_plugin_created_by_setup
run_case "opencode: restores exact pristine plugin"         t_opencode_restores_exact_pristine_plugin_and_mode
run_case "opencode: drift preserves plugin and authority"   t_opencode_drift_refuses_and_preserves_authority
run_case "opencode: manifest identity/path mismatches refuse" t_opencode_manifest_identity_and_path_mismatches_refuse
run_case "opencode: caller target/authority binding refuses" t_opencode_caller_target_and_authority_binding_refuse
run_case "opencode: authority resolves custom target"        t_opencode_authority_resolves_custom_config_root
run_case "opencode: cleanup reentry is idempotent"           t_opencode_cleanup_reentry_is_idempotent
run_case "opencode: missing restore target refuses"          t_opencode_missing_restore_target_refuses
run_case "opencode: Darwin write ACLs refuse"                t_opencode_darwin_write_acls_refuse
run_case "opencode: non-private authority dir refuses"       t_opencode_nonprivate_authority_directory_refuses
run_case "managed plugin: batch failure retains retry authority" t_managed_restore_retains_authority_across_batch_retry
run_case "missing file returns 2"                           t_missing_file_returns_2
run_case "unsupported connector returns 3"                  t_unsupported_connector_returns_3
run_case "garbage JSON returns 4"                           t_garbage_json_returns_4
run_case "empty object is no-op"                            t_empty_object_safe
