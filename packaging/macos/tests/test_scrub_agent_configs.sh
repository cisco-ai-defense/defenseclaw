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

t_opencode_restores_pristine_plugin_exactly() {
  local d; d="$(mktest_tmp)"
  mkdir -p "${d}/plugins" "${d}/backups"
  local plugin="${d}/plugins/defenseclaw.js"
  local backup="${d}/backups/config.json"
  printf '// user plugin\nexport const user = true;\n' > "${plugin}"
  chmod 640 "${plugin}"
  PLUGIN="${plugin}" BACKUP="${backup}" ${PY} - <<'PY'
import base64, hashlib, json, os
path = os.environ["PLUGIN"]
pristine = open(path, "rb").read()
managed = b"// defenseclaw-managed-plugin v7\n"
open(path, "wb").write(managed)
backup = {
    "version": 1, "connector": "opencode", "logical_name": "config",
    "path": path, "existed": True, "mode": 0o640,
    "pristine_sha256": hashlib.sha256(pristine).hexdigest(),
    "post_sha256": hashlib.sha256(managed).hexdigest(),
    "pristine_bytes": base64.b64encode(pristine).decode(),
}
open(os.environ["BACKUP"], "w", encoding="utf-8").write(json.dumps(backup))
PY
  ${PY} "${SCRUB}" opencode "${plugin}" "${backup}"
  local rc=$?; assert_status "${rc}" 0 "OpenCode exact restore exits 0"
  assert_eq "$(cat "${plugin}")" $'// user plugin\nexport const user = true;' "pristine bytes restored"
  [[ ! -e "${backup}" ]] || _fail "OpenCode backup removed after successful restore"
  local mode; mode="$(stat -f '%Lp' "${plugin}" 2>/dev/null || stat -c '%a' "${plugin}")"
  assert_eq "${mode}" "640" "pristine mode restored"
}

t_opencode_removes_new_plugin() {
  local d; d="$(mktest_tmp)"
  mkdir -p "${d}/plugins" "${d}/backups"
  local plugin="${d}/plugins/defenseclaw.js"
  local backup="${d}/backups/config.json"
  printf '// defenseclaw-managed-plugin v7\n' > "${plugin}"
  PLUGIN="${plugin}" BACKUP="${backup}" ${PY} - <<'PY'
import hashlib, json, os
managed = open(os.environ["PLUGIN"], "rb").read()
backup = {
    "version": 1, "connector": "opencode", "logical_name": "config",
    "path": os.environ["PLUGIN"], "existed": False,
    "pristine_sha256": "missing",
    "post_sha256": hashlib.sha256(managed).hexdigest(),
}
open(os.environ["BACKUP"], "w", encoding="utf-8").write(json.dumps(backup))
PY
  ${PY} "${SCRUB}" opencode "${plugin}" "${backup}"
  local rc=$?; assert_status "${rc}" 0 "OpenCode removal exits 0"
  [[ ! -e "${plugin}" ]] || _fail "new managed OpenCode plugin removed"
  [[ ! -e "${backup}" ]] || _fail "OpenCode backup removed after successful cleanup"
}

t_opencode_preserves_tamper_and_backup() {
  local d; d="$(mktest_tmp)"
  mkdir -p "${d}/plugins" "${d}/backups"
  local plugin="${d}/plugins/defenseclaw.js"
  local backup="${d}/backups/config.json"
  printf '// defenseclaw-managed-plugin v7\n' > "${plugin}"
  PLUGIN="${plugin}" BACKUP="${backup}" ${PY} - <<'PY'
import hashlib, json, os
managed = open(os.environ["PLUGIN"], "rb").read()
backup = {
    "version": 1, "connector": "opencode", "logical_name": "config",
    "path": os.environ["PLUGIN"], "existed": False,
    "pristine_sha256": "missing",
    "post_sha256": hashlib.sha256(managed).hexdigest(),
}
open(os.environ["BACKUP"], "w", encoding="utf-8").write(json.dumps(backup))
PY
  printf '// user changed this after setup\n' > "${plugin}"
  ${PY} "${SCRUB}" opencode "${plugin}" "${backup}" 2>/dev/null
  local rc=$?; assert_status "${rc}" 5 "OpenCode drift returns custody error"
  assert_contains "$(cat "${plugin}")" "user changed" "tampered plugin preserved"
  [[ -f "${backup}" ]] || _fail "backup preserved when plugin drifted"
}

t_opencode_rejects_mismatched_restore_target() {
  local d; d="$(mktest_tmp)"
  mkdir -p "${d}/expected/plugins" "${d}/crafted/plugins" "${d}/backups"
  local expected="${d}/expected/plugins/defenseclaw.js"
  local crafted="${d}/crafted/plugins/defenseclaw.js"
  local backup="${d}/backups/config.json"
  printf '// expected target stays unchanged\n' > "${expected}"
  printf '// managed crafted target\n' > "${crafted}"
  CRAFTED="${crafted}" BACKUP="${backup}" ${PY} - <<'PY'
import base64, hashlib, json, os
managed = open(os.environ["CRAFTED"], "rb").read()
pristine = b"// crafted pristine bytes must not be restored\n"
backup = {
    "version": 1, "connector": "opencode", "logical_name": "config",
    "path": os.environ["CRAFTED"], "existed": True, "mode": 0o600,
    "pristine_sha256": hashlib.sha256(pristine).hexdigest(),
    "post_sha256": hashlib.sha256(managed).hexdigest(),
    "pristine_bytes": base64.b64encode(pristine).decode(),
}
open(os.environ["BACKUP"], "w", encoding="utf-8").write(json.dumps(backup))
PY
  local expected_before crafted_before rc
  expected_before="$(cat "${expected}")"
  crafted_before="$(cat "${crafted}")"
  ${PY} "${SCRUB}" opencode "${expected}" "${backup}" 2>/dev/null
  rc=$?
  assert_status "${rc}" 4 "OpenCode mismatched restore target fails closed"
  assert_eq "$(cat "${expected}")" "${expected_before}" "expected target unchanged on mismatch"
  assert_eq "$(cat "${crafted}")" "${crafted_before}" "crafted target not overwritten on mismatch"
  [[ -f "${backup}" ]] || _fail "backup preserved on restore-target mismatch"
}

t_opencode_rejects_mismatched_removal_target() {
  local d; d="$(mktest_tmp)"
  mkdir -p "${d}/expected/plugins" "${d}/crafted/plugins" "${d}/backups"
  local expected="${d}/expected/plugins/defenseclaw.js"
  local crafted="${d}/crafted/plugins/defenseclaw.js"
  local backup="${d}/backups/config.json"
  printf '// expected target stays unchanged\n' > "${expected}"
  printf '// managed crafted target\n' > "${crafted}"
  CRAFTED="${crafted}" BACKUP="${backup}" ${PY} - <<'PY'
import hashlib, json, os
managed = open(os.environ["CRAFTED"], "rb").read()
backup = {
    "version": 1, "connector": "opencode", "logical_name": "config",
    "path": os.environ["CRAFTED"], "existed": False,
    "pristine_sha256": "missing",
    "post_sha256": hashlib.sha256(managed).hexdigest(),
}
open(os.environ["BACKUP"], "w", encoding="utf-8").write(json.dumps(backup))
PY
  local expected_before crafted_before rc
  expected_before="$(cat "${expected}")"
  crafted_before="$(cat "${crafted}")"
  ${PY} "${SCRUB}" opencode "${expected}" "${backup}" 2>/dev/null
  rc=$?
  assert_status "${rc}" 4 "OpenCode mismatched removal target fails closed"
  assert_eq "$(cat "${expected}")" "${expected_before}" "expected target unchanged on mismatch"
  assert_eq "$(cat "${crafted}")" "${crafted_before}" "crafted target not deleted on mismatch"
  [[ -f "${backup}" ]] || _fail "backup preserved on removal-target mismatch"
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
run_case "missing file returns 2"                           t_missing_file_returns_2
run_case "unsupported connector returns 3"                  t_unsupported_connector_returns_3
run_case "garbage JSON returns 4"                           t_garbage_json_returns_4
run_case "empty object is no-op"                            t_empty_object_safe
run_case "opencode: restores pristine plugin exactly"       t_opencode_restores_pristine_plugin_exactly
run_case "opencode: removes newly-created plugin"           t_opencode_removes_new_plugin
run_case "opencode: preserves tamper and backup"             t_opencode_preserves_tamper_and_backup
run_case "opencode: rejects mismatched restore target"       t_opencode_rejects_mismatched_restore_target
run_case "opencode: rejects mismatched removal target"       t_opencode_rejects_mismatched_removal_target
