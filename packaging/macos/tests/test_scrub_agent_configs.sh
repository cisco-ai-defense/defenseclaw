#!/usr/bin/env bash
# Scrub helper: remove DefenseClaw entries from user agent configs while
# preserving the user's own state. Driven by lib/scrub_agent_configs.py.
SCRUB="${PKG_DIR}/lib/scrub_agent_configs.py"
PY=/usr/bin/python3

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

run_case "cursor: drops DC, keeps user entry (idempotent)" t_cursor_drops_dc_keeps_user_entry
run_case "cursor: no-op without DC entries"                 t_cursor_no_op_when_no_dc_entries
run_case "claudecode: preserves theme/env"                  t_claudecode_preserves_non_hook_state
run_case "codex: strips managed sections"                   t_codex_strips_managed_sections
run_case "codex: leaves unrelated [otel]/[hooks] alone"     t_codex_skips_unrelated_otel_or_hooks_blocks
run_case "missing file returns 2"                           t_missing_file_returns_2
run_case "unsupported connector returns 3"                  t_unsupported_connector_returns_3
run_case "garbage JSON returns 4"                           t_garbage_json_returns_4
run_case "empty object is no-op"                            t_empty_object_safe
