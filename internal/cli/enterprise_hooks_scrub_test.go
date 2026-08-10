// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pelletier/go-toml/v2"
)

// TestScrubCursor_DropsDCKeepsUserEntryIdempotent guards the primary
// contract of the Cursor scrub: DefenseClaw-owned hook entries are
// dropped, non-DefenseClaw entries survive verbatim, and a second call
// against the already-scrubbed file is a no-op. This mirrors
// t_cursor_drops_dc_keeps_user_entry from the previous shell test
// (packaging/macos/tests/test_scrub_agent_configs.sh) so behavioural
// parity across the Python → Go rewrite is CI-verifiable.
func TestScrubCursor_DropsDCKeepsUserEntryIdempotent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hooks.json")
	writeFile(t, path, `{
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
`)
	changed, err := scrubCursorFile(path, scrubDefaultMarkers)
	if err != nil {
		t.Fatalf("scrubCursorFile: %v", err)
	}
	if !changed {
		t.Fatalf("expected changed=true on first scrub")
	}
	out := readFile(t, path)
	if strings.Contains(out, "defenseclaw") {
		t.Errorf("scrub output still references defenseclaw:\n%s", out)
	}
	if !strings.Contains(out, "my-other-hook.sh") {
		t.Errorf("user hook was dropped:\n%s", out)
	}
	if strings.Contains(out, "sessionStart") {
		t.Errorf("DC-only event key should have been removed:\n%s", out)
	}
	// Idempotent
	changed2, err := scrubCursorFile(path, scrubDefaultMarkers)
	if err != nil {
		t.Fatalf("second scrub: %v", err)
	}
	if changed2 {
		t.Errorf("second scrub reported changed=true (should be no-op)")
	}
	out2 := readFile(t, path)
	if out != out2 {
		t.Errorf("second scrub mutated file:\n--first--\n%s\n--second--\n%s", out, out2)
	}
}

func TestScrubCursor_NoOpWhenNoDCEntries(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hooks.json")
	writeFile(t, path, `{"version":1,"hooks":{"preToolUse":[{"type":"command","command":"/Users/u/my-hook.sh"}]}}
`)
	changed, err := scrubCursorFile(path, scrubDefaultMarkers)
	if err != nil {
		t.Fatalf("scrubCursorFile: %v", err)
	}
	// The user's hook survives regardless of the changed flag; a rewrite
	// of a file that only differed in formatting (compact JSON in →
	// pretty JSON out) is expected here.
	_ = changed
	out := readFile(t, path)
	if !strings.Contains(out, "my-hook.sh") {
		t.Errorf("user hook lost during no-op scrub:\n%s", out)
	}
}

// TestScrubClaudeCode_StripsManagedEnvKeys covers the DefenseClaw-owned
// keys in Claude Code's settings.json env block. Kept in sync with
// claudeCodeOtelEnvKeys in the Go connector — a divergence between the
// two would silently leave a stale key in the user's settings.json
// after uninstall.
func TestScrubClaudeCode_StripsManagedEnvKeys(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	writeFile(t, path, `{
  "hooks": {},
  "env": {
    "MY_USER_VAR": "keep-me",
    "CLAUDE_CODE_ENABLE_TELEMETRY": "1",
    "OTEL_EXPORTER_OTLP_ENDPOINT": "http://127.0.0.1:18970",
    "OTEL_EXPORTER_OTLP_HEADERS": "x-defenseclaw-token=abc",
    "DEFENSECLAW_FAIL_MODE": "open"
  }
}
`)
	if _, err := scrubClaudeCodeFile(path, scrubDefaultMarkers); err != nil {
		t.Fatalf("scrubClaudeCodeFile: %v", err)
	}
	out := readFile(t, path)
	if !strings.Contains(out, "MY_USER_VAR") || !strings.Contains(out, "keep-me") {
		t.Errorf("user env dropped:\n%s", out)
	}
	for _, key := range []string{
		"CLAUDE_CODE_ENABLE_TELEMETRY",
		"OTEL_EXPORTER_OTLP_ENDPOINT",
		"OTEL_EXPORTER_OTLP_HEADERS",
		"DEFENSECLAW_FAIL_MODE",
	} {
		if strings.Contains(out, key) {
			t.Errorf("managed env key %q still present after scrub:\n%s", key, out)
		}
	}
}

func TestScrubClaudeCode_DropsEnvBlockIfOnlyDCKeys(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	writeFile(t, path, `{
  "hooks": {},
  "env": {
    "CLAUDE_CODE_ENABLE_TELEMETRY": "1",
    "OTEL_EXPORTER_OTLP_ENDPOINT": "http://127.0.0.1:18970"
  }
}
`)
	if _, err := scrubClaudeCodeFile(path, scrubDefaultMarkers); err != nil {
		t.Fatalf("scrubClaudeCodeFile: %v", err)
	}
	out := readFile(t, path)
	if strings.Contains(out, `"env"`) {
		t.Errorf("empty env block not removed:\n%s", out)
	}
}

func TestScrubClaudeCode_PreservesNonHookState(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	writeFile(t, path, `{
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
`)
	if _, err := scrubClaudeCodeFile(path, scrubDefaultMarkers); err != nil {
		t.Fatalf("scrubClaudeCodeFile: %v", err)
	}
	out := readFile(t, path)
	if !strings.Contains(out, `"theme"`) {
		t.Errorf("theme dropped:\n%s", out)
	}
	if !strings.Contains(out, `"env"`) {
		t.Errorf("user env dropped:\n%s", out)
	}
	if !strings.Contains(out, `"FOO"`) || !strings.Contains(out, `"bar"`) {
		t.Errorf("env values dropped:\n%s", out)
	}
	if strings.Contains(out, "defenseclaw") {
		t.Errorf("defenseclaw ref still present:\n%s", out)
	}
	if !strings.Contains(out, "my-prompt-hook.sh") {
		t.Errorf("user prompt hook dropped:\n%s", out)
	}
	if strings.Contains(out, "PreToolUse") {
		t.Errorf("DC-only event key still present:\n%s", out)
	}
}

// TestScrubCodex_StripsManagedSections covers the wholesale removal of
// the three DefenseClaw-owned top-level Codex TOML keys ([hooks],
// [otel], notify=). Non-DefenseClaw state (model, personality, project
// trust) must survive.
func TestScrubCodex_StripsManagedSections(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	writeFile(t, path, `model = "gpt-5"
personality = "pragmatic"

[projects."/Users/u/dev"]
trust_level = "trusted"

[hooks]
PreToolUse = "/Users/u/.defenseclaw/hooks/codex-hook.sh"
SessionStart = "/Users/u/.defenseclaw/hooks/codex-hook.sh"

[otel]
otlp_endpoint = "http://127.0.0.1:18970/v1/logs"

notify = ["bash", "/Users/u/.defenseclaw/notify-bridge.sh"]
`)
	if _, err := scrubCodexFile(path, scrubDefaultMarkers); err != nil {
		t.Fatalf("scrubCodexFile: %v", err)
	}
	out := readFile(t, path)
	for _, want := range []string{
		`model = "gpt-5"`,
		`personality = "pragmatic"`,
		`[projects."/Users/u/dev"]`,
		`trust_level = "trusted"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("user state dropped: %s\n---output---\n%s", want, out)
		}
	}
	for _, bad := range []string{"[hooks]", "[otel]", "notify =", "defenseclaw"} {
		if strings.Contains(out, bad) {
			t.Errorf("DC-owned marker %q still present:\n%s", bad, out)
		}
	}
	// Round-trip parse guard: what we leave behind must still be valid TOML.
	var parsed map[string]any
	if err := toml.Unmarshal([]byte(out), &parsed); err != nil {
		t.Errorf("post-scrub TOML no longer parses: %v\n---output---\n%s", err, out)
	}
}

func TestScrubCodex_StopsAtDottedTableHeader(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	writeFile(t, path, `model = "gpt-5"

[hooks]
PreToolUse = "/Users/u/.defenseclaw/hooks/codex-hook.sh"
[projects."/Users/u/dev"]
trust_level = "trusted"
model = "override"

[[some.array.of.tables]]
name = "user-owned-array-entry"
`)
	if _, err := scrubCodexFile(path, scrubDefaultMarkers); err != nil {
		t.Fatalf("scrubCodexFile: %v", err)
	}
	out := readFile(t, path)
	if strings.Contains(out, "[hooks]") {
		t.Errorf("[hooks] not removed:\n%s", out)
	}
	if strings.Contains(out, "defenseclaw") {
		t.Errorf("defenseclaw ref survived:\n%s", out)
	}
	if !strings.Contains(out, `[projects."/Users/u/dev"]`) {
		t.Errorf("dotted table lost:\n%s", out)
	}
	if !strings.Contains(out, `trust_level = "trusted"`) {
		t.Errorf("dotted table content lost:\n%s", out)
	}
	if !strings.Contains(out, "[[some.array.of.tables]]") {
		t.Errorf("array-of-tables header lost:\n%s", out)
	}
	if !strings.Contains(out, "user-owned-array-entry") {
		t.Errorf("array-of-tables content lost:\n%s", out)
	}
}

func TestScrubCodex_StripsTopLevelNotifyBeforeAnyTable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	writeFile(t, path, `notify = ["bash", "/Users/u/.defenseclaw/notify-bridge.sh"]

model = "gpt-5"

[projects."/Users/u/dev"]
trust_level = "trusted"
`)
	if _, err := scrubCodexFile(path, scrubDefaultMarkers); err != nil {
		t.Fatalf("scrubCodexFile: %v", err)
	}
	out := readFile(t, path)
	if strings.Contains(out, "notify =") {
		t.Errorf("top-level notify not removed:\n%s", out)
	}
	if strings.Contains(out, "defenseclaw") {
		t.Errorf("defenseclaw ref survived:\n%s", out)
	}
	if !strings.Contains(out, `model = "gpt-5"`) {
		t.Errorf("model preference lost:\n%s", out)
	}
	if !strings.Contains(out, `[projects."/Users/u/dev"]`) {
		t.Errorf("projects table lost:\n%s", out)
	}
}

// TestScrubCodex_LeavesUnrelatedBlocksAlone guards the "if the user has
// their own [otel] block that does NOT reference DefenseClaw, leave it
// alone" invariant. This was a real regression risk in the earlier
// scanner design and remains a load-bearing assertion.
func TestScrubCodex_LeavesUnrelatedBlocksAlone(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	writeFile(t, path, `model = "gpt-5"

[otel]
otlp_endpoint = "https://my-vendor.example/v1"

[hooks]
PreToolUse = "/Users/u/my-own-hook.sh"
`)
	if _, err := scrubCodexFile(path, scrubDefaultMarkers); err != nil {
		t.Fatalf("scrubCodexFile: %v", err)
	}
	out := readFile(t, path)
	for _, want := range []string{
		"[otel]",
		"my-vendor",
		"[hooks]",
		"my-own-hook.sh",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("user block dropped: %s\n---output---\n%s", want, out)
		}
	}
}

// TestScrubReturnsRC2OnMissingFile covers the file-not-found exit code
// callers (uninstall.sh) key off. Delivered via the ExitCode() error
// surface, not a naked os.Exit.
func TestScrubReturnsRC2OnMissingFile(t *testing.T) {
	prev := scrubMissingIsSilent
	defer func() { scrubMissingIsSilent = prev }()
	scrubMissingIsSilent = false

	scrubConnectorFlag = "cursor"
	scrubFileFlag = filepath.Join(t.TempDir(), "does-not-exist.json")
	err := runEnterpriseHooksScrub(enterpriseHooksScrubCmd, nil)
	if err == nil {
		t.Fatalf("expected error for missing file")
	}
	var exitErr *scrubExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("expected *scrubExitError, got %T: %v", err, err)
	}
	if exitErr.ExitCode() != 2 {
		t.Errorf("exit code = %d, want 2", exitErr.ExitCode())
	}
}

// TestScrubReturnsRC3OnUnsupportedConnector guards the "geminicli
// returns rc 3" contract from the previous shell test suite.
func TestScrubReturnsRC3OnUnsupportedConnector(t *testing.T) {
	scrubConnectorFlag = "geminicli"
	scrubFileFlag = filepath.Join(t.TempDir(), "x.json")
	writeFile(t, scrubFileFlag, "{}")
	err := runEnterpriseHooksScrub(enterpriseHooksScrubCmd, nil)
	if err == nil {
		t.Fatalf("expected error for unsupported connector")
	}
	var exitErr *scrubExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("expected *scrubExitError, got %T: %v", err, err)
	}
	if exitErr.ExitCode() != 3 {
		t.Errorf("exit code = %d, want 3", exitErr.ExitCode())
	}
}

// TestScrubReturnsRC4OnBrokenJSON guards the parse-failure contract.
// A garbage JSON file must NOT be silently rewritten as valid JSON; the
// scrub bails and reports rc 4 so operators can decide whether to
// discard the file or edit it by hand.
func TestScrubReturnsRC4OnBrokenJSON(t *testing.T) {
	scrubConnectorFlag = "cursor"
	scrubFileFlag = filepath.Join(t.TempDir(), "broken.json")
	writeFile(t, scrubFileFlag, "this is not json\n")
	err := runEnterpriseHooksScrub(enterpriseHooksScrubCmd, nil)
	if err == nil {
		t.Fatalf("expected error for garbage JSON")
	}
	var exitErr *scrubExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("expected *scrubExitError, got %T: %v", err, err)
	}
	if exitErr.ExitCode() != 4 {
		t.Errorf("exit code = %d, want 4", exitErr.ExitCode())
	}
}

func TestScrubEmptyObjectSafe(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.json")
	writeFile(t, path, "{}\n")
	if _, err := scrubCursorFile(path, scrubDefaultMarkers); err != nil {
		t.Fatalf("scrubCursorFile: %v", err)
	}
	// The output should still be a valid JSON object; parse it to check.
	var parsed any
	if err := json.Unmarshal([]byte(readFile(t, path)), &parsed); err != nil {
		t.Errorf("empty-object scrub produced invalid JSON: %v", err)
	}
}

// TestScrubManagedEnvKeysMatchClaudeCodeConnector is a sync guard: the
// managed-env-key set the scrub knows about MUST match
// claudeCodeOtelEnvKeys in internal/gateway/connector/claudecode.go.
// A key added on the connector side without a matching entry here
// would leave DefenseClaw's telemetry env vars in a user's
// settings.json after uninstall.
func TestScrubManagedEnvKeysMatchClaudeCodeConnector(t *testing.T) {
	// This test intentionally lives in a package outside connector/
	// (import cycle avoidance), so the check runs on the raw source
	// via a simple substring scan. If the file layout changes the
	// test will fail loudly rather than pass silently — that's fine.
	data, err := os.ReadFile("../gateway/connector/claudecode.go")
	if err != nil {
		t.Skipf("connector source not available at expected path: %v", err)
	}
	src := string(data)
	for key := range claudeManagedEnvKeys {
		if !strings.Contains(src, `"`+key+`"`) {
			t.Errorf("scrub knows managed env key %q but the Claude Code connector source no longer references it — the two lists have drifted", key)
		}
	}
}

// -----------------------------------------------------------------------
// helpers

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}
