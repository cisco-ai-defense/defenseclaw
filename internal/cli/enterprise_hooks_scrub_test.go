// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
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

// TestScrubCodex_PreservesNotifyInsideUserTable is a regression guard for
// the top-level-only scoping of the `notify =` scrub. DefenseClaw owns the
// FILE-LEVEL notify array (invoked before any [table] header). If a user
// puts a `notify = [...]` inside a table they own (e.g. per-project
// alerting under [projects."/Users/u/dev"]) and its value happens to
// contain one of our markers as a substring, the earlier scanner would
// still delete it — a real risk when markers include short strings like
// "notify-bridge.sh". Assert the top-level flag flips at the first table
// header and gates the notify branch.
func TestScrubCodex_PreservesNotifyInsideUserTable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	writeFile(t, path, `model = "gpt-5"

[projects."/Users/u/dev"]
trust_level = "trusted"
notify = ["bash", "/tmp/notify-bridge.sh"]

[projects."/Users/u/otherdir"]
trust_level = "trusted"
`)
	if _, err := scrubCodexFile(path, scrubDefaultMarkers); err != nil {
		t.Fatalf("scrubCodexFile: %v", err)
	}
	out := readFile(t, path)
	if !strings.Contains(out, `notify = ["bash", "/tmp/notify-bridge.sh"]`) {
		t.Errorf("in-table notify was scrubbed; DC-owned scrub must only affect the top-level array:\n%s", out)
	}
	if !strings.Contains(out, `[projects."/Users/u/dev"]`) {
		t.Errorf("user projects table lost:\n%s", out)
	}
	if !strings.Contains(out, `[projects."/Users/u/otherdir"]`) {
		t.Errorf("second user projects table lost:\n%s", out)
	}
}

// TestScrubCodex_PreservesUserLocalOtelCollector is a regression guard
// for a real endpoint-software failure mode: developers commonly run
// their own OTel collector on loopback (jaeger-all-in-one, Grafana
// Alloy, otel-desktop-viewer, etc.) at http://localhost:4318 or
// http://127.0.0.1:4318. The prior scrub keyed on `127.0.0.1` /
// `localhost` as sufficient markers, which would wipe those user
// blocks on uninstall. Behaviour after tightening: the block is
// only classified as DefenseClaw-managed when it carries a
// DC-authored header substring, so a plain user block survives.
func TestScrubCodex_PreservesUserLocalOtelCollector(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	writeFile(t, path, `model = "gpt-5"

[otel]
log_user_prompt = false
[otel.exporter.otlp-http]
endpoint = "http://127.0.0.1:4318"
protocol = "grpc"
`)
	if _, err := scrubCodexFile(path, scrubDefaultMarkers); err != nil {
		t.Fatalf("scrubCodexFile: %v", err)
	}
	out := readFile(t, path)
	if !strings.Contains(out, "[otel]") {
		t.Errorf("user local OTel [otel] block was scrubbed:\n%s", out)
	}
	if !strings.Contains(out, "127.0.0.1:4318") {
		t.Errorf("user local OTel endpoint was scrubbed:\n%s", out)
	}
}

// TestScrubCodex_StillScrubsDefenseClawOtelBlock complements the
// user-collector guard: the DC-authored [otel] block (which contains
// the x-defenseclaw-* header substrings that the codex connector
// emits) MUST still be scrubbed. Guards against over-tightening the
// marker set to the point where the DC block itself no longer matches.
func TestScrubCodex_StillScrubsDefenseClawOtelBlock(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	writeFile(t, path, `model = "gpt-5"

[otel]
log_user_prompt = false
[otel.exporter.otlp-http]
endpoint = "http://127.0.0.1:18970"
protocol = "json"
[otel.exporter.otlp-http.headers]
x-defenseclaw-source = "codex"
x-defenseclaw-client = "codex-otel/1.0"
x-defenseclaw-token = "abc"
`)
	if _, err := scrubCodexFile(path, scrubDefaultMarkers); err != nil {
		t.Fatalf("scrubCodexFile: %v", err)
	}
	out := readFile(t, path)
	if strings.Contains(out, "[otel]") {
		t.Errorf("DC-owned [otel] block survived scrub:\n%s", out)
	}
	if strings.Contains(out, "x-defenseclaw") {
		t.Errorf("DC header substrings survived scrub:\n%s", out)
	}
	if !strings.Contains(out, `model = "gpt-5"`) {
		t.Errorf("model preference was lost:\n%s", out)
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

// setScrubFlags atomically swaps the package-level flag vars for the
// duration of one test and restores the previous values via
// t.Cleanup. Kept as a shared helper so the exit-code tests can't
// leak flag state into anything a future `t.Parallel()` call adds —
// or a new test that reads these vars without assigning them.
func setScrubFlags(t *testing.T, connector, file string, quietMissing bool) {
	t.Helper()
	prevConn, prevFile, prevQuiet := scrubConnectorFlag, scrubFileFlag, scrubMissingIsSilent
	t.Cleanup(func() {
		scrubConnectorFlag, scrubFileFlag, scrubMissingIsSilent = prevConn, prevFile, prevQuiet
	})
	scrubConnectorFlag, scrubFileFlag, scrubMissingIsSilent = connector, file, quietMissing
}

// TestScrubReturnsRC2OnMissingFile covers the file-not-found exit code
// callers (uninstall.sh) key off. Delivered via the ExitCode() error
// surface, not a naked os.Exit.
func TestScrubReturnsRC2OnMissingFile(t *testing.T) {
	setScrubFlags(t, "cursor", filepath.Join(t.TempDir(), "does-not-exist.json"), false)
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
	filePath := filepath.Join(t.TempDir(), "x.json")
	writeFile(t, filePath, "{}")
	setScrubFlags(t, "geminicli", filePath, false)
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
	filePath := filepath.Join(t.TempDir(), "broken.json")
	writeFile(t, filePath, "this is not json\n")
	setScrubFlags(t, "cursor", filePath, false)
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

// TestExitCodeFor_HandlesAllContracts drives the pure
// error-to-int mapping cli.Execute delegates to. All three branches
// of the contract must hold:
//
//   - nil                      -> 0
//   - wrapped ExitCode() err   -> that code (via errors.As, not a
//     bare type assertion — a wrapped exit-coded error would
//     otherwise collapse to rc 1 and break uninstall.sh's branching
//     on rc 2/3/4)
//   - any other non-nil err    -> 1
//
// Testing exitCodeFor directly (rather than errors.As independently)
// locks the shell-callable contract into a single named entry point
// that Execute delegates to.
func TestExitCodeFor_HandlesAllContracts(t *testing.T) {
	if rc := exitCodeFor(nil); rc != 0 {
		t.Errorf("exitCodeFor(nil) = %d, want 0", rc)
	}
	if rc := exitCodeFor(errors.New("random failure")); rc != 1 {
		t.Errorf("exitCodeFor(<plain error>) = %d, want 1", rc)
	}

	// The critical case: wrapped scrubExitError. Two levels of
	// wrapping mirrors any future fmt.Errorf("context: %w", err)
	// site that could appear along the return path from a RunE
	// without breaking exit-code propagation.
	inner := &scrubExitError{code: 2, msg: "missing file"}
	wrapped := fmt.Errorf("outer: %w", fmt.Errorf("inner: %w", inner))
	if rc := exitCodeFor(wrapped); rc != 2 {
		t.Errorf("exitCodeFor(<double-wrapped rc 2>) = %d, want 2 — errors.As must unwrap through %%w layers", rc)
	}

	// rc 3 and rc 4 too so the guard catches a hypothetical
	// regression where exitCodeFor accidentally masks to a single
	// value.
	for _, want := range []int{3, 4} {
		wrapped := fmt.Errorf("wrap: %w", &scrubExitError{code: want, msg: "x"})
		if rc := exitCodeFor(wrapped); rc != want {
			t.Errorf("exitCodeFor(<wrapped rc %d>) = %d, want %d", want, rc, want)
		}
	}

	// Concrete-type guard: unrelated types that happen to satisfy
	// `interface{ ExitCode() int }` — most importantly
	// *os/exec.ExitError from a spawned subprocess — MUST collapse
	// to rc 1. A generic interface-based match would silently
	// propagate the subprocess exit code as OUR exit code, which
	// collides with our own well-defined statuses.
	//
	// Rather than shelling out to /bin/sh (missing/renamed on
	// Windows CI runners, on certain container images, and inside
	// hermetic sandboxes), re-execute the test binary itself with an
	// environment flag that trips the exit-42 side branch in
	// TestMain. This is the same self-exec helper-process pattern
	// used across the Go stdlib. Portable, and it exercises
	// *os/exec.ExitError with the exact wire shape a real subprocess
	// call would produce.
	helper := exec.Command(os.Args[0], "-test.run=^$")
	helper.Env = append(os.Environ(), scrubExitHelperEnv+"=42")
	subprocErr := helper.Run()
	if subprocErr == nil {
		t.Fatalf("subprocess sanity check: expected non-nil error from `exit 42` helper")
	}
	// Sanity: subprocErr does implement ExitCode() int via
	// *exec.ExitError, so this test would fail against the older
	// generic-interface match. Confirm via a direct type assertion
	// that this is the case we care about.
	if _, ok := subprocErr.(*exec.ExitError); !ok {
		t.Fatalf("subprocess sanity check: expected *exec.ExitError, got %T", subprocErr)
	}
	if rc := exitCodeFor(subprocErr); rc != 1 {
		t.Errorf("exitCodeFor(*exec.ExitError rc 42) = %d, want 1 (subprocess exit codes must not leak into our contract)", rc)
	}
}

// scrubExitHelperEnv names an env-var flag that, when set during test
// binary startup, causes TestMain to os.Exit with the flag's numeric
// value BEFORE any test cases run. Consumed by
// TestExitCodeFor_HandlesAllContracts's self-exec helper-process
// path — see the exec.Command call there for the pairing.
const scrubExitHelperEnv = "DC_SCRUB_TEST_EXIT"

// TestMain intercepts the helper-process re-exec. When
// scrubExitHelperEnv is set to a numeric string, exit immediately
// with that status. When unset, forward to the standard test runner
// so all other tests execute normally.
func TestMain(m *testing.M) {
	if raw, ok := os.LookupEnv(scrubExitHelperEnv); ok {
		code, err := strconv.Atoi(strings.TrimSpace(raw))
		if err != nil {
			// Malformed helper request — surface via a distinct
			// non-zero code so the parent test sees the mismatch
			// rather than a matching-by-accident rc 1.
			fmt.Fprintf(os.Stderr, "scrub test helper: bad %s=%q: %v\n", scrubExitHelperEnv, raw, err)
			os.Exit(120)
		}
		os.Exit(code)
	}
	os.Exit(m.Run())
}

// TestScrubClaudeCode_PreservesHTMLBytesInStringValues guards
// byte-idempotency across the Python -> Go rewrite. Python's
// `json.dumps(sort_keys=True, indent=2)` (the shape the previous
// scrubber wrote) does NOT HTML-escape `<`, `>`, `&`. Go's
// `json.Marshal` DOES by default. A settings.json that was previously
// scrubbed by the Python variant and contains e.g. an env value with
// an ampersand or an angle bracket would fail the `bytes.Equal(buf,
// original)` early-return in writeSortedJSON, forcing an unnecessary
// rewrite every scrub run (mtime bump, file-watcher wakeups) even
// when no DC content is present. Assert `&`, `<`, `>` survive
// verbatim in a no-op scrub.
func TestScrubClaudeCode_PreservesHTMLBytesInStringValues(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	// Content shaped like `json.dumps(sort_keys=True, indent=2)` with
	// no HTML escaping — this is the exact byte shape the old Python
	// scrubber would leave a user's file in.
	original := `{
  "env": {
    "MY_QS": "https://example.com/?x=1&y=2",
    "MY_LIT": "<template>foo</template>"
  },
  "theme": "dark"
}
`
	writeFile(t, path, original)
	if _, err := scrubClaudeCodeFile(path, scrubDefaultMarkers); err != nil {
		t.Fatalf("scrubClaudeCodeFile: %v", err)
	}
	out := readFile(t, path)
	// Positive check: the raw HTML-bearing bytes survive verbatim.
	for _, want := range []string{
		`"https://example.com/?x=1&y=2"`,
		`"<template>foo</template>"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("HTML byte(s) were escaped or dropped: expected verbatim %q\n---output---\n%s", want, out)
		}
	}
	// Negative check: Go's default SetEscapeHTML=true would emit
	// the `<`, `>`, `&` byte sequences in place of
	// `<`, `>`, `&`. Those escape SEQUENCES MUST NOT appear in the
	// output. Use \u-escape literals here so the source text
	// matches the exact 6-character on-disk shape the JSON encoder
	// would have produced.
	for _, bad := range []string{"\\u003c", "\\u003e", "\\u0026"} {
		if strings.Contains(out, bad) {
			t.Errorf("output contains JSON \\uXXXX escape %q — SetEscapeHTML=false must preserve the raw byte to stay Python-idempotent\n%s", bad, out)
		}
	}
}

// TestScrubCursor_ThroughSymlinkPreservesLink is a regression guard
// for chezmoi / GNU stow / homeshick / vcsh users whose agent config
// lives symlinked into a ~/.dotfiles/... tree. The scrub must:
//
//  1. Resolve the symlink and rewrite the concrete target file
//     (so the agent sees the scrubbed content when it re-reads).
//  2. Leave the symlink itself intact (so `stow --restow` doesn't
//     re-link, and the user's dotfiles workflow keeps working).
//
// Behaviour before this fix: writeConfigAtomic refused symlinks
// entirely with rc 4 → uninstall.sh set SCRUB_FAILED → refused to
// delete ~/.defenseclaw → uninstall exited 1 on every chezmoi user.
func TestScrubCursor_ThroughSymlinkPreservesLink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "dotfiles-cursor-hooks.json")
	link := filepath.Join(dir, "hooks.json")
	writeFile(t, target, `{
  "version": 1,
  "hooks": {
    "preToolUse": [
      {"type":"command","command":"/Users/u/.defenseclaw/hooks/cursor-hook.sh"},
      {"type":"command","command":"/Users/u/.local/bin/keep-me.sh"}
    ]
  }
}
`)
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if _, err := scrubCursorFile(link, scrubDefaultMarkers); err != nil {
		t.Fatalf("scrubCursorFile through symlink: %v", err)
	}
	// The symlink itself must survive.
	linkInfo, err := os.Lstat(link)
	if err != nil {
		t.Fatalf("lstat symlink after scrub: %v", err)
	}
	if linkInfo.Mode()&os.ModeSymlink == 0 {
		t.Errorf("symlink was replaced with a regular file — dotfiles workflow broken")
	}
	// And it must still point at the same target.
	if p, err := os.Readlink(link); err != nil || p != target {
		t.Errorf("symlink target changed: got %q want %q (err=%v)", p, target, err)
	}
	// The scrubbed content must land in the concrete target file.
	out := readFile(t, target)
	if strings.Contains(out, "defenseclaw") {
		t.Errorf("DC entry survived scrub through symlink:\n%s", out)
	}
	if !strings.Contains(out, "keep-me.sh") {
		t.Errorf("user entry lost during scrub through symlink:\n%s", out)
	}
}

// TestScrubCursor_ChainedSymlinksResolveToConcreteTarget guards the
// bounded-loop symlink resolution. Dotfiles workflows sometimes stack
// links (chezmoi manages a source dir that itself is a symlink into a
// worktree, for example). A single-hop resolver would land on the
// intermediate link and rewrite THAT with a regular file, breaking
// the outer indirection. Assert the scrub walks the chain to the
// concrete target.
func TestScrubCursor_ChainedSymlinksResolveToConcreteTarget(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "final-target.json")
	mid := filepath.Join(dir, "mid.json")
	link := filepath.Join(dir, "hooks.json")
	writeFile(t, target, `{
  "hooks": {
    "preToolUse": [
      {"type":"command","command":"/Users/u/.defenseclaw/hooks/cursor-hook.sh"},
      {"type":"command","command":"/Users/u/.local/bin/keep-me.sh"}
    ]
  }
}
`)
	if err := os.Symlink(target, mid); err != nil {
		t.Fatalf("symlink mid: %v", err)
	}
	if err := os.Symlink(mid, link); err != nil {
		t.Fatalf("symlink link: %v", err)
	}
	if _, err := scrubCursorFile(link, scrubDefaultMarkers); err != nil {
		t.Fatalf("scrubCursorFile through chained symlinks: %v", err)
	}
	// Both symlinks must survive.
	for _, p := range []string{link, mid} {
		info, err := os.Lstat(p)
		if err != nil {
			t.Fatalf("lstat %s after scrub: %v", p, err)
		}
		if info.Mode()&os.ModeSymlink == 0 {
			t.Errorf("chained-symlink hop %s was replaced with a regular file", p)
		}
	}
	// Concrete target has the scrubbed content.
	out := readFile(t, target)
	if strings.Contains(out, "defenseclaw") {
		t.Errorf("DC entry survived scrub through chained symlinks:\n%s", out)
	}
	if !strings.Contains(out, "keep-me.sh") {
		t.Errorf("user entry lost during scrub through chained symlinks:\n%s", out)
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
// managed-env-key set the scrub knows about MUST equal (both
// directions) the OTel keys listed in claudeCodeOtelEnvKeys inside
// internal/gateway/connector/claudecode.go.
//
// Both directions matter:
//
//   - scrub → connector: a scrub-known key that the connector doesn't
//     write anymore is dead code, but it also means we're documenting
//     a policy that no longer matches the code path — the two must
//     agree so an uninstall doesn't strip a name the connector never
//     wrote.
//   - connector → scrub: a connector-newly-added key that the scrub
//     doesn't know about survives the uninstall, leaves stale
//     telemetry env vars in a user's settings.json, and (worse) can
//     silently redirect Claude Code's OTLP traffic to
//     http://127.0.0.1:18970 with no gateway listening. That's the
//     load-bearing regression this test guards against.
//
// Failing loudly on a connector-source read failure (rather than
// t.Skipf'ing) matches the "fail loudly if the guard is broken" goal:
// a rename, refactor, or file-tree reshuffle that hides
// claudecode.go from the test would silently drop this coverage.
func TestScrubManagedEnvKeysMatchClaudeCodeConnector(t *testing.T) {
	// This test intentionally lives in a package outside connector/
	// (import cycle avoidance), so the check runs on the raw source
	// via a simple substring scan.
	connectorPath := "../gateway/connector/claudecode.go"
	data, err := os.ReadFile(connectorPath)
	if err != nil {
		t.Fatalf("cannot read connector source at %s: %v — this is the sync-guard's data source; if the file moved, update the path here so the guard keeps running", connectorPath, err)
	}
	src := string(data)

	// Forward direction: every scrub-known key must appear as a string
	// literal in the connector source.
	for key := range claudeManagedEnvKeys {
		if !strings.Contains(src, `"`+key+`"`) {
			t.Errorf("scrub knows managed env key %q but the Claude Code connector source no longer references it — the two lists have drifted (drop the key from claudeManagedEnvKeys if the connector no longer writes it)", key)
		}
	}

	// Reverse direction: every key literally listed in claudeCodeOtelEnvKeys
	// must be present in claudeManagedEnvKeys. Parse the connector's
	// literal block by name so we don't false-positive on unrelated
	// string literals scattered elsewhere in the file. If the block
	// literal isn't found we fail hard — same "fail loudly" rationale
	// as the file-read guard above.
	block := extractGoStringSliceLiteral(t, src, "claudeCodeOtelEnvKeys")
	if len(block) == 0 {
		t.Fatalf("could not locate claudeCodeOtelEnvKeys literal in %s — the guard needs to enumerate it to check reverse coverage; if the variable was renamed or restructured update this test", connectorPath)
	}
	for _, key := range block {
		if _, ok := claudeManagedEnvKeys[key]; !ok {
			t.Errorf("Claude Code connector writes managed env key %q but scrub's claudeManagedEnvKeys does not include it — add it to internal/cli/enterprise_hooks_scrub.go so `defenseclaw enterprise hooks scrub --connector claudecode` strips it on uninstall", key)
		}
	}
}

// extractGoStringSliceLiteral pulls the string entries out of a `var
// NAME = []string{ "A", "B", ... }` declaration. Deliberately minimal
// — this guard only needs to enumerate the Claude Code OTel key list,
// which is a flat literal on one line-per-entry shape. Anything more
// intricate (multi-line initialisers, referenced constants) belongs in
// a proper go/parser + type-check pipeline; we don't need that here
// because the connector source is a single well-known file whose
// shape we control.
func extractGoStringSliceLiteral(t *testing.T, src, name string) []string {
	t.Helper()
	// Anchor on `<name> = []string{` (allowing var/const in front) and
	// capture through the balancing `}`. Nested braces inside string
	// literals are impossible here (keys are simple identifiers), so a
	// non-greedy match against the first `}` is sufficient.
	re := regexp.MustCompile(`(?s)\b` + regexp.QuoteMeta(name) + `\s*=\s*\[\]string\s*\{(.*?)\}`)
	m := re.FindStringSubmatch(src)
	if len(m) < 2 {
		return nil
	}
	body := m[1]
	// Pull every `"quoted-string"` inside the body. Comments in Go
	// source can technically hide a `"..."` we shouldn't count, but
	// that's not a real-world concern for this specific block.
	strRE := regexp.MustCompile(`"([^"\\]*)"`)
	matches := strRE.FindAllStringSubmatch(body, -1)
	out := make([]string, 0, len(matches))
	for _, s := range matches {
		out = append(out, s[1])
	}
	return out
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
