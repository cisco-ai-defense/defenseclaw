// Scratch code-close probe, round 2 (S7 lane s7-probe1, test-only branch
// s7/ccprobes-1). Old API only (bothLateScansOrdinary, Options): red at the
// pre-fix sha, green at rel.

package hookexec

import (
	"encoding/json"
	"runtime"
	"testing"
)

// rel-1-0-10:GAP-0030 (P3 functional, Windows only): on native Windows a
// Kiro, Devin or Antigravity shell call whose gateway took it and did not
// answer stays closed; only Claude Code and Codex calls may follow the open
// outage tier (GAP-0518 contract). Pre-fix the late-ordinary check matched by
// payload shape alone on Windows, so a Kiro call followed the open tier. On
// Linux and macOS the link-hop scan already answered false, so the probe runs
// on Windows only.
func TestCCP1GAP0030LateOrdinaryOpenIsClaudeCodeAndCodexOnly(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("the payload-shape-only path is the Windows one")
	}
	// The shared reader needs an absolute cwd; a per-test folder under the
	// test user's temp folder names no protected file.
	payload, err := json.Marshal(map[string]any{
		"hook_event_name": "PreToolUse", "tool_name": "shell", "cwd": t.TempDir(),
		"tool_input": map[string]any{"command": "echo ok"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bothLateScansOrdinary(Options{Connector: "claudecode", Event: "PreToolUse", failurePayload: payload}) {
		t.Skip("control: a Claude Code ordinary late call does not follow the open tier on this tree")
	}
	for _, connector := range []string{"kiro", "devin", "antigravity"} {
		if bothLateScansOrdinary(Options{Connector: connector, Event: "PreToolUse", failurePayload: payload}) {
			t.Errorf("%s ordinary late call follows the open outage tier on Windows, want closed", connector)
		}
	}
}
