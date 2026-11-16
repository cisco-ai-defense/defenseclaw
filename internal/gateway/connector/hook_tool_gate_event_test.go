// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

// GAP-0323 follow-up: the Claude Code shell hook picks its tool-call bound
// from the payload's top-level hook_event_name, so JSON spacing does not
// lose the 4 s bound and a hook_event_name nested in a tool's input or
// output does not give another event the tool call's bound.
func TestClaudeToolGateBoundFollowsTheTopLevelEvent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows hooks use the native hook runner")
	}
	shell := systemBashForTest(t)
	helperPath := materializeHookAssetForTest(t, "hooks/_hardening.sh")
	for _, tc := range []struct {
		name, payload, want string
	}{
		{"compact tool call", `{"hook_event_name":"PreToolUse","tool_name":"Bash"}`, "4"},
		{"spaced tool call", `{"hook_event_name" : "PreToolUse", "tool_name": "Bash"}`, "4"},
		{"newline after the colon", "{\"hook_event_name\":\n  \"PermissionRequest\",\"tool_name\":\"Bash\"}", "4"},
		{"nested key in a tool result", `{"hook_event_name":"PostToolUse","tool_input":{"hook_event_name":"PreToolUse"}}`, "10"},
		{"nested key in a prompt event", `{"prompt":"x","meta":{"hook_event_name":"PreToolUse"},"hook_event_name":"UserPromptSubmit"}`, "10"},
		{"not JSON", `"hook_event_name":"PreToolUse"`, "10"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			command := exec.Command(shell, "-c", `set -e; source "$1"; defenseclaw_payload_tool_gate_max_time "$2" 10; printf '%s' "$HOOK_MAX_TIME"`, "bash", helperPath, tc.payload)
			command.Env = os.Environ()
			out, err := command.CombinedOutput()
			if err != nil {
				t.Fatalf("helper failed: %v\n%s", err, out)
			}
			if got := strings.TrimSpace(string(out)); got != tc.want {
				t.Fatalf("payload %s: bound %q s, want %s s", tc.payload, got, tc.want)
			}
		})
	}
}
