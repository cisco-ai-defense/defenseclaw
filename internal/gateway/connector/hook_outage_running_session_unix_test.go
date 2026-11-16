// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// GAP-1352: a Codex session that was already running when the gateway
// stopped got no outage warning. Its UserPromptSubmit hook took the
// once-per-session marker without showing anything, so every later
// PreToolUse found it spent. Claude Code lost it the same way through
// PostToolUse and Stop. Only a call that shows the warning takes the marker:
// a running session sees exactly one warning, whichever event comes first.
func TestRunningSessionOutageWarnsOnceWhicheverEventComesFirst(t *testing.T) {
	for _, tc := range []struct {
		conn   Connector
		events []string
	}{
		{NewCodexConnector(), []string{"UserPromptSubmit", "Stop", "PreToolUse", "PreToolUse"}},
		{NewClaudeCodeConnector(), []string{"PostToolUse", "Stop", "UserPromptSubmit", "PreToolUse", "PreToolUse"}},
		{NewClaudeCodeConnector(), []string{"PostToolUse", "PreToolUse", "PreToolUse"}},
	} {
		tc := tc
		t.Run(tc.conn.Name()+"/"+strings.Join(tc.events, ","), func(t *testing.T) {
			t.Parallel()
			home := t.TempDir()
			installNativeGatewayForHookTest(t, home)
			writeOutageTierConfig(t, home, outageDefaultTierConfig)
			hookDir := filepath.Join(home, "hooks")
			opts := SetupOpts{DataDir: home, APIAddr: freeLoopbackAddrForOutageTest(t), APIToken: "scoped-test-token", HookFailMode: "open"}
			if err := WriteHookScriptsForConnectorObjectWithOpts(hookDir, opts, tc.conn); err != nil {
				t.Fatal(err)
			}
			warning := outageOpenWarningForTest(tc.conn.Name())
			warnings := 0
			for call, event := range tc.events {
				var args []string
				script := "claude-code-hook.sh"
				if tc.conn.Name() == "codex" {
					script = "codex-hook.sh"
					args = codexBoundShellHookArgsForTest(t, script, event)[1:]
				}
				stdin := `{"hook_event_name":"` + event + `","session_id":"s1"`
				switch event {
				case "UserPromptSubmit":
					stdin += `,"prompt":"hello"}`
				case "PreToolUse", "PostToolUse":
					stdin += `,"tool_name":"Bash","tool_input":{"command":"echo hi"}}`
				default:
					stdin += `}`
				}
				cmd := exec.Command("bash", append([]string{filepath.Join(hookDir, script)}, args...)...)
				cmd.Stdin = strings.NewReader(stdin)
				cmd.Env = append(sanitizedTestEnv(), "HOME="+home, "DEFENSECLAW_HOME="+home, "DEFENSECLAW_GATEWAY_AUTOSTART=0")
				output, err := cmd.CombinedOutput()
				if hookCallBlocked(err, string(output)) {
					t.Fatalf("call %d (%s) blocked during an outage in the default tier (exit %v):\n%s", call, event, err, output)
				}
				warnings += strings.Count(string(output), warning)
			}
			if warnings != 1 {
				t.Fatalf("%d outage warnings over %v, want exactly 1", warnings, tc.events)
			}
		})
	}
}
