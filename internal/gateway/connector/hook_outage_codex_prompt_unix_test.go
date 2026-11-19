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

// rel-1-0-10 GAP-1168: a Codex session that was running when the gateway
// stopped, whose next turn is a prompt with no tool call, showed no
// DefenseClaw warning (dc-mac, route-only session: only Codex's
// "Reconnecting... Connection failed"). codex-hook.sh printed its notice for
// SessionStart and PreToolUse only, though Codex shows a UserPromptSubmit
// systemMessage. The prompt now carries it, once per session; the strict
// tier still blocks every call and prints no allow notice.
func TestGAP1168RunningCodexSessionPromptShowsTheOutageWarning(t *testing.T) {
	for _, tc := range []struct {
		name, tier string
		events     []string
		warnings   int
		blocked    bool
	}{
		{"prompt only", outageDefaultTierConfig, []string{"UserPromptSubmit"}, 1, false},
		{"prompt, tool call, prompt", outageDefaultTierConfig, []string{"UserPromptSubmit", "PreToolUse", "UserPromptSubmit"}, 1, false},
		{"strict tier", outageStrictTierConfig, []string{"UserPromptSubmit", "PreToolUse"}, 0, true},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			home := t.TempDir()
			installNativeGatewayForHookTest(t, home)
			writeOutageTierConfig(t, home, tc.tier)
			hookDir := filepath.Join(home, "hooks")
			opts := SetupOpts{DataDir: home, APIAddr: freeLoopbackAddrForOutageTest(t), APIToken: "scoped-test-token", HookFailMode: "open"}
			conn := NewCodexConnector()
			if err := WriteHookScriptsForConnectorObjectWithOpts(hookDir, opts, conn); err != nil {
				t.Fatal(err)
			}
			warning := outageOpenWarningForTest("codex")
			warnings := 0
			for call, event := range tc.events {
				args := codexBoundShellHookArgsForTest(t, "codex-hook.sh", event)[1:]
				stdin := `{"hook_event_name":"` + event + `","session_id":"gap1168"`
				if event == "UserPromptSubmit" {
					stdin += `,"prompt":"What is 2+2?"}`
				} else {
					stdin += `,"tool_name":"Bash","tool_input":{"command":"echo hi"}}`
				}
				cmd := exec.Command("bash", append([]string{filepath.Join(hookDir, "codex-hook.sh")}, args...)...)
				cmd.Stdin = strings.NewReader(stdin)
				cmd.Env = append(sanitizedTestEnv(), "HOME="+home, "DEFENSECLAW_HOME="+home, "DEFENSECLAW_GATEWAY_AUTOSTART=0")
				output, err := cmd.CombinedOutput()
				if got := hookCallBlocked(err, string(output)); got != tc.blocked {
					t.Fatalf("call %d (%s) blocked=%v, want %v (exit %v):\n%s", call, event, got, tc.blocked, err, output)
				}
				if call == 0 && !tc.blocked && !strings.Contains(string(output), warning) {
					t.Fatalf("the prompt of a running session shows no outage warning:\n%s", output)
				}
				warnings += strings.Count(string(output), warning)
			}
			if warnings != tc.warnings {
				t.Fatalf("%d outage warnings over %v, want %d", warnings, tc.events, tc.warnings)
			}
		})
	}
}
