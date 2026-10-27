// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// GAP-2253: in the strict tier a per-user Codex call blocked after
// `defenseclaw-gateway stop` said the hook "could not reach its gateway" and
// to check its status, while Claude Code and the open-mode warning name the
// stop and the start step. Both hooks now name the same cause and fix.
func TestPerUserStrictOutageBlockNamesTheStoppedGatewayAndTheStartStep(t *testing.T) {
	codexPrompt := hookArgvCase{script: "codex-hook.sh", args: codexBoundShellHookArgsForTest(t, "codex-hook.sh", "UserPromptSubmit")[1:],
		stdin: `{"hook_event_name":"UserPromptSubmit","session_id":"s1","prompt":"echo strict"}`}
	for _, tc := range []struct {
		name    string
		conn    Connector
		invoke  hookArgvCase
		stopped bool
		want    string
	}{
		{"codex prompt after stop", NewCodexConnector(), codexPrompt, true, "its gateway is stopped. Run defenseclaw-gateway start"},
		{"codex tool after stop", NewCodexConnector(), hookArgvConnectorCase(t, "codex"), true, "its gateway is stopped. Run defenseclaw-gateway start"},
		{"claude code prompt after stop", NewClaudeCodeConnector(), hookArgvConnectorCase(t, "claudecode"), true, "its gateway is stopped. Run defenseclaw-gateway start"},
		{"codex prompt, gateway not running", NewCodexConnector(), codexPrompt, false, "run defenseclaw-gateway start"},
		{"claude code prompt, gateway not running", NewClaudeCodeConnector(), hookArgvConnectorCase(t, "claudecode"), false, "run defenseclaw-gateway start"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			installNativeGatewayForHookTest(t, home)
			writeOutageTierConfig(t, home, outageStrictTierConfig)
			hookDir := filepath.Join(home, "hooks")
			opts := SetupOpts{DataDir: home, APIAddr: freeLoopbackAddrForOutageTest(t), APIToken: "scoped-test-token", HookFailMode: "closed"}
			if err := WriteHookScriptsForConnectorObjectWithOpts(hookDir, opts, tc.conn); err != nil {
				t.Fatal(err)
			}
			if tc.stopped {
				if err := os.WriteFile(filepath.Join(home, "gateway.stopped"), []byte("stopped\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			cmd := exec.Command("bash", append([]string{filepath.Join(hookDir, tc.invoke.script)}, tc.invoke.args...)...)
			cmd.Stdin = strings.NewReader(tc.invoke.stdin)
			cmd.Env = append(sanitizedTestEnv(), "HOME="+home, "DEFENSECLAW_HOME="+home, "DEFENSECLAW_GATEWAY_AUTOSTART=0")
			output, err := cmd.CombinedOutput()
			text := string(output)
			if !hookCallBlocked(err, text) {
				t.Fatalf("a strict-tier outage must block (exit %v):\n%s", err, text)
			}
			if !strings.Contains(text, tc.want) || strings.Contains(text, "could not reach its gateway") {
				t.Fatalf("the block does not name the cause and the start step (want %q):\n%s", tc.want, text)
			}
		})
	}
}
