// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// A link made after a pushd or inside a ( cd ... ) subshell is placed in the
// directory that statement runs in, as after a plain cd: a write through it
// to DefenseClaw state is the state write in every mode, under its own rule,
// not an observe-mode notice under the authorized_keys rule (GAP-2562).
// The same shapes on project files stay allowed.
func TestPushdAndSubshellLinkToStateIsStateWrite(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX link forms")
	}
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	for _, dir := range []string{filepath.Join(home, ".defenseclaw", "hooks"), filepath.Join(home, ".ssh"), filepath.Join(cwd, "src")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{filepath.Join(home, ".defenseclaw", "config.yaml"),
		filepath.Join(home, ".ssh", "authorized_keys"), filepath.Join(cwd, "a.txt")} {
		if err := os.WriteFile(name, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	const stateRule = "tamper.detector_state_write"
	rows := []struct {
		command string
		block   bool
	}{
		{"pushd ~ && ln -s .defenseclaw hc && cp project/a.txt hc/config.yaml", true},
		{"(cd ~ && ln -s .defenseclaw hc && cp project/a.txt hc/config.yaml)", true},
		{"cd ~ && ln -s .defenseclaw hc && cp project/a.txt hc/config.yaml", true},
		{"pushd ~; ln -s .defenseclaw/hooks hh; cp project/a.txt hh/x.sh; popd", true},
		{"pushd .. && ln -s .defenseclaw hc && cp project/a.txt hc/config.yaml && popd", true},
		{"pushd ./src && popd && cd ~ && ln -s .defenseclaw hc && cp project/a.txt hc/config.yaml", true},
		{"(pushd ~ && ln -s .defenseclaw hc && cp project/a.txt hc/config.yaml)", true},
		// Benign twins: the same shapes on project files.
		{"pushd ~ && ln -s project/src s && cp project/a.txt s/b.txt", false},
		{"(cd ~ && ln -s project/src s && cp project/a.txt s/b.txt)", false},
		{"pushd ./src && ln -s ../a.txt b && popd", false},
		{"pushd ./src && ln -s ../a.txt b && popd && cp a.txt src/c.txt", false},
		{"pushd ~ && ln -s .defenseclaw dc && cat dc/config.yaml", false},
		{"pushd ~ && ln -s .defenseclaw dc && cp dc/config.yaml project/backup.yaml", false},
	}
	for _, connector := range []string{"claudecode", "codex"} {
		installDefaultProfileConnector(t, connector)
		for _, hint := range []actionfacts.Dialect{"", actionfacts.DialectPOSIX} {
			for _, row := range rows {
				input := actionfacts.Input{Tool: "Bash", Command: row.command, CWD: cwd, ActiveHome: home, DialectHint: hint}
				findings := dispatchTrustedAction(t.Context(), trustedActionRequest{Input: input, Connector: connector, EnforcementCapable: true})
				ids := ""
				state := false
				for _, finding := range findings {
					ids += finding.RuleID + " "
					state = state || finding.RuleID == stateRule
				}
				if blocked := buildVerdict(findings, "tool_call").Action == "block"; blocked != row.block || state != row.block {
					t.Errorf("%s hint=%q %q: block=%v state rule=%v, want %v (%s)", connector, hint, row.command, blocked, state, row.block, ids)
				}
			}
		}
		for _, mode := range []string{"observe", "action"} {
			api := instructionProtectionTestAPI(t, connector, mode, "HIGH")
			for _, row := range rows {
				var action, reason string
				if connector == "claudecode" {
					resp := api.evaluateClaudeCodeHook(context.Background(), claudeCodeHookRequest{
						HookEventName: "PreToolUse", CWD: cwd, ToolName: "Bash",
						ToolInput: map[string]interface{}{"command": row.command},
					})
					action, reason = resp.Action, resp.Reason
				} else {
					resp := api.evaluateCodexHook(context.Background(), codexHookRequest{
						HookEventName: "PreToolUse", CWD: cwd, ToolName: "exec_command",
						ToolInput: map[string]interface{}{"cmd": row.command},
					})
					action, reason = resp.Action, resp.Reason
				}
				if got := action == "block"; got != row.block {
					t.Errorf("%s %s %q: action=%q want block=%v reason=%q", connector, mode, row.command, action, row.block, reason)
				}
				if row.block && strings.Contains(strings.ToLower(reason), "authorized keys") {
					t.Errorf("%s %s %q: state write labelled as an authorized_keys mutation: %q", connector, mode, row.command, reason)
				}
			}
		}
	}
}
