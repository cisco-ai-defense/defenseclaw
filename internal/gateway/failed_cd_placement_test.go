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

// TestFailedDirectoryChangeKeepsLaterStatementsInStartingDirectory pins
// GAP-2574: a cd or pushd may fail (a missing directory), and a statement
// after ; or || then runs where the shell stood, so a link or copy to
// DefenseClaw state written there is the state write in every mode. An &&
// chain after the change keeps the lexical placement, and benign project
// links after a cd that may fail stay allowed (GAP-2550, GAP-2570).
func TestFailedDirectoryChangeKeepsLaterStatementsInStartingDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX link forms")
	}
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	for _, dir := range []string{filepath.Join(home, ".defenseclaw", "hooks"), filepath.Join(home, ".ssh"), filepath.Join(cwd, "src"),
		filepath.Join(cwd, "build"), filepath.Join(cwd, "lib")} {
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
		{"pushd /nonexistent-gap2574; ln -s ../.defenseclaw hc; cp a.txt hc/config.yaml", true},
		{"cd /nonexistent-gap2574; ln -s ../.defenseclaw hc; cp a.txt hc/config.yaml", true},
		{"pushd /nonexistent-gap2574 || ln -s ../.defenseclaw hc && cp a.txt hc/config.yaml", true},
		{"cd /nonexistent-gap2574 || ln -s ../.defenseclaw hc && cp a.txt hc/config.yaml", true},
		{"pushd /nonexistent-gap2574; cp a.txt ../.defenseclaw/config.yaml", true},
		{"cd /nonexistent-gap2574; cp a.txt ../.defenseclaw/config.yaml", true},
		{"cd missing-gap2574; ln -s ../../.defenseclaw/hooks hh; cp a.txt hh/x.sh", true},
		{"cd /tmp && cd /nonexistent-gap2574; ln -s ~/.defenseclaw hc; cp a.txt hc/config.yaml", true},
		// Benign twins: the same shapes on project files.
		{"pushd /nonexistent-gap2574; ln -s src s; cp a.txt s/b.txt", false},
		{"cd /nonexistent-gap2574; ln -s ../project/src s; cp a.txt s/b.txt", false},
		{"cd src; ln -s ../a.txt b", false},
		{"cd missing-gap2574; ln -s ../a.txt b", false},
		{"cd missing-gap2574 && ln -s ../a.txt b", false},
		{"(cd missing-gap2574; ln -s ../a.txt b)", false},
		{"cd /nonexistent-gap2574 || cd src; ln -s ../a.txt b", false},
		{"pushd ./src; ln -s ../a.txt b; popd", false},
		{"pushd /nonexistent-gap2574 && ln -s ../.defenseclaw dc && cat dc/config.yaml", false},
		// Checker it10 rows: a recursive copy named from the parent after
		// a cd to an existing directory reads a source missing where the
		// shell stood if the cd failed; a missing source is not a link
		// (R01, R03, R05, R07), and six relative cds joined by ; stay
		// placed (N04).
		{"cd build; cp -r ../src ./src-copy; cd ..", false},
		{"cd build; cp -r ../lib .", false},
		{"cd build; cp -a ../src/. ./out/", false},
		{"cd build; cp -r ../missing-dir ./x", false},
		{"cd a1; ls; cd a2; ls; cd a3; ls; cd a4; ls; cd a5; ln -s ../a.txt b", false},
		{"cd a1; cd a2; cd a3; cd a4; cd a5; cd a6; ln -s ../a.txt b", false},
		{"cd build; cd /nonexistent-gap2574; cp -r ../src ./s; cp a.txt ../.defenseclaw/config.yaml", true},
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
