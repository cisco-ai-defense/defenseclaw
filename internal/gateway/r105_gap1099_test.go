// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// GAP-1099: the saved installer (installer/ and previous/installer/) is
// active DefenseClaw state, as config.yaml is: a proven agent mutation of it
// blocks in every mode (BALANCED-DEFAULTS rule 2, LEAD DECISION 10:17), here
// observe. Its digest record is receipts/installer.sha256. Reads, running the
// saved installer, the DefenseClaw CLI and a project look-alike stay allowed.
func TestR105GAP1099SavedInstallerIsActiveState(t *testing.T) {
	home, cwd := r104ReviewHome(t)
	state := filepath.Join(home, ".defenseclaw")
	installer := filepath.Join(state, "installer", "install.sh")
	previous := filepath.Join(state, "previous", "installer", "install.sh")
	digest := filepath.Join(state, "receipts", "installer.sha256")
	lookalike := filepath.Join(cwd, ".defenseclaw", "installer", "install.sh")
	for _, file := range []string{installer, previous, digest, lookalike} {
		if err := os.MkdirAll(filepath.Dir(file), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(file, []byte("fixture\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// A move of the saved installer is judged by the classifier's
	// active-state tree list (hookpaths activeStateTrees); its seam is in
	// plans/r105/groups/classifier.md (Notes from other groups, GAP-1099).
	type row struct {
		name, command string
		block         bool
	}
	var rows []row
	if runtime.GOOS == "windows" {
		rows = []row{
			{"append installer", "Add-Content -LiteralPath '" + installer + "' -Value changed", true},
			{"overwrite previous installer", "Set-Content -LiteralPath '" + previous + "' -Value changed", true},
			{"delete installer", "Remove-Item -LiteralPath '" + installer + "'", true},
			{"read installer", "Get-Content -LiteralPath '" + installer + "'", false},
			{"project lookalike", "Set-Content -LiteralPath '" + lookalike + "' -Value changed", false},
		}
	} else {
		rows = []row{
			{"append installer", "printf changed >> " + installer, true},
			{"overwrite previous installer", "printf changed > " + previous, true},
			{"delete installer", "rm -f " + installer, true},
			{"delete previous installer", "rm -f " + previous, true},
			{"digest record", "printf 0 > " + digest, true},
			{"read installer", "cat " + installer, false},
			{"run saved installer help", "sh " + installer + " --help", false},
			{"DefenseClaw CLI", "defenseclaw upgrade --help", false},
			{"mention in text", "printf '%s\\n' '" + installer + "' > report.txt", false},
			{"project lookalike", "printf changed >> .defenseclaw/installer/install.sh", false},
		}
	}
	for _, agent := range []string{"claudecode", "codex"} {
		t.Run(agent, func(t *testing.T) {
			api := instructionProtectionTestAPI(t, agent, "observe", "HIGH")
			for _, r := range rows {
				t.Run(r.name, func(t *testing.T) {
					var action, reason string
					var findings []string
					if agent == "claudecode" {
						tool := "Bash"
						if runtime.GOOS == "windows" {
							tool = "PowerShell"
						}
						resp := api.evaluateClaudeCodeHook(context.Background(), claudeCodeHookRequest{
							HookEventName: "PreToolUse", CWD: cwd, ToolName: tool,
							ToolInput: map[string]interface{}{"command": r.command},
						})
						action, reason, findings = resp.Action, resp.Reason, resp.Findings
					} else {
						resp := api.evaluateCodexHook(context.Background(), codexHookRequest{
							HookEventName: "PreToolUse", CWD: cwd, ToolName: "exec_command",
							ToolInput: map[string]interface{}{"cmd": r.command},
						})
						action, reason, findings = resp.Action, resp.Reason, resp.Findings
					}
					if got := action == guardrailActionBlock; got != r.block {
						t.Fatalf("action=%q want block=%t reason=%q findings=%v", action, r.block, reason, findings)
					}
					if r.block && !findingStringHasRuleID(findings, "tamper.detector_state_write") {
						t.Fatalf("blocked without the state tamper finding: %v", findings)
					}
				})
			}
		})
	}
}
