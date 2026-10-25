// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

func TestR104DetectorStateWriteRequiresResolvedTarget(t *testing.T) {
	home, cwd := r104ReviewHome(t)
	stateDir := filepath.Join(home, ".defenseclaw")
	if err := os.Mkdir(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(stateDir, "config.yaml")
	if err := os.WriteFile(state, []byte("guardrail:\n  mode: action\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	installDefaultProfileConnector(t, "claudecode")
	tests := []struct {
		name, command string
		block         bool
	}{
		{"active state", `printf marker >> ` + state, true},
		{"project file", `printf marker >> report.txt`, false},
		{"state path as data", `printf '%s\n' '` + state + `' > report.txt`, false},
	}
	dialect := actionfacts.DialectPOSIX
	if runtime.GOOS == "windows" {
		dialect = actionfacts.DialectPowerShell
		tests = []struct {
			name, command string
			block         bool
		}{
			{"active state", `Add-Content -LiteralPath '` + state + `' -Value marker`, true},
			{"project file", `Add-Content -LiteralPath report.txt -Value marker`, false},
			{"state path as data", `Set-Content -LiteralPath report.txt -Value '` + state + `'`, false},
		}
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			input := actionfacts.Input{Tool: "Bash", Command: tc.command, CWD: cwd, ActiveHome: home,
				DialectHint: dialect}
			findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
				Input: input, Connector: "claudecode", EnforcementCapable: true,
			})
			finding := findingWithID(findings, "tamper.detector_state_write")
			if got := finding != nil && finding.contributesToEnforcement(); got != tc.block {
				t.Fatalf("tamper enforcement=%t, want %t; finding=%+v", got, tc.block, finding)
			}
			if got := buildVerdict(findings, "tool_call").Action == guardrailActionBlock; got != tc.block {
				t.Fatalf("tamper verdict block=%t, want %t; findings=%v", got, tc.block, FindingStrings(findings))
			}
		})
	}
}

// GAP-1409: observe mode still refuses a proved mutation of the installed
// DefenseClaw state. A path appearing as data or in a project is ordinary work.
func TestGAP1409ObserveSelfProtectionHooks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX command matrix; native Windows cases are below")
	}
	home, cwd := r104ReviewHome(t)
	stateDir := filepath.Join(home, ".defenseclaw")
	hooksDir := filepath.Join(stateDir, "hooks")
	policyDir := filepath.Join(stateDir, "policies")
	for _, dir := range []string{hooksDir, policyDir, filepath.Join(cwd, ".defenseclaw"), filepath.Join(home, ".DefenseClaw")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	state := filepath.Join(stateDir, "config.yaml")
	hook := filepath.Join(hooksDir, "codex-hook.sh")
	policy := filepath.Join(policyDir, "active.yaml")
	for _, file := range []string{state, hook, policy, filepath.Join(home, ".DefenseClaw", "config.yaml")} {
		if err := os.WriteFile(file, []byte("fixture\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(state, filepath.Join(cwd, "state-alias")); err != nil {
		t.Fatal(err)
	}
	rows := []struct {
		name, command, workdir string
		block                  bool
	}{
		{"redirect config", "printf changed >> " + state, cwd, true},
		{"relative config", "printf changed >> config.yaml", stateDir, true},
		{"symlink config", "printf changed >> state-alias", cwd, true},
		{"move config", "mv " + state + " " + filepath.Join(cwd, "saved.yaml"), cwd, true},
		{"delete config", "rm " + state, cwd, true},
		{"truncate config", "truncate -s 0 " + state, cwd, true},
		{"chmod config", "chmod 600 " + state, cwd, true},
		{"hook runtime", "printf changed >> " + hook, cwd, true},
		{"policy", "printf changed >> " + policy, cwd, true},
		{"read config", "cat " + state, cwd, false},
		{"DefenseClaw CLI", "defenseclaw status", cwd, false},
		{"DefenseClaw config CLI", "defenseclaw config set guardrail.mode observe", cwd, false},
		{"mention in text", "printf '%s\\n' '" + state + "' > report.txt", cwd, false},
		{"project lookalike", "printf changed >> .defenseclaw/config.yaml", cwd, false},
		{"case-different lookalike", "printf changed >> " + filepath.Join(home, ".DefenseClaw", "config.yaml"), cwd, false},
	}
	for _, agent := range []string{"claudecode", "codex", "hermes"} {
		t.Run(agent, func(t *testing.T) {
			api := instructionProtectionTestAPI(t, agent, "observe", "HIGH")
			for _, row := range rows {
				t.Run(row.name, func(t *testing.T) {
					var action, reason string
					switch agent {
					case "claudecode":
						resp := api.evaluateClaudeCodeHook(context.Background(), claudeCodeHookRequest{
							HookEventName: "PreToolUse", CWD: row.workdir, ToolName: "Bash",
							ToolInput: map[string]interface{}{"command": row.command},
						})
						action, reason = resp.Action, resp.Reason
					case "codex":
						resp := api.evaluateCodexHook(context.Background(), codexHookRequest{
							HookEventName: "PreToolUse", CWD: row.workdir, ToolName: "exec_command",
							ToolInput: map[string]interface{}{"cmd": row.command},
						})
						action, reason = resp.Action, resp.Reason
					case "hermes":
						profile := connector.NewHermesConnector().HookProfile(connector.SetupOpts{})
						payload := map[string]interface{}{
							"hook_event_name": "pre_tool_call", "tool_name": "terminal",
							"tool_input": map[string]interface{}{"command": row.command}, "cwd": row.workdir,
						}
						resp := api.evaluateAgentHook(context.Background(), normalizeAgentHookRequestWithProfile("hermes", payload, profile))
						action, reason = resp.Action, resp.Reason
					}
					if got := action == "block"; got != row.block {
						t.Fatalf("action=%q want block=%t reason=%q", action, row.block, reason)
					}
					if row.block && reason == "" {
						t.Fatal("blocked mutation has no agent-facing reason")
					}
				})
			}
		})
	}
}

func TestGAP1409ObserveSelfProtectionWindows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("native Windows path and PowerShell spelling")
	}
	home, cwd := r104ReviewHome(t)
	state := filepath.Join(home, ".defenseclaw", "config.yaml")
	hook := filepath.Join(home, ".defenseclaw", "hooks", "codex-hook.ps1")
	for _, file := range []string{state, hook} {
		if err := os.MkdirAll(filepath.Dir(file), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(file, []byte("fixture\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	api := instructionProtectionTestAPI(t, "codex", "observe", "HIGH")
	ctx := withManagedHookPeer(t.Context(), managedHookPeer{Home: home})
	for _, row := range []struct {
		name, command string
		block         bool
	}{
		{"config write", "Set-Content -LiteralPath '" + state + "' -Value marker", true},
		{"config delete", "Remove-Item -LiteralPath '" + state + "'", true},
		{"hook write", "Set-Content -LiteralPath '" + hook + "' -Value marker", true},
		{"config read", "Get-Content -LiteralPath '" + state + "'", false},
		{"path as text", "Set-Content -LiteralPath '" + filepath.Join(cwd, "report.txt") + "' -Value '" + state + "'", false},
		{"project lookalike", "Set-Content -LiteralPath '" + filepath.Join(cwd, ".defenseclaw", "config.yaml") + "' -Value marker", false},
		{"DefenseClaw CLI", "defenseclaw status", false},
	} {
		t.Run(row.name, func(t *testing.T) {
			resp := api.evaluateCodexHook(ctx, codexHookRequest{
				HookEventName: "PreToolUse", CWD: cwd, ToolName: "exec_command",
				ToolInput: map[string]interface{}{"cmd": row.command},
			})
			if got := resp.Action == "block"; got != row.block {
				t.Fatalf("action=%q want block=%t reason=%q", resp.Action, row.block, resp.Reason)
			}
		})
	}
}

func TestR104ActiveStateMentionRequiresMutation(t *testing.T) {
	home, cwd := r104ReviewHome(t)
	state := filepath.Join(home, ".defenseclaw", "config.yaml")
	installDefaultProfileConnector(t, "claudecode")
	dialect := actionfacts.DialectPOSIX
	active := "echo " + state
	readOnly := "cat " + state
	project := "echo " + filepath.Join(cwd, ".defenseclaw", "config.yaml")
	if runtime.GOOS == "windows" {
		dialect = actionfacts.DialectPowerShell
		active = "Write-Output " + state
		readOnly = "Get-Content " + state
		project = "Write-Output " + filepath.Join(cwd, ".defenseclaw", "config.yaml")
	}
	for _, tc := range []struct {
		name, command string
		enforce       bool
		block         bool
	}{
		{"action active", active, true, false},
		{"observe active", active, false, false},
		{"action read only", readOnly, true, false},
		{"action project state", project, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := actionfacts.Input{Tool: "Bash", Command: tc.command, CWD: cwd,
				ActiveHome: home, DialectHint: dialect}
			findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
				Input: input, Connector: "claudecode", EnforcementCapable: tc.enforce,
			})
			stateFinding := findingWithID(findings, "tamper.detector_state_write")
			if got := stateFinding != nil && stateFinding.contributesToEnforcement(); got != tc.block {
				t.Fatalf("state enforcement=%t, want %t; findings=%v", got, tc.block, FindingStrings(findings))
			}
			sshFinding := findingWithID(findings, "persistence.ssh_authorized_keys_command")
			if sshFinding != nil && sshFinding.contributesToEnforcement() {
				t.Fatalf("state command received SSH enforcement: %v", FindingStrings(findings))
			}
			if got := buildVerdict(findings, "tool_call").Action == guardrailActionBlock; got != tc.block {
				t.Fatalf("block=%t, want %t; findings=%v", got, tc.block, FindingStrings(findings))
			}
		})
	}
}
