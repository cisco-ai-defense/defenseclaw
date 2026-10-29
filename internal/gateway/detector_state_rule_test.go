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
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
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
	if err := os.Link(state, filepath.Join(cwd, "state-hardlink")); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(hook, filepath.Join(cwd, "hook-hardlink")); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(policy, filepath.Join(cwd, "policy-hardlink")); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(cwd, "ordinary.txt")
	if err := os.WriteFile(other, []byte("ordinary\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(other, filepath.Join(cwd, "ordinary-hardlink")); err != nil {
		t.Fatal(err)
	}
	rows := []struct {
		name, command, workdir string
		block                  bool
	}{
		{"redirect config", "printf changed >> " + state, cwd, true},
		{"relative config", "printf changed >> config.yaml", stateDir, true},
		{"symlink config", "printf changed >> state-alias", cwd, true},
		{"hardlink config", "printf changed >> state-hardlink", cwd, true},
		{"hardlink hook", "printf changed >> hook-hardlink", cwd, true},
		{"hardlink policy", "printf changed >> policy-hardlink", cwd, true},
		{"move config", "mv " + state + " " + filepath.Join(cwd, "saved.yaml"), cwd, true},
		{"delete config", "rm " + state, cwd, true},
		{"truncate config", "truncate -s 0 " + state, cwd, true},
		{"chmod config", "chmod 600 " + state, cwd, true},
		{"hook runtime", "printf changed >> " + hook, cwd, true},
		{"policy", "printf changed >> " + policy, cwd, true},
		{"read config", "cat " + state, cwd, false},
		{"read config hardlink", "cat state-hardlink", cwd, false},
		{"unrelated hardlink", "printf changed >> ordinary-hardlink", cwd, false},
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
	hardlink := filepath.Join(cwd, "state-hardlink.yaml")
	if err := os.Link(state, hardlink); err != nil {
		t.Fatal(err)
	}
	if mapped, same := hookpaths.ResolveActiveStateHardlinkTarget(hardlink, home); !same {
		t.Fatalf("active state hardlink not mapped: %q", mapped)
	}
	ordinary := filepath.Join(cwd, "ordinary.txt")
	if err := os.WriteFile(ordinary, []byte("ordinary\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ordinaryHardlink := filepath.Join(cwd, "ordinary-hardlink.txt")
	if err := os.Link(ordinary, ordinaryHardlink); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(cwd, "state-symlink.yaml")
	if err := os.Symlink(state, symlink); err != nil {
		t.Fatalf("create symlink (the Windows lane runs elevated): %v", err)
	}
	api := instructionProtectionTestAPI(t, "codex", "observe", "HIGH")
	ctx := withManagedHookPeer(t.Context(), managedHookPeer{Home: home})
	for _, row := range []struct {
		name, command string
		block         bool
	}{
		// Review loop 2: removing or moving an alias leaves the state alone.
		{"config hardlink delete", "Remove-Item -LiteralPath '" + hardlink + "'", false},
		{"config hardlink move", "Move-Item -LiteralPath '" + hardlink + "' -Destination '" + filepath.Join(cwd, "moved.yaml") + "'", false},
		{"config symlink delete", "Remove-Item -LiteralPath '" + symlink + "'", false},
		{"config symlink write", "Set-Content -LiteralPath '" + symlink + "' -Value marker", true},
		{"config move", "Move-Item -LiteralPath '" + state + "' -Destination '" + filepath.Join(cwd, "saved.yaml") + "'", true},
		{"config write", "Set-Content -LiteralPath '" + state + "' -Value marker", true},
		{"config hardlink write", "Set-Content -LiteralPath '" + hardlink + "' -Value marker", true},
		{"config delete", "Remove-Item -LiteralPath '" + state + "'", true},
		{"hook write", "Set-Content -LiteralPath '" + hook + "' -Value marker", true},
		{"config read", "Get-Content -LiteralPath '" + state + "'", false},
		{"config hardlink read", "Get-Content -LiteralPath '" + hardlink + "'", false},
		{"unrelated hardlink write", "Set-Content -LiteralPath '" + ordinaryHardlink + "' -Value marker", false},
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

// GAP-1409 review loop 2: rm, unlink and mv act on the directory entry they
// name. Removing, moving or replacing a project symlink or hard link to
// active state leaves the state untouched and stays allowed in observe mode;
// the same names still block when the command writes through them or when a
// linked parent directory places the entry inside the active state.
func TestGAP1409DirectoryEntryOperandsDoNotFollowFinalLink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX command matrix; native Windows cases are in TestGAP1409ObserveSelfProtectionWindows")
	}
	home, cwd := r104ReviewHome(t)
	stateDir := filepath.Join(home, ".defenseclaw")
	guardrailDir := filepath.Join(stateDir, "policies", "guardrail")
	hooksDir := filepath.Join(stateDir, "hooks")
	for _, dir := range []string{guardrailDir, hooksDir} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	state := filepath.Join(stateDir, "config.yaml")
	hook := filepath.Join(hooksDir, "codex-hook.sh")
	for _, file := range []string{state, hook, filepath.Join(guardrailDir, "rules.yaml")} {
		if err := os.WriteFile(file, []byte("fixture\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for name, target := range map[string]string{
		"state-alias": state, "hook-alias": hook,
		"state-dir": stateDir, "guardrail-dir": guardrailDir,
	} {
		if err := os.Symlink(target, filepath.Join(cwd, name)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Link(state, filepath.Join(cwd, "state-hardlink")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cwd, "ordinary.txt"), []byte("ordinary\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rows := []struct {
		name, command string
		block         bool
	}{
		{"delete config symlink", "rm state-alias", false},
		{"force delete config symlink", "rm -f -- ./state-alias", false},
		{"unlink config symlink", "unlink state-alias", false},
		{"delete hook symlink", "rm " + filepath.Join(cwd, "hook-alias"), false},
		{"recursive delete linked state dir", "rm -r state-dir", false},
		{"recursive delete linked policy dir", "rm -rf guardrail-dir", false},
		{"move config symlink", "mv state-alias moved-alias", false},
		{"replace config symlink", "mv ordinary.txt state-alias", false},
		{"delete config hardlink", "rm state-hardlink", false},
		{"move config hardlink", "mv state-hardlink moved-hardlink", false},
		{"replace config hardlink", "mv ordinary.txt state-hardlink", false},
		{"write through config symlink", "printf changed >> state-alias", true},
		{"truncate through config symlink", "truncate -s 0 state-alias", true},
		{"chmod through config symlink", "chmod 600 state-alias", true},
		{"write through config hardlink", "printf changed >> state-hardlink", true},
		{"delete config via linked parent", "rm state-dir/config.yaml", true},
		{"move config via linked parent", "mv state-dir/config.yaml saved.yaml", true},
		{"replace config via linked parent", "mv ordinary.txt state-dir/config.yaml", true},
		{"delete hook via linked parent", "rm state-dir/hooks/codex-hook.sh", true},
		{"move into linked policy dir", "mv ordinary.txt guardrail-dir", true},
		{"delete through linked policy dir", "rm -rf guardrail-dir/", true},
		{"delete active config", "rm " + state, true},
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
							HookEventName: "PreToolUse", CWD: cwd, ToolName: "Bash",
							ToolInput: map[string]interface{}{"command": row.command},
						})
						action, reason = resp.Action, resp.Reason
					case "codex":
						resp := api.evaluateCodexHook(context.Background(), codexHookRequest{
							HookEventName: "PreToolUse", CWD: cwd, ToolName: "exec_command",
							ToolInput: map[string]interface{}{"cmd": row.command},
						})
						action, reason = resp.Action, resp.Reason
					case "hermes":
						profile := connector.NewHermesConnector().HookProfile(connector.SetupOpts{})
						payload := map[string]interface{}{
							"hook_event_name": "pre_tool_call", "tool_name": "terminal",
							"tool_input": map[string]interface{}{"command": row.command}, "cwd": cwd,
						}
						resp := api.evaluateAgentHook(context.Background(), normalizeAgentHookRequestWithProfile("hermes", payload, profile))
						action, reason = resp.Action, resp.Reason
					}
					if got := action == "block"; got != row.block {
						t.Fatalf("action=%q want block=%t reason=%q", action, row.block, reason)
					}
				})
			}
		})
	}
}
