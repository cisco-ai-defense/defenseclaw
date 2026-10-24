// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
)

// GAP-0768: a native write finding at the configured block threshold must
// deny the mutation even when the active-file set is absent from the hook.
// The Windows cases use the PowerShell dialect on Linux as a decision test.
func TestR104GAP0768NativeHighSeverityWrites(t *testing.T) {
	for _, tc := range []struct {
		name, connector, command, cwd, home, rule, blockAt, active string
		dialect                                                    actionfacts.Dialect
		block                                                      bool
	}{
		{"claude Unix active CLAUDE", "claudecode", "printf changed > /repo/CLAUDE.md", "/repo", "/home/alice", "COG-CLAUDE-MD", "HIGH", "/other/CLAUDE.md", actionfacts.DialectPOSIX, true},
		{"claude Windows active CLAUDE", "claudecode", `Set-Content -LiteralPath 'C:\Repo\CLAUDE.md' -Value changed`, `C:\Repo`, `C:\Users\alice`, "COG-CLAUDE-MD", "HIGH", `C:\Other\CLAUDE.md`, actionfacts.DialectPowerShell, true},
		{"openclaw Unix SOUL", "openclaw", "printf changed > /repo/SOUL.md", "/repo", "/home/alice", "COG-SOUL", "CRITICAL", "/other/SOUL.md", actionfacts.DialectPOSIX, true},
		{"openclaw Windows absolute SOUL", "openclaw", `Set-Content -LiteralPath 'C:\Users\alice\scratch\SOUL.md' -Value changed`, `C:\Users\alice\scratch`, `C:\Users\alice`, "COG-SOUL", "CRITICAL", `C:\Other\SOUL.md`, actionfacts.DialectPowerShell, true},
		{"codex Unix AGENTS", "codex", "printf changed > /repo/AGENTS.md", "/repo", "/home/alice", "COG-AGENTS-MD", "HIGH", "/other/AGENTS.md", actionfacts.DialectPOSIX, true},
		{"codex Unix SOUL it does not load", "codex", "printf changed > /repo/SOUL.md", "/repo", "/home/alice", "", "CRITICAL", "/other/SOUL.md", actionfacts.DialectPOSIX, false},
		{"claude Unix AGENTS it does not load", "claudecode", "printf changed > /repo/AGENTS.md", "/repo", "/home/alice", "", "HIGH", "/other/AGENTS.md", actionfacts.DialectPOSIX, false},
		{"codex Windows AGENTS", "codex", `Set-Content -LiteralPath 'C:\Repo\AGENTS.md' -Value changed`, `C:\Repo`, `C:\Users\alice`, "COG-AGENTS-MD", "HIGH", `C:\Other\AGENTS.md`, actionfacts.DialectPowerShell, true},
		{"claude Unix ordinary write", "claudecode", "printf changed > /repo/notes.txt", "/repo", "/home/alice", "", "HIGH", "/other/CLAUDE.md", actionfacts.DialectPOSIX, false},
		{"claude Unix name in write data", "claudecode", "printf CLAUDE.md > /repo/notes.txt", "/repo", "/home/alice", "", "HIGH", "/other/CLAUDE.md", actionfacts.DialectPOSIX, false},
		{"codex Windows ordinary write", "codex", `Set-Content -LiteralPath 'C:\Users\alice\scratch\notes.txt' -Value changed`, `C:\Users\alice\scratch`, `C:\Users\alice`, "", "CRITICAL", `C:\Other\SOUL.md`, actionfacts.DialectPowerShell, false},
		{"codex Windows name in write data", "codex", `Set-Content -LiteralPath 'C:\Users\alice\scratch\notes.txt' -Value SOUL.md`, `C:\Users\alice\scratch`, `C:\Users\alice`, "", "CRITICAL", `C:\Other\SOUL.md`, actionfacts.DialectPowerShell, false},
		{"claude Unix instruction read", "claudecode", "cat /repo/CLAUDE.md", "/repo", "/home/alice", "", "HIGH", "/other/CLAUDE.md", actionfacts.DialectPOSIX, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			installToolCallCorpusProfileConnector(t, tc.connector, "default")
			cfg := &config.Config{}
			cfg.Guardrail.Mode = "action"
			cfg.Guardrail.Connector = tc.connector
			cfg.Guardrail.BlockAt = tc.blockAt
			cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), "default")
			args, err := json.Marshal(map[string]string{"command": tc.command})
			if err != nil {
				t.Fatal(err)
			}
			request := &ToolInspectRequest{Tool: "Bash", Args: args, Direction: "tool_call", Connector: tc.connector}
			action := trustedActionRequest{
				Input: actionfacts.Input{Tool: "Bash", Args: args, CWD: tc.cwd, ActiveHome: tc.home,
					ActiveAgentFiles: []string{tc.active}, DialectHint: tc.dialect},
				LegacyText: string(args), Connector: tc.connector, EnforcementCapable: true,
			}
			verdict := (&APIServer{scannerCfg: cfg}).inspectTrustedToolPolicyCtx(t.Context(), request, action)
			if (verdict.Action == guardrailActionBlock) != tc.block ||
				tc.rule != "" && !findingStringHasRuleID(verdict.Findings, tc.rule) {
				t.Fatalf("verdict=%+v, want block=%t rule=%q; facts=%+v", verdict, tc.block, tc.rule, actionfacts.Analyze(action.Input))
			}
		})
	}
}

// GAP-0777: a restarted gateway gets no InstructionsLoaded again for a
// session that is still running. A resolved instruction-file write keeps its
// action-mode block in that session: the gateway restores the loads it
// recorded under its data directory. A new session that loaded nothing
// keeps the block only on the CLAUDE.md that Claude Code reads at every
// start; its SOUL.md and AGENTS.md are ordinary files.
func TestR104GAP0777ExistingSessionAfterGatewayRestart(t *testing.T) {
	installToolCallCorpusProfileConnector(t, "claudecode", "default")
	cfg := &config.Config{DataDir: t.TempDir()}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	cfg.Guardrail.BlockAt = "HIGH"
	cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), "default")
	root := t.TempDir()
	for _, tc := range []struct {
		name, rule  string
		startupLoad bool
	}{
		{"CLAUDE.md", "COG-CLAUDE-MD", true},
		{"SOUL.md", "COG-SOUL", false},
		{"AGENTS.md", "COG-AGENTS-MD", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			file := filepath.Join(root, tc.name)
			if err := os.WriteFile(file, []byte("instructions\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			before := &APIServer{scannerCfg: cfg}
			before.evaluateClaudeCodeHook(authenticatedClaudeCodeTestContext(), claudeCodeHookRequest{
				HookEventName: "InstructionsLoaded", SessionID: "existing-session", FilePath: file,
			})
			if len(before.activeAgentContext.snapshot("claudecode", "existing-session").files) == 0 {
				t.Fatal("the original gateway did not authenticate the loaded file")
			}
			toolInput := map[string]interface{}{"command": "printf changed >> " + tc.name}
			ctx := withAuthenticatedHookConnector(
				instructionResolvedWriteContext(t, root, "Bash", toolInput), "claudecode",
			)
			// A new APIServer models a healthy gateway restart, while the
			// agent continues to send the same session ID.
			after := &APIServer{scannerCfg: cfg}
			for _, session := range []string{"existing-session", "new-session"} {
				response := after.evaluateClaudeCodeHook(ctx, claudeCodeHookRequest{
					HookEventName: "PreToolUse", SessionID: session, CWD: root,
					ToolName: "Bash", ToolInput: toolInput,
				})
				if session == "new-session" && !tc.startupLoad {
					if response.Action == guardrailActionBlock {
						t.Errorf("session=%q wrote an unloaded %s: action=%q findings=%v", session, tc.name, response.Action, response.Findings)
					}
					continue
				}
				if response.Action != guardrailActionBlock ||
					!findingStringHasRuleID(response.Findings, tc.rule) {
					t.Errorf("session=%q action=%q findings=%v, want %s block", session, response.Action, response.Findings, tc.rule)
				}
			}
		})
	}
}

func TestR104GAP0768NativePOSIXHookRoutes(t *testing.T) {
	for _, tc := range []struct {
		connector, command, rule, blockAt string
	}{
		{"claudecode", "printf changed > /repo/CLAUDE.md", "COG-CLAUDE-MD", "HIGH"},
		{"codex", "printf changed > /repo/AGENTS.md", "COG-AGENTS-MD", "HIGH"},
	} {
		t.Run(tc.connector, func(t *testing.T) {
			installToolCallCorpusProfileConnector(t, tc.connector, "default")
			cfg := &config.Config{}
			cfg.Guardrail.Mode = "action"
			cfg.Guardrail.Connector = tc.connector
			cfg.Guardrail.BlockAt = tc.blockAt
			cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), "default")
			api := &APIServer{scannerCfg: cfg}
			var action, raw string
			var findings []string
			if tc.connector == "claudecode" {
				response := api.evaluateClaudeCodeHook(t.Context(), claudeCodeHookRequest{
					HookEventName: "PreToolUse", ToolName: "Bash", CWD: "/repo",
					ToolInput: map[string]interface{}{"command": tc.command},
				})
				action, raw, findings = response.Action, response.RawAction, response.Findings
			} else {
				response := api.evaluateCodexHook(t.Context(), codexHookRequest{
					HookEventName: "PreToolUse", ToolName: "Bash", CWD: "/repo",
					ToolInput: map[string]interface{}{"command": tc.command},
				})
				action, raw, findings = response.Action, response.RawAction, response.Findings
			}
			if action != guardrailActionBlock || raw != guardrailActionBlock ||
				!findingStringHasRuleID(findings, tc.rule) {
				t.Fatalf("action=%q raw=%q findings=%v, want native block on %s", action, raw, findings, tc.rule)
			}
		})
	}
}
