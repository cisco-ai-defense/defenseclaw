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

// GAP-0995: after a gateway restart no session has a loaded-file snapshot,
// so the resolved write target alone must keep an instruction-file write
// blocked in action mode. That holds for every spelling the shell accepts:
// relative operands, and on Windows the drive spellings Git Bash takes
// (C:\x quoted, C:/x, /c/x) and relative operands in a drive CWD. Writes to
// other files, reads, and instruction names that are only write data stay
// allowed.
func TestGAP0995InstructionWriteBlocksAfterRestartInEverySpelling(t *testing.T) {
	const unixCWD, unixHome = "/repo", "/home/alice"
	const winCWD, winHome = `C:\Repo`, `C:\Users\alice`
	for _, tc := range []struct {
		name, connector, command, cwd, home, rule string
	}{
		{"claude Unix relative append", "claudecode", "printf changed >> CLAUDE.md", unixCWD, unixHome, "COG-CLAUDE-MD"},
		{"claude Unix dot-relative write", "claudecode", "printf changed > ./CLAUDE.md", unixCWD, unixHome, "COG-CLAUDE-MD"},
		{"claude Unix subdirectory relative", "claudecode", "printf changed > docs/../SOUL.md", unixCWD, unixHome, "COG-SOUL"},
		{"codex Unix relative tee", "codex", "printf changed | tee -a AGENTS.md", unixCWD, unixHome, "COG-AGENTS-MD"},
		{"codex Unix relative cp", "codex", "cp /tmp/new.md SOUL.md", unixCWD, unixHome, "COG-SOUL"},
		{"claude Unix wrapped relative", "claudecode", "sh -c 'printf changed >> CLAUDE.md'", unixCWD, unixHome, "COG-CLAUDE-MD"},
		{"claude Windows Git Bash quoted drive path", "claudecode", `printf changed >> 'C:\Repo\CLAUDE.md'`, winCWD, winHome, "COG-CLAUDE-MD"},
		{"claude Windows Git Bash double-quoted drive path", "claudecode", `printf changed >> "C:\Repo\CLAUDE.md"`, winCWD, winHome, "COG-CLAUDE-MD"},
		{"claude Windows Git Bash forward-slash drive path", "claudecode", "printf changed >> C:/Repo/CLAUDE.md", winCWD, winHome, "COG-CLAUDE-MD"},
		{"codex Windows Git Bash forward-slash SOUL", "codex", "printf changed > C:/Users/alice/scratch/SOUL.md", winCWD, winHome, "COG-SOUL"},
		{"claude Windows Git Bash relative in drive CWD", "claudecode", "printf changed >> CLAUDE.md", winCWD, winHome, "COG-CLAUDE-MD"},
		{"codex Windows Git Bash relative AGENTS", "codex", "printf changed > AGENTS.md", winCWD, winHome, "COG-AGENTS-MD"},
		{"claude Windows Git Bash MSYS drive path", "claudecode", "printf changed >> /c/Repo/CLAUDE.md", winCWD, winHome, "COG-CLAUDE-MD"},
		{"claude Windows Git Bash home path", "claudecode", "printf changed >> ~/CLAUDE.md", winCWD, winHome, "COG-CLAUDE-MD"},
		{"claude Windows Git Bash tee relative", "claudecode", "printf changed | tee CLAUDE.md", winCWD, winHome, "COG-CLAUDE-MD"},
		{"claude Unix relative ordinary write", "claudecode", "printf changed >> notes.txt", unixCWD, unixHome, ""},
		{"claude Unix relative lookalike", "claudecode", "printf changed >> CLAUDE.md.bak", unixCWD, unixHome, ""},
		{"claude Unix name in write data", "claudecode", "printf CLAUDE.md >> notes.txt", unixCWD, unixHome, ""},
		{"claude Unix relative read", "claudecode", "cat CLAUDE.md", unixCWD, unixHome, ""},
		{"claude Windows relative ordinary write", "claudecode", "printf changed >> notes.txt", winCWD, winHome, ""},
		{"claude Windows drive ordinary write", "claudecode", `printf changed >> 'C:\Repo\notes.txt'`, winCWD, winHome, ""},
		{"codex Windows forward-slash ordinary write", "codex", "printf changed > C:/Repo/build/out.txt", winCWD, winHome, ""},
		{"claude Windows name in write data", "claudecode", `printf CLAUDE.md >> 'C:\Repo\notes.txt'`, winCWD, winHome, ""},
		{"claude Windows relative read", "claudecode", "cat CLAUDE.md", winCWD, winHome, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			installToolCallCorpusProfileConnector(t, tc.connector, "default")
			cfg := &config.Config{}
			cfg.Guardrail.Mode = "action"
			cfg.Guardrail.Connector = tc.connector
			cfg.Guardrail.BlockAt = "HIGH"
			cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), "default")
			args, err := json.Marshal(map[string]string{"command": tc.command})
			if err != nil {
				t.Fatal(err)
			}
			request := &ToolInspectRequest{Tool: "Bash", Args: args, Direction: "tool_call", Connector: tc.connector}
			// No ActiveAgentFiles: a restarted gateway has no loaded-file
			// snapshot for any session.
			action := trustedActionRequest{
				Input:      actionfacts.Input{Tool: "Bash", Args: args, CWD: tc.cwd, ActiveHome: tc.home},
				LegacyText: string(args), Connector: tc.connector, EnforcementCapable: true,
			}
			verdict := (&APIServer{scannerCfg: cfg}).inspectTrustedToolPolicyCtx(t.Context(), request, action)
			block := tc.rule != ""
			if (verdict.Action == guardrailActionBlock) != block ||
				block && !findingStringHasRuleID(verdict.Findings, tc.rule) {
				t.Fatalf("verdict=%+v, want block=%t rule=%q", verdict, block, tc.rule)
			}
		})
	}
}

// GAP-0995: the native hook routes of Claude Code and Codex, on a gateway
// that never saw the session's InstructionsLoaded event, block a relative
// instruction-file write in the session's own directory and allow an
// ordinary relative write there.
func TestGAP0995NativeHookRoutesBlockRelativeInstructionWriteAfterRestart(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"CLAUDE.md", "AGENTS.md"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("instructions\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		connector, command, rule string
	}{
		{"claudecode", "printf changed >> CLAUDE.md", "COG-CLAUDE-MD"},
		{"codex", "printf changed >> AGENTS.md", "COG-AGENTS-MD"},
		{"claudecode", "printf changed >> notes.txt", ""},
		{"codex", "printf changed >> notes.txt", ""},
	} {
		t.Run(tc.connector+" "+tc.command, func(t *testing.T) {
			installToolCallCorpusProfileConnector(t, tc.connector, "default")
			cfg := &config.Config{}
			cfg.Guardrail.Mode = "action"
			cfg.Guardrail.Connector = tc.connector
			cfg.Guardrail.BlockAt = "HIGH"
			cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), "default")
			api := &APIServer{scannerCfg: cfg}
			var action string
			var findings []string
			if tc.connector == "claudecode" {
				response := api.evaluateClaudeCodeHook(t.Context(), claudeCodeHookRequest{
					HookEventName: "PreToolUse", SessionID: "existing-session", CWD: root,
					ToolName: "Bash", ToolInput: map[string]interface{}{"command": tc.command},
				})
				action, findings = response.Action, response.Findings
			} else {
				response := api.evaluateCodexHook(t.Context(), codexHookRequest{
					HookEventName: "PreToolUse", SessionID: "existing-session", CWD: root,
					ToolName: "Bash", ToolInput: map[string]interface{}{"command": tc.command},
				})
				action, findings = response.Action, response.Findings
			}
			block := tc.rule != ""
			if (action == guardrailActionBlock) != block || block && !findingStringHasRuleID(findings, tc.rule) {
				t.Fatalf("action=%q findings=%v, want block=%t rule=%q", action, findings, block, tc.rule)
			}
		})
	}
}
