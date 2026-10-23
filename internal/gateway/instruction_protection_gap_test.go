// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

func instructionProtectionTestAPI(t *testing.T, connector, mode, blockAt string) *APIServer {
	t.Helper()
	installToolCallCorpusProfileConnector(t, connector, "default")
	cfg := &config.Config{}
	cfg.Guardrail.Mode = mode
	cfg.Guardrail.Connector = connector
	cfg.Guardrail.BlockAt = blockAt
	cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), "default")
	return &APIServer{scannerCfg: cfg}
}

func instructionResolvedWriteContext(t *testing.T, cwd, tool string, input map[string]interface{}) context.Context {
	t.Helper()
	body := mustJSON(t, map[string]interface{}{
		"hook_event_name": "PreToolUse", "session_id": "live", "cwd": cwd,
		"tool_name": tool, "tool_input": input,
	})
	targets, ok := hookpaths.Decode(hookpaths.Resolve(body))
	if !ok || len(targets) == 0 {
		t.Fatalf("native hook did not resolve write targets for %s", tool)
	}
	return context.WithValue(t.Context(), resolvedWritesContextKey{}, targets)
}

func TestInstructionProtectionRelativeClaudeAcrossGatewayRestart(t *testing.T) {
	root := t.TempDir()
	file := writeActiveAgentTestFile(t, root, "CLAUDE.md")
	before := instructionProtectionTestAPI(t, "claudecode", "action", "HIGH")
	before.evaluateClaudeCodeHook(authenticatedClaudeCodeTestContext(), claudeCodeHookRequest{
		HookEventName: "InstructionsLoaded", SessionID: "live", FilePath: file,
	})
	input := map[string]interface{}{"command": "printf changed >> CLAUDE.md"}
	ctx := withAuthenticatedHookConnector(instructionResolvedWriteContext(t, root, "Bash", input), "claudecode")
	for _, api := range []*APIServer{before, instructionProtectionTestAPI(t, "claudecode", "action", "HIGH")} {
		response := api.evaluateClaudeCodeHook(ctx, claudeCodeHookRequest{
			HookEventName: "PreToolUse", SessionID: "live", CWD: root, ToolName: "Bash",
			ToolInput: input,
		})
		if response.Action != guardrailActionBlock || !findingStringHasRuleID(response.Findings, "COG-CLAUDE-MD") {
			t.Fatalf("relative active CLAUDE.md: action=%q findings=%v", response.Action, response.Findings)
		}
	}
	observed := instructionProtectionTestAPI(t, "claudecode", "observe", "HIGH").evaluateClaudeCodeHook(
		ctx, claudeCodeHookRequest{
			HookEventName: "PreToolUse", SessionID: "live", CWD: root, ToolName: "Bash",
			ToolInput: input,
		})
	if observed.Action != "allow" || observed.RawAction != "block" || !observed.WouldBlock ||
		!findingStringHasRuleID(observed.Findings, "COG-CLAUDE-MD") {
		t.Fatalf("observe mode lost write finding: %+v", observed)
	}
}

func TestInstructionProtectionClaudeStartupAndResume(t *testing.T) {
	root := t.TempDir()
	writeActiveAgentTestFile(t, root, "CLAUDE.md")
	input := map[string]interface{}{"command": "printf changed >> CLAUDE.md"}
	ctx := withAuthenticatedHookConnector(instructionResolvedWriteContext(t, root, "Bash", input), "claudecode")
	for _, source := range []string{"startup", "resume"} {
		t.Run(source, func(t *testing.T) {
			api := instructionProtectionTestAPI(t, "claudecode", "action", "HIGH")
			api.evaluateClaudeCodeHook(ctx, claudeCodeHookRequest{
				HookEventName: "SessionStart", SessionID: source, Source: source, CWD: root,
			})
			// Native Claude may report InstructionsLoaded without a file_path.
			// The first tool call must still protect a proven instruction write.
			api.evaluateClaudeCodeHook(ctx, claudeCodeHookRequest{
				HookEventName: "InstructionsLoaded", SessionID: source, CWD: root,
			})
			response := api.evaluateClaudeCodeHook(ctx, claudeCodeHookRequest{
				HookEventName: "PreToolUse", SessionID: source, CWD: root,
				ToolName: "Bash", ToolInput: input,
			})
			if response.Action != guardrailActionBlock || !findingStringHasRuleID(response.Findings, "COG-CLAUDE-MD") {
				t.Fatalf("%s first instruction write: action=%q findings=%v", source, response.Action, response.Findings)
			}
		})
	}
}

func TestInstructionProtectionCodexNativeTools(t *testing.T) {
	root := t.TempDir()
	writeActiveAgentTestFile(t, root, "AGENTS.md")
	api := instructionProtectionTestAPI(t, "codex", "action", "HIGH")
	for _, tc := range []struct {
		name, tool string
		input      map[string]interface{}
	}{
		{"exec command", "exec_command", map[string]interface{}{"cmd": "printf changed >> AGENTS.md"}},
		{"apply patch", "apply_patch", map[string]interface{}{"command": "*** Begin Patch\n*** Update File: AGENTS.md\n@@\n test instructions\n+changed\n*** End Patch"}},
		{"exec patch heredoc", "exec_command", map[string]interface{}{"cmd": "apply_patch <<'PATCH'\n*** Begin Patch\n*** Update File: AGENTS.md\n@@\n test instructions\n+changed\n*** End Patch\nPATCH"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := instructionResolvedWriteContext(t, root, tc.tool, tc.input)
			response := api.evaluateCodexHook(ctx, codexHookRequest{
				HookEventName: "PreToolUse", SessionID: "codex-live", CWD: root,
				ToolName: tc.tool, ToolInput: tc.input,
			})
			if response.Action != guardrailActionBlock || !findingStringHasRuleID(response.Findings, "COG-AGENTS-MD") {
				t.Fatalf("Codex %s: action=%q findings=%v", tc.tool, response.Action, response.Findings)
			}
		})
	}
}

func TestInstructionProtectionUsesClientResolvedAlias(t *testing.T) {
	root := t.TempDir()
	agentFile := writeActiveAgentTestFile(t, root, "AGENTS.md")
	alias := filepath.Join(root, "active-link")
	if err := os.Symlink(agentFile, alias); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	api := instructionProtectionTestAPI(t, "codex", "action", "HIGH")
	body := mustJSON(t, map[string]interface{}{
		"hook_event_name": "PreToolUse", "session_id": "alias-session", "cwd": root,
		"tool_name": "exec_command", "tool_input": map[string]interface{}{"cmd": "printf changed > active-link"},
	})
	targets, ok := hookpaths.Decode(hookpaths.Resolve(body))
	if !ok || targets[alias] != agentFile {
		t.Fatalf("client resolved writes = %v, ok=%t", targets, ok)
	}
	ctx := context.WithValue(t.Context(), resolvedWritesContextKey{}, targets)
	response := api.evaluateCodexHook(ctx, codexHookRequest{
		HookEventName: "PreToolUse", SessionID: "alias-session", CWD: root,
		ToolName: "exec_command", ToolInput: map[string]interface{}{"cmd": "printf changed > active-link"},
	})
	if response.Action != guardrailActionBlock || !findingStringHasRuleID(response.Findings, "COG-AGENTS-MD") {
		t.Fatalf("resolved alias: action=%q findings=%v", response.Action, response.Findings)
	}
}

func TestInstructionProtectionRelativeWindowsShellsAndThreshold(t *testing.T) {
	for _, tc := range []struct {
		name, command, rule string
		dialect             actionfacts.Dialect
	}{
		{"PowerShell", `Set-Content -LiteralPath '.\CLAUDE.md' -Value changed`, "COG-CLAUDE-MD", actionfacts.DialectPowerShell},
		{"PowerShell SOUL", `Add-Content -LiteralPath '.\SOUL.md' -Value changed`, "COG-SOUL", actionfacts.DialectPowerShell},
		{"PowerShell OpenClaw case", `Set-Content -LiteralPath '.\openclaw.JSON' -Value changed`, "COG-OPENCLAW-JSON", actionfacts.DialectPowerShell},
		{"cmd", `echo changed > CLAUDE.md`, "COG-CLAUDE-MD", actionfacts.DialectCMD},
	} {
		t.Run(tc.name, func(t *testing.T) {
			api := instructionProtectionTestAPI(t, "claudecode", "action", "HIGH")
			input := actionfacts.Input{Tool: "Bash", Command: tc.command, CWD: `C:\Repo`, ActiveHome: `C:\Users\alice`, DialectHint: tc.dialect}
			verdict := api.inspectTrustedToolPolicyCtx(t.Context(), &ToolInspectRequest{Tool: "Bash", Direction: "tool_call", Connector: "claudecode"}, trustedActionRequest{
				Input: input, LegacyText: tc.command, Connector: "claudecode", EnforcementCapable: true,
			})
			if verdict.Action != guardrailActionBlock || !findingStringHasRuleID(verdict.Findings, tc.rule) {
				t.Fatalf("%s relative write: action=%q findings=%v; facts=%+v", tc.name, verdict.Action, verdict.Findings, actionfacts.Analyze(input))
			}
		})
	}
	api := instructionProtectionTestAPI(t, "claudecode", "action", "CRITICAL")
	response := api.evaluateClaudeCodeHook(t.Context(), claudeCodeHookRequest{
		HookEventName: "PreToolUse", CWD: "/repo", ToolName: "Bash",
		ToolInput: map[string]interface{}{"command": "printf changed > /repo/CLAUDE.md"},
	})
	if response.Action == guardrailActionBlock {
		t.Fatalf("HIGH finding ignored CRITICAL block threshold: %+v", response)
	}
}

func TestInstructionProtectionPOSIXCaseRequiresExactInstructionName(t *testing.T) {
	api := instructionProtectionTestAPI(t, "codex", "action", "HIGH")
	for _, tc := range []struct {
		name, command string
		blocked       bool
	}{
		{"canonical", "printf changed > /repo/AGENTS.md", true},
		{"distinct lowercase file", "printf changed > /repo/agents.md", false},
		{"OpenClaw canonical", "printf changed > /repo/openclaw.json", true},
		{"OpenClaw distinct case", "printf changed > /repo/openclaw.JSON", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			verdict := api.inspectTrustedToolPolicyCtx(t.Context(),
				&ToolInspectRequest{Tool: "Bash", Direction: "tool_call", Connector: "codex"},
				trustedActionRequest{Input: actionfacts.Input{Tool: "Bash", Command: tc.command, CWD: "/repo"},
					LegacyText: tc.command, Connector: "codex", EnforcementCapable: true})
			if got := verdict.Action == guardrailActionBlock; got != tc.blocked {
				t.Fatalf("command=%q blocked=%t, want %t; findings=%v", tc.command, got, tc.blocked, verdict.Findings)
			}
		})
	}
}

func TestInstructionProtectionCaseInsensitivePOSIXAlias(t *testing.T) {
	for _, tc := range []struct{ canonical, alias, rule string }{
		{"CLAUDE.md", "claude.md", "COG-CLAUDE-MD"},
		{"openclaw.json", "openclaw.JSON", "COG-OPENCLAW-JSON"},
	} {
		t.Run(tc.canonical, func(t *testing.T) {
			root := t.TempDir()
			canonical := writeActiveAgentTestFile(t, root, tc.canonical)
			alias := filepath.Join(root, tc.alias)
			originalInfo, err := os.Stat(canonical)
			if err != nil {
				t.Fatal(err)
			}
			aliasInfo, err := os.Stat(alias)
			if err != nil || !os.SameFile(originalInfo, aliasInfo) {
				t.Skip("this POSIX volume is case-sensitive")
			}
			input := map[string]interface{}{"command": "printf changed > " + tc.alias}
			ctx := withAuthenticatedHookConnector(
				instructionResolvedWriteContext(t, root, "Bash", input), "claudecode",
			)
			response := instructionProtectionTestAPI(t, "claudecode", "action", "HIGH").evaluateClaudeCodeHook(
				ctx, claudeCodeHookRequest{
					HookEventName: "PreToolUse", SessionID: "case-alias", CWD: root,
					ToolName: "Bash", ToolInput: input,
				})
			if response.Action != guardrailActionBlock || !findingStringHasRuleID(response.Findings, tc.rule) {
				t.Fatalf("case alias %q reached an active %q: action=%q findings=%v", tc.alias, tc.canonical, response.Action, response.Findings)
			}
		})
	}
}

func TestInstructionProtectionPOSIXCaseAliasHardLink(t *testing.T) {
	root := t.TempDir()
	canonical := writeActiveAgentTestFile(t, root, "CLAUDE.md")
	alias := filepath.Join(root, "claude.md")
	if err := os.Link(canonical, alias); err != nil {
		if os.IsExist(err) {
			t.Skip("this POSIX volume is already case-insensitive")
		}
		t.Fatal(err)
	}
	input := map[string]interface{}{"command": "printf changed > claude.md"}
	ctx := withAuthenticatedHookConnector(instructionResolvedWriteContext(t, root, "Bash", input), "claudecode")
	response := instructionProtectionTestAPI(t, "claudecode", "action", "HIGH").evaluateClaudeCodeHook(
		ctx, claudeCodeHookRequest{
			HookEventName: "PreToolUse", SessionID: "hardlink-alias", CWD: root,
			ToolName: "Bash", ToolInput: input,
		})
	if response.Action != guardrailActionBlock || !findingStringHasRuleID(response.Findings, "COG-CLAUDE-MD") {
		t.Fatalf("hard link to active CLAUDE.md: action=%q findings=%v", response.Action, response.Findings)
	}
}

func TestInstructionProtectionSharedConnectorAndFileMatrix(t *testing.T) {
	for _, connectorName := range connector.NewDefaultRegistry().Names() {
		t.Run(connectorName, func(t *testing.T) {
			api := instructionProtectionTestAPI(t, connectorName, "action", "HIGH")
			command := "printf changed > CLAUDE.md"
			verdict := api.inspectTrustedToolPolicyCtx(t.Context(),
				&ToolInspectRequest{Tool: "Bash", Direction: "tool_call", Connector: connectorName},
				trustedActionRequest{Input: actionfacts.Input{Tool: "Bash", Command: command, CWD: "/repo"},
					LegacyText: command, Connector: connectorName, EnforcementCapable: true})
			if verdict.Action != guardrailActionBlock || !findingStringHasRuleID(verdict.Findings, "COG-CLAUDE-MD") {
				t.Fatalf("connector=%q action=%q findings=%v", connectorName, verdict.Action, verdict.Findings)
			}
		})
	}
	api := instructionProtectionTestAPI(t, "codex", "action", "HIGH")
	for _, tc := range []struct{ file, rule string }{
		{"AGENTS.md", "COG-AGENTS-MD"}, {"CLAUDE.md", "COG-CLAUDE-MD"},
		{"SOUL.md", "COG-SOUL"}, {"IDENTITY.md", "COG-IDENTITY"},
		{"MEMORY.md", "COG-MEMORY"}, {"TOOLS.md", "COG-TOOLS-MD"},
		{"openclaw.json", "COG-OPENCLAW-JSON"}, {"gateway.json", "COG-GATEWAY-JSON"},
	} {
		t.Run(tc.file, func(t *testing.T) {
			command := "printf changed > " + tc.file
			verdict := api.inspectTrustedToolPolicyCtx(t.Context(),
				&ToolInspectRequest{Tool: "Bash", Direction: "tool_call", Connector: "codex"},
				trustedActionRequest{Input: actionfacts.Input{Tool: "Bash", Command: command, CWD: "/repo"},
					LegacyText: command, Connector: "codex", EnforcementCapable: true})
			if verdict.Action != guardrailActionBlock || !findingStringHasRuleID(verdict.Findings, tc.rule) {
				t.Fatalf("file=%q action=%q findings=%v", tc.file, verdict.Action, verdict.Findings)
			}
		})
	}
}

func TestInstructionProtectionCannotBeSkippedByToolAllow(t *testing.T) {
	root := t.TempDir()
	writeActiveAgentTestFile(t, root, "AGENTS.md")
	api := instructionProtectionTestAPI(t, "codex", "action", "HIGH")
	allowTool(api.scannerCfg, "Bash", "codex", "ordinary shell work")
	input := map[string]interface{}{"command": "printf changed > AGENTS.md"}
	ctx := instructionResolvedWriteContext(t, root, "Bash", input)
	response := api.evaluateCodexHook(ctx, codexHookRequest{
		HookEventName: "PreToolUse", SessionID: "allowed-shell", CWD: root,
		ToolName: "Bash", ToolInput: input,
	})
	if response.Action != guardrailActionBlock || !findingStringHasRuleID(response.Findings, "COG-AGENTS-MD") {
		t.Fatalf("allow-listed shell wrote an instruction file: action=%q findings=%v", response.Action, response.Findings)
	}
}
