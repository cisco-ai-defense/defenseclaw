// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
)

// TestShellExtraArgumentKeysWindowsDialect: on a Windows host the shell
// dialect of a structured tool call is inferred from its command, and an
// extra argument key left that inference empty, so the command judged on its
// own was read as POSIX and a PowerShell write to authorized_keys had no
// finding (GAP-0686). The command alone now has its own dialect inferred.
// It runs on every platform: the inference reads only the arguments.
func TestShellExtraArgumentKeysWindowsDialect(t *testing.T) {
	const home = `C:\Users\u`
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "opencode"
	api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
	for _, command := range []string{
		`echo k >> $HOME\.ssh\authorized_keys`,
		`echo k >> ~\.ssh\authorized_keys`,
	} {
		alone := mustJSON(t, map[string]string{"command": command})
		input := actionfacts.Input{Tool: "shell", Args: alone, CWD: home + `\proj`, ActiveHome: home}
		if hint := agentHookWindowsShellDialect(input); hint != actionfacts.DialectPowerShell {
			t.Fatalf("%s alone: dialect %q, want powershell", command, hint)
		}
		full := mustJSON(t, map[string]string{"command": command, "extra": "x"})
		input.Args = full
		input.DialectHint = agentHookWindowsShellDialect(input)
		if input.DialectHint != "" {
			t.Fatalf("%s with an extra key: dialect %q; the regression needs the empty hint", command, input.DialectHint)
		}
		for _, inferred := range []bool{true, false} {
			verdict := api.inspectSandboxShellToolPolicyCtx(t.Context(),
				&ToolInspectRequest{Tool: "bash", Args: full, Direction: "tool_call", Connector: "opencode"},
				trustedActionRequest{
					Input: input, LegacyText: string(full), Connector: "opencode",
					EnforcementCapable: true, windowsShellDialect: inferred,
				}, json.RawMessage(alone), "shell")
			if verdict == nil {
				t.Fatalf("%s: no verdict", command)
			}
			blocked := verdict.Action == guardrailActionBlock && verdictHasFinding(verdict, "persistence.ssh_authorized_keys_command")
			if inferred && !blocked {
				t.Errorf("%s with an extra key: verdict %s %v, want block with the authorized-keys finding", command, verdict.Action, verdict.Findings)
			}
			if !inferred && blocked {
				// Without an inferred hint (Claude Code, Linux and macOS
				// hosts) the command keeps the dialect it came with.
				t.Errorf("%s with no inferred hint: verdict %s %v; want the call's own dialect", command, verdict.Action, verdict.Findings)
			}
		}
	}
}

func verdictHasFinding(verdict *ToolInspectVerdict, ruleID string) bool {
	for _, finding := range verdict.DetailedFindings {
		if finding.RuleID == ruleID {
			return true
		}
	}
	for _, finding := range verdict.Findings {
		if finding == ruleID {
			return true
		}
	}
	return false
}
