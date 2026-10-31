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
		if hint := agentHookWindowsShellDialect("", input); hint != actionfacts.DialectPowerShell {
			t.Fatalf("%s alone: dialect %q, want powershell", command, hint)
		}
		full := mustJSON(t, map[string]string{"command": command, "extra": "x"})
		input.Args = full
		input.DialectHint = agentHookWindowsShellDialect("", input)
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
			if !blocked {
				// A missing hint leaves a file effect whose destination
				// cannot be proved ordinary. The protected-write class rule
				// closes that route as well as the inferred PowerShell route.
				t.Errorf("%s with an extra key (inferred=%v): verdict %s %v, want block", command, inferred, verdict.Action, verdict.Findings)
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
