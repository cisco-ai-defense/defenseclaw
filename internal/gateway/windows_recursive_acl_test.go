// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
)

const windowsRecursiveEveryoneFullControlRuleID = "tamper.windows_recursive_everyone_full_control"

func TestWindowsRecursiveEveryoneFullControlProfilePosture(t *testing.T) {
	const command = `icacls 'C:\inetpub\wwwroot\intranet' /grant 'Everyone:(OI)(CI)F' /T`
	input := actionfacts.Input{
		Tool: "powershell", Command: command, CWD: `C:\repo`,
		DialectHint: actionfacts.DialectPowerShell,
	}
	facts := actionfacts.Analyze(input)
	if !actionfacts.ExactWindowsRecursiveEveryoneFullControl(facts) {
		t.Fatalf("exact ActionFacts proof did not match: %+v", facts)
	}
	proof, owned := trustedSemanticOwnerFindingProof(
		windowsRecursiveEveryoneFullControlRuleID, input, facts,
	)
	if !owned || !proof.authorizes(windowsRecursiveEveryoneFullControlRuleID) {
		t.Fatalf("exact owner did not authorize proof=%+v facts=%+v", proof, facts)
	}

	profiles := []struct {
		name     string
		action   string
		severity string
	}{
		{name: "default", action: "block", severity: "CRITICAL"},
		{name: "permissive", action: "alert", severity: "HIGH"},
		{name: "strict", action: "block", severity: "CRITICAL"},
	}
	for _, profile := range profiles {
		profile := profile
		t.Run(profile.name, func(t *testing.T) {
			const connector = "codex"
			installToolCallCorpusProfileConnector(t, connector, profile.name)
			cfg := &config.Config{}
			cfg.Guardrail.Mode = "action"
			cfg.Guardrail.Connector = connector
			cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), profile.name)
			response := (&APIServer{scannerCfg: cfg}).evaluateCodexHook(
				t.Context(),
				codexHookRequest{
					HookEventName: "PreToolUse",
					ToolName:      "powershell",
					CWD:           `C:\repo`,
					ToolInput:     map[string]interface{}{"command": command},
				},
			)
			if response.Action != profile.action || response.RawAction != profile.action ||
				response.Severity != profile.severity ||
				!findingStringHasRuleID(response.Findings, windowsRecursiveEveryoneFullControlRuleID) {
				t.Fatalf("response=%+v want %s/%s with %s", response, profile.action, profile.severity, windowsRecursiveEveryoneFullControlRuleID)
			}
		})
	}
}

func TestWindowsRecursiveEveryoneFullControlNearMissesStayQuiet(t *testing.T) {
	const connector = "windows-recursive-acl-near-misses"
	installToolCallCorpusProfileConnector(t, connector, "strict")
	commands := []string{
		`icacls 'C:\inetpub\wwwroot' /grant 'Everyone:(OI)(CI)F'`,
		`icacls 'C:\inetpub\wwwroot' /grant 'Everyone:(OI)(CI)R' /T`,
		`icacls 'C:\inetpub\wwwroot' /grant 'Everyone:(OI)(CI)(IO)F' /T`,
		`icacls 'C:\inetpub\wwwroot' /grant 'Developers:(OI)(CI)F' /T`,
		`Write-Output "Example: icacls C:\inetpub\wwwroot /grant Everyone:(OI)(CI)F /T"`,
	}
	for _, command := range commands {
		input := actionfacts.Input{
			Tool: "powershell", Command: command, CWD: `C:\repo`,
			DialectHint: actionfacts.DialectPowerShell,
		}
		facts := actionfacts.Analyze(input)
		if actionfacts.ExactWindowsRecursiveEveryoneFullControl(facts) {
			t.Fatalf("near miss minted exact proof: %q facts=%+v", command, facts)
		}
		findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
			Input: input, LegacyText: command, Connector: connector, EnforcementCapable: true,
		})
		if finding := findingWithID(findings, windowsRecursiveEveryoneFullControlRuleID); finding != nil {
			t.Fatalf("near miss matched dedicated rule: %q finding=%+v", command, *finding)
		}
	}
}

func TestWindowsRecursiveEveryoneFullControlFallbackContract(t *testing.T) {
	contract, ok := exactFallbackContracts[windowsRecursiveEveryoneFullControlRuleID]
	if !ok || contract.proves == nil || contract.boundedSubgraphProves == nil || contract.detectionOnly {
		t.Fatalf("recursive ACL fallback contract is incomplete: %+v", contract)
	}
}
