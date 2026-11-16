// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

// A complete-argv marker rule blocks the cmd.exe wrapper forms beyond the
// plain one: a PowerShell list after it, /r (the synonym of /c), joined
// switches, and the call operator without a space.
func TestCMDWrapperListAndSwitchFormsKeepTheArgvMarkerEnforceable(t *testing.T) {
	resetConnectorRuleCategories(t)
	const ruleID = "R104-CMD-MARKER-BLOCK"
	if err := ApplyRulePackOverrides(&guardrail.RulePack{RuleFiles: []*guardrail.RulesFileYAML{{
		Version: 1, Category: "r104-cmd-marker", Rules: []guardrail.RuleDefYAML{{
			ID: ruleID, ToolCallOnly: true,
			Pattern:    "dccert-block-marker",
			Expression: `f.commands.exists(c, c.argv_complete && "dccert-block-marker" in c.argv)`,
			Title:      "cmd marker block", Severity: "CRITICAL", Confidence: 0.99,
		}},
	}}}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		command string
		blocked bool
	}{
		{`cmd.exe /c echo dccert-block-marker > x.txt && type x.txt`, true},
		{`cmd.exe /c echo dccert-block-marker > x.txt; type x.txt`, true},
		{`cmd.exe /r echo dccert-block-marker > x.txt`, true},
		{`cmd.exe /d/c echo dccert-block-marker > x.txt`, true},
		{`cmd.exe /d/q /c echo dccert-block-marker > x.txt`, true},
		{`&cmd.exe /c echo dccert-block-marker > x.txt`, true},
		{`cmd.exe /c echo hello > x.txt && type x.txt`, false},
		{`cmd.exe /d/k echo dccert-block-marker > x.txt`, false},
		{`cmd.exe /c/d echo dccert-block-marker > x.txt`, false},
		{`cmd.exe /x/c echo dccert-block-marker > x.txt`, false},
	} {
		findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
			Input:      actionfacts.Input{Tool: "powershell", Command: tc.command, DialectHint: actionfacts.DialectPowerShell},
			LegacyText: tc.command, Connector: "codex", EnforcementCapable: true,
		})
		match := findingWithID(findings, ruleID)
		if enforced := match != nil && match.contributesToEnforcement(); enforced != tc.blocked {
			t.Errorf("%s: enforced=%v, want %v (%v)", tc.command, enforced, tc.blocked, FindingStrings(findings))
		}
	}
}
