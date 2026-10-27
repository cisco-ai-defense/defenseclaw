// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"context"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// GAP-1389: a benign skill-only formatting plugin got two judge HIGHs
// (LLM-OB-009-001 "manifest-only plugin", META-LLM-001 "opaque
// functionality") next to judge MEDIUMs, the no-source note and a static
// LOW (the native G51 finding set) and was quarantined in default. The
// pre-step warns on such a plugin in default and permissive; the findings
// stay HIGH; every explicit action, the strict tier and Secure Client keep
// their decision.
func TestWarnJudgeOnlyPluginHigh(t *testing.T) {
	eng := repoEngine(t)
	gap1389 := []FindingInput{
		{Severity: "HIGH", Scanner: "plugin-scanner", RuleID: "LLM-OB-009-001", Title: "Manifest-only plugin with no source code available"},
		{Severity: "HIGH", Scanner: "plugin-scanner", RuleID: "META-LLM-001", Title: "Manifest-only plugin with opaque functionality"},
		{Severity: "MEDIUM", Scanner: "plugin-scanner", RuleID: "META-LLM-002", Title: "Unable to validate permission claims"},
		{Severity: "MEDIUM", Scanner: "plugin-scanner", RuleID: "SCAN-LLM-NO-SOURCE", Title: "LLM analysis ran without any plugin source files"},
		{Severity: "LOW", Scanner: "plugin-scanner", RuleID: "PERM-NONE", Title: "declares no permissions"},
		{Severity: "INFO", Scanner: "plugin-scanner", RuleID: "META-LLM-FP-ADVISORY", Title: "possible false positive in PERM-NONE"},
	}
	with := func(extra ...FindingInput) []FindingInput {
		return append(append([]FindingInput(nil), gap1389...), extra...)
	}
	quarantine := &config.AdmissionAction{Shorthand: config.AdmissionActionQuarantine}
	block := &config.AdmissionAction{Shorthand: config.AdmissionActionBlock}
	warn := &config.AdmissionAction{Shorthand: config.AdmissionActionWarn}
	bypass := false
	cases := []struct {
		name     string
		edit     func(*config.Config)
		target   string
		findings []FindingInput
		total    int
		max      string
		want     string
	}{
		{name: "GAP-1389 plugin in default", findings: gap1389, want: "warning"},
		{name: "one judge HIGH alone", findings: gap1389[:1], want: "warning"},
		{name: "judge MEDIUM beside the judge HIGH", findings: with(FindingInput{Severity: "MEDIUM", RuleID: "LLM-OB-013-001"}), want: "warning"},
		{name: "permissive rule pack", edit: func(c *config.Config) { c.Guardrail.RulePack = "permissive" }, findings: gap1389, want: "warning"},
		{name: "permissive preset (defaults HIGH warn)", edit: func(c *config.Config) { c.Admission.Defaults.Actions.High = warn }, findings: gap1389, want: "warning"},
		// A static concrete threat keeps the block.
		{name: "static HIGH beside the judge", findings: with(FindingInput{Severity: "HIGH", RuleID: "SRC-EXFIL-001", Title: "reads ~/.ssh and posts it"}), want: "rejected"},
		{name: "static MEDIUM beside the judge", findings: with(FindingInput{Severity: "MEDIUM", RuleID: "SRC-NET-002", Title: "network call"}), want: "rejected"},
		{name: "deterministic META chain", findings: with(FindingInput{Severity: "MEDIUM", RuleID: "META-EXFIL-CHAIN"}), want: "rejected"},
		{name: "static CRITICAL", findings: with(FindingInput{Severity: "CRITICAL", RuleID: "SRC-EVAL-001"}), max: "CRITICAL", want: "rejected"},
		{name: "judge CRITICAL", findings: []FindingInput{{Severity: "CRITICAL", RuleID: "LLM-OB-008-001"}}, max: "CRITICAL", want: "rejected"},
		{name: "judge failure beside a judge HIGH", findings: with(FindingInput{Severity: "MEDIUM", RuleID: "LLM-SCAN-ERROR"}), want: "rejected"},
		{name: "another LLM rule id", findings: []FindingInput{{Severity: "HIGH", RuleID: "LLM-UNKNOWN"}}, want: "rejected"},
		{name: "a second META rule id", findings: []FindingInput{{Severity: "HIGH", RuleID: "META-LLM-CORR"}}, want: "rejected"},
		{name: "meta advisory id at HIGH", findings: []FindingInput{{Severity: "HIGH", RuleID: "META-LLM-FP-ADVISORY"}}, want: "rejected"},
		{name: "meta answer without a rule id", findings: []FindingInput{{Severity: "HIGH", RuleID: "META-LLM-UNKNOWN"}}, want: "rejected"},
		// GAP-2107: the number of a meta missed threat is the model's count.
		{name: "another meta missed threat at HIGH", findings: []FindingInput{{Severity: "HIGH", RuleID: "META-LLM-002"}}, want: "warning"},
		{name: "meta missed threat the scanner prefixed", findings: with(FindingInput{Severity: "HIGH", RuleID: "META-LLM-MISSED-001"}), want: "warning"},
		{name: "unknown severity", findings: with(FindingInput{Severity: "SEVERE", RuleID: "LLM-OB-009-002"}), want: "rejected"},
		{name: "incomplete findings list", findings: gap1389, total: 4, want: "rejected"},
		{name: "count-only input", total: 2, want: "rejected"},
		// Explicit actions, strict and Secure Client are unchanged.
		{name: "explicit plugin HIGH quarantine", edit: func(c *config.Config) { c.Admission.Plugin.Actions.High = quarantine }, findings: gap1389, want: "rejected"},
		{name: "explicit plugin HIGH block (G51 fixture)", edit: func(c *config.Config) { c.Admission.Plugin.Actions.High = block }, findings: gap1389, want: "rejected"},
		{name: "explicit defaults HIGH quarantine", edit: func(c *config.Config) { c.Admission.Defaults.Actions.High = quarantine }, findings: gap1389, want: "rejected"},
		{name: "explicit HIGH quarantine, permissive rule pack", edit: func(c *config.Config) {
			c.Guardrail.RulePack = "permissive"
			c.Admission.Plugin.Actions.High = quarantine
		}, findings: gap1389, want: "rejected"},
		{name: "scanner override HIGH quarantine", edit: func(c *config.Config) {
			c.Admission.Plugin.ScannerOverrides = map[string]config.AdmissionActionMap{"plugin-scanner": {High: quarantine}}
		}, findings: gap1389, want: "rejected"},
		{name: "blocking MEDIUM", edit: func(c *config.Config) { c.Admission.Plugin.Actions.Medium = quarantine }, findings: gap1389, want: "rejected"},
		{name: "strict rule pack", edit: func(c *config.Config) { c.Guardrail.RulePack = "strict" }, findings: gap1389, want: "rejected"},
		{name: "strict rule pack for the connector", edit: func(c *config.Config) {
			c.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{"claudecode": {RulePack: "strict"}}
		}, findings: gap1389, want: "rejected"},
		{name: "strict preset", edit: func(c *config.Config) {
			c.Admission.Defaults.Actions.High, c.Admission.Defaults.Actions.Medium = quarantine, quarantine
			c.Admission.Plugin.Actions.High = quarantine
		}, findings: gap1389, want: "rejected"},
		{name: "upgraded strict preset", edit: func(c *config.Config) {
			c.Admission.Defaults.AllowListBypassScan = &bypass
			c.Admission.Skill.Actions.High, c.Admission.Skill.Actions.Medium, c.Admission.Skill.Actions.Low = quarantine, quarantine, warn
		}, findings: gap1389, want: "rejected"},
		{name: "Secure Client", edit: func(c *config.Config) {
			c.DeploymentMode, c.Enterprise.Profile = "managed_enterprise", "secure_client"
		}, findings: gap1389, want: "rejected"},
		{name: "skill with the same findings", target: config.AdmissionTypeSkill, findings: gap1389, want: "rejected"},
	}
	for _, tc := range cases {
		cfg := config.DefaultConfig()
		if tc.edit != nil {
			tc.edit(cfg)
		}
		target, total, max := tc.target, tc.total, tc.max
		if target == "" {
			target = config.AdmissionTypePlugin
		}
		if total == 0 {
			total = len(tc.findings)
		}
		if max == "" {
			max = "HIGH"
		}
		in := AdmissionInput{
			TargetType: target, TargetName: "r104fx-ok",
			ScanResult: &ScanResultInput{MaxSeverity: max, TotalFindings: total, ScannerName: "plugin-scanner", Findings: tc.findings},
			Admission:  AdmissionFor(CompileAdmission(cfg), target),
		}
		compiled := in.Admission
		WarnJudgeOnlyPluginHigh(cfg, "claudecode", &in)
		fallback := EvaluateAdmissionFallback(in)
		rego, err := eng.Evaluate(context.Background(), in)
		if err != nil {
			t.Fatal(err)
		}
		if fallback.Verdict != tc.want || rego.Verdict != tc.want {
			t.Errorf("%s: fallback=%s rego=%s, want %s", tc.name, fallback.Verdict, rego.Verdict, tc.want)
		}
		if in.ScanResult.MaxSeverity != max || compiled.Actions["HIGH"] != AdmissionFor(CompileAdmission(cfg), target).Actions["HIGH"] {
			t.Errorf("%s: the pre-step changed the findings or the shared compiled admission", tc.name)
		}
	}
}
