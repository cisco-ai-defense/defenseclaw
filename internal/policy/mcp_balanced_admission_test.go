// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"context"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// A completed HIGH finding is still visible to admission and audit. The
// balanced action warns on MCP findings; an administrator can explicitly
// restore strict blocking through config.yaml.
func TestBalancedMCPFindingsWarnUnlessPolicyTightens(t *testing.T) {
	eng := repoEngine(t)
	check := func(name string, cfg *config.Config, severity, want string) {
		t.Helper()
		in := AdmissionInput{
			TargetType: config.AdmissionTypeMCP, TargetName: "context7",
			ScanResult: &ScanResultInput{MaxSeverity: severity, TotalFindings: 1, ScannerName: "mcp-scanner"},
			Admission:  AdmissionFor(CompileAdmission(cfg), config.AdmissionTypeMCP),
		}
		fallback := EvaluateAdmissionFallback(in)
		rego, err := eng.Evaluate(context.Background(), in)
		if err != nil {
			t.Fatal(err)
		}
		if fallback.Verdict != want || rego.Verdict != want {
			t.Fatalf("%s: fallback=%s rego=%s, want %s", name, fallback.Verdict, rego.Verdict, want)
		}
	}
	balanced := config.DefaultConfig()
	for _, severity := range []string{"HIGH", "MEDIUM", "LOW"} {
		check("balanced "+severity, balanced, severity, "warning")
	}
	check("critical", balanced, "CRITICAL", "rejected")
	strict := config.DefaultConfig()
	strict.Admission.MCP.Actions.High = &config.AdmissionAction{Shorthand: config.AdmissionActionQuarantine}
	check("strict high", strict, "HIGH", "rejected")
	// A config upgraded from the old strict preset can have only per-skill
	// actions: the old built-in MCP actions supplied its other severities.
	// Keep that selected strict behavior across the balanced default change.
	legacyStrict := config.DefaultConfig()
	bypass := false
	legacyStrict.Admission.Defaults.AllowListBypassScan = &bypass
	legacyStrict.Admission.Skill.Actions.High = &config.AdmissionAction{Shorthand: config.AdmissionActionQuarantine}
	legacyStrict.Admission.Skill.Actions.Medium = &config.AdmissionAction{Shorthand: config.AdmissionActionQuarantine}
	legacyStrict.Admission.Skill.Actions.Low = &config.AdmissionAction{Shorthand: config.AdmissionActionWarn}
	check("upgraded strict high", legacyStrict, "HIGH", "rejected")
	check("upgraded strict medium", legacyStrict, "MEDIUM", "rejected")
	legacyMCP := AdmissionFor(CompileAdmission(legacyStrict), config.AdmissionTypeMCP)
	if got := legacyMCP.Actions["LOW"]; got.Runtime != "block" || got.Install != "none" {
		t.Fatalf("upgraded strict low action %+v, want runtime disabled", got)
	}
	legacyStrict.Admission.MCP.Actions.High = &config.AdmissionAction{Shorthand: config.AdmissionActionWarn}
	check("upgraded strict explicit high warning", legacyStrict, "HIGH", "warning")
	// Disabling allow-list bypass alone does not select the old strict preset.
	balancedNoBypass := config.DefaultConfig()
	balancedNoBypass.Admission.Defaults.AllowListBypassScan = &bypass
	check("balanced without bypass high", balancedNoBypass, "HIGH", "warning")
	secure := config.DefaultConfig()
	secure.DeploymentMode = "managed_enterprise"
	secure.Enterprise.Profile = "secure_client"
	check("Secure Client high", secure, "HIGH", "rejected")
}
