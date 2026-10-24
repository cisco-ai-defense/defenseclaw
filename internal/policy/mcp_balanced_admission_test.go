// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"context"
	"os"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"gopkg.in/yaml.v3"
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

func TestActivatedPre104DefaultKeepsBalancedMCPAdmission(t *testing.T) {
	// This is the default.yaml shipped in 1.0.3. policy activate stored its
	// skill_actions as defaults and its MCP overrides as per-type actions.
	raw, err := os.ReadFile("../../testdata/legacy_default_1_0_3.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var preset struct {
		Admission struct {
			ScanOnInstall       *bool `yaml:"scan_on_install"`
			AllowListBypassScan *bool `yaml:"allow_list_bypass_scan"`
		} `yaml:"admission"`
		SkillActions     map[string]config.SeverityAction            `yaml:"skill_actions"`
		ScannerOverrides map[string]map[string]config.SeverityAction `yaml:"scanner_overrides"`
	}
	if err := yaml.Unmarshal(raw, &preset); err != nil {
		t.Fatal(err)
	}
	actionMap := func(src map[string]config.SeverityAction) config.AdmissionActionMap {
		var out config.AdmissionActionMap
		for severity, triple := range src {
			// The policy YAML predates config.yaml's runtime enable/disable
			// spelling; policy activate normalizes block/allow on write.
			switch triple.Runtime {
			case "block":
				triple.Runtime = config.RuntimeDisable
			case "allow":
				triple.Runtime = config.RuntimeEnable
			}
			action := &config.AdmissionAction{Triple: triple}
			switch severity {
			case "critical", "CRITICAL":
				out.Critical = action
			case "high", "HIGH":
				out.High = action
			case "medium", "MEDIUM":
				out.Medium = action
			case "low", "LOW":
				out.Low = action
			case "info", "INFO":
				out.Info = action
			}
		}
		return out
	}
	cfg := config.DefaultConfig()
	cfg.Admission.Defaults.ScanOnInstall = preset.Admission.ScanOnInstall
	cfg.Admission.Defaults.AllowListBypassScan = preset.Admission.AllowListBypassScan
	cfg.Admission.Defaults.Actions = actionMap(preset.SkillActions)
	cfg.Admission.Skill.Actions = actionMap(preset.SkillActions)
	cfg.Admission.MCP.Actions = actionMap(preset.ScannerOverrides["mcp"])
	eng := repoEngine(t)
	for _, severity := range []string{"HIGH", "MEDIUM", "LOW", "CRITICAL"} {
		in := AdmissionInput{
			TargetType: config.AdmissionTypeMCP, TargetName: "context7",
			ScanResult: &ScanResultInput{MaxSeverity: severity, TotalFindings: 1, ScannerName: "mcp-scanner"},
			Admission:  AdmissionFor(CompileAdmission(cfg), config.AdmissionTypeMCP),
		}
		want := "warning"
		if severity == "CRITICAL" {
			want = "rejected"
		}
		fallback := EvaluateAdmissionFallback(in)
		rego, err := eng.Evaluate(context.Background(), in)
		if err != nil {
			t.Fatal(err)
		}
		if fallback.Verdict != want || rego.Verdict != want {
			t.Errorf("%s: fallback=%s rego=%s, want %s", severity, fallback.Verdict, rego.Verdict, want)
		}
	}
	// An admin's explicit HIGH action still wins over the compatibility shape.
	cfg.Admission.MCP.Actions.High = &config.AdmissionAction{Shorthand: config.AdmissionActionQuarantine}
	if got := AdmissionFor(CompileAdmission(cfg), config.AdmissionTypeMCP).Actions["HIGH"]; got != actionQuarantine {
		t.Errorf("explicit HIGH action = %+v, want quarantine", got)
	}
}
