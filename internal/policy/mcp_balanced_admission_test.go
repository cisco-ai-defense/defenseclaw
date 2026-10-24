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
	secure := config.DefaultConfig()
	secure.DeploymentMode = "managed_enterprise"
	secure.Enterprise.Profile = "secure_client"
	check("Secure Client high", secure, "HIGH", "rejected")
}
