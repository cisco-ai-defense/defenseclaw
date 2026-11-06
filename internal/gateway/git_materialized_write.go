// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

const gitMaterializedWriteRuleID = "persistence.ssh_authorized_keys_possible"

// withGitMaterializedWriteFinding keeps the unmaterialized target distinct
// from a named protected target. A HIGH finding warns in balanced profiles
// and blocks in strict profiles; a named target keeps its CRITICAL finding.
func withGitMaterializedWriteFinding(findings []RuleFinding, request trustedActionRequest, possible bool) []RuleFinding {
	if !possible {
		return findings
	}
	for _, finding := range findings {
		if finding.RuleID == "persistence.ssh_authorized_keys_command" && finding.contributesToEnforcement() {
			return findings
		}
	}
	finding := RuleFinding{
		RuleID:   gitMaterializedWriteRuleID,
		Title:    "Project write may reach a protected file after a repository update",
		Severity: "HIGH", Confidence: 0.85,
		Tags:       []string{"persistence", "source-control", "possible-target"},
		LineNumber: 1,
	}.withTrustedActionProof(newExactFallbackFindingProof(
		gitMaterializedWriteRuleID, true, request.EnforcementCapable, true, true,
	))
	finding = applyTrustedActionProofBoundary([]RuleFinding{finding}, request.EnforcementCapable)[0]
	return append(findings, finding)
}
