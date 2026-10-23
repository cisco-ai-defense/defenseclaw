// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// appendTrustedPrivateKeyReaderFinding carries a complete reader proof across
// a home-anchored shell expansion or an exact inline pathlib read. The normal
// partial parse is retained for all other policy checks.
func appendTrustedPrivateKeyReaderFinding(
	findings []RuleFinding,
	generation *compiledRulePackCategories,
	request trustedActionRequest,
	facts actionfacts.Facts,
) []RuleFinding {
	proved := facts.Authoritative() && facts.EnforcementEligible() &&
		trustedActionActiveSSHPrivateKeyContentRead(facts.EnforcementProjection())
	if !proved {
		if twin, ok := actionfacts.HomeResolvedTwin(request.Input); ok {
			projection := twin.EnforcementProjection()
			proved = projection.EnforcementEligible() &&
				trustedActionActiveSSHPrivateKeyContentRead(projection)
		}
	}
	if !proved {
		if path, ok := actionfacts.ExactPythonHomePathRead(facts); ok &&
			strings.HasPrefix(path, ".ssh/") && strings.Count(path, "/") == 1 &&
			matchesSSHPrivateKey(path) && request.Input.ActiveHome != "" {
			proved = true
		}
	}
	if !proved {
		return findings
	}
	_, rule, ok := trustedActionCatalogRule(generation, "PATH-SSH-KEY")
	if !ok {
		return findings
	}
	enforcement := findingEnforcementDetectionOnly
	if request.EnforcementCapable {
		enforcement = findingEnforcementAllowed
	}
	for index := range findings {
		if findings[index].RuleID == "PATH-SSH-KEY" ||
			findings[index].RuleID == "PATH-WIN-SSH-KEY" {
			findings[index].enforcement = enforcement
			return findings
		}
	}
	return append(findings, adjustConfidence(request.Input.Tool, RuleFinding{
		RuleID: rule.ID, Title: rule.Title, Severity: rule.Severity,
		Confidence: rule.Confidence, Evidence: trustedActionInputText(request.Input, ""),
		Tags: append([]string(nil), rule.Tags...), LineNumber: 1,
		enforcement: enforcement,
	}))
}
