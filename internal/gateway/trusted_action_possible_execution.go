// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"slices"
	"strings"
)

// possibleExecutionRuleID names a command that may run, but only through a
// runtime choice the simple-command walk does not decide (a PowerShell body
// under a condition that is not a literal, GAP-0935; a function selected
// through an assigned variable, GAP-0934), and that matches a blocking rule
// when judged alone. It is MEDIUM: the default and permissive packs alert
// on it, the strict pack (block_at MEDIUM) blocks it. guardrail.block_at
// and the pack posture choose the tier.
const possibleExecutionRuleID = "ACTION-POSSIBLE-EXECUTION"

// possibleExecutionFindings turns the blocking findings of a possible child
// into one possibleExecutionRuleID finding that names their rules. Findings
// that do not block alone add nothing: the whole action already records them.
func possibleExecutionFindings(findings []RuleFinding, enforcementCapable bool) []RuleFinding {
	var matched []string
	for _, finding := range findings {
		if finding.contributesToEnforcement() && finding.proof.authorizes(finding.RuleID) &&
			!slices.Contains(matched, finding.RuleID) {
			matched = append(matched, finding.RuleID)
		}
	}
	if len(matched) == 0 {
		return nil
	}
	finding := RuleFinding{
		RuleID:      possibleExecutionRuleID,
		Title:       "A command that may run matches " + strings.Join(matched, ", "),
		Severity:    "MEDIUM",
		Confidence:  1,
		Tags:        []string{"possible-execution"},
		enforcement: findingEnforcementAllowed,
	}.withTrustedActionProof(newFindingProof(findingProofPossibleExecution, possibleExecutionRuleID, true))
	return applyTrustedActionProofBoundary([]RuleFinding{finding}, enforcementCapable)
}
