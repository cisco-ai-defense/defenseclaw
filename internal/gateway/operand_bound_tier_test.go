// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

// operandBoundReason is the audit reason of a call past the operand bound
// (actionfacts.MaxOperandsPerCall): the bound rule's items cap
// (rel-1-0-10:GAP-0313).
var operandBoundReason = bounded.Of(bounded.Items).Reason()

// operandBoundTruncated reports the evaluation-limit finding of a call past
// the operand bound.
func operandBoundTruncated(finding RuleFinding) bool {
	return finding.RuleID == evaluationLimitRuleID && finding.Evidence == operandBoundReason
}

// operandBoundTruncatedString is operandBoundTruncated for a finding string
// of a hook answer.
func operandBoundTruncatedString(finding string) bool {
	return strings.HasPrefix(finding, evaluationLimitRuleID+":") && strings.Contains(finding, operandBoundReason)
}

// operandBoundTierAction is the action of findings with the policy tier
// applied, as the hook routes decide them (guardrailActionForProfile over the
// shipped levels): a call past the operand bound alerts in the default tier
// and blocks in the strict tier.
func operandBoundTierAction(findings []RuleFinding, strict bool) string {
	return guardrailActionForProfile(findings, false, func() bool { return strict }, func(severity string) string {
		return guardrailContentAction(nil, "", severity, false)
	})
}
