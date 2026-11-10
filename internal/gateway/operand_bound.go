// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"slices"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// A statement with more operands than actionfacts.MaxOperandsPerStatement
// keeps a hook call past its answer window on a Windows host, where every
// operand costs a few reads of the file system, though the gateway is up
// (rel-1-0-9:GAP-0943, GAP-0963). Such a call is unresolved: the readers
// judge the first operands and the later ones that could name a protected
// file by their form (hookpaths.BoundCommandOperands), exactly as for a
// call below the bound, so a protected file or link named directly, or
// through a value the gateway knows, is blocked in every profile. The plain
// names left out are not asked whether they are links. The policy tier of
// the request decides that: the strict tier (and managed strict) keeps the
// evaluation-limit block, and the default and permissive tiers allow the
// call with an alert that names the bound, as for an unread share body
// (shareBodyUnreadFindings).

// operandBoundRuleID is the alert the default and permissive tiers raise for
// a call over the operand bound. It is not the evaluation-limit rule, so a
// strict request that met the alert in a twin dispatch still adds the block.
const operandBoundRuleID = "ACTION-OPERAND-BOUND"

// operandBoundTwinRequest is the request for the reading of a shell call
// that has a statement over the operand bound (hookpaths.BoundCommandOperands);
// false when the call is not a shell call or is within the bound.
func operandBoundTwinRequest(request trustedActionRequest) (trustedActionRequest, bool) {
	if request.operandBounded {
		return trustedActionRequest{}, false
	}
	command, known := trustedBashCommandInput(request.Input)
	if !known {
		return trustedActionRequest{}, false
	}
	reduced, over := hookpaths.BoundCommandOperands(command)
	if !over {
		return trustedActionRequest{}, false
	}
	twin := request
	twin.operandBounded = true
	twin.Input.Command, twin.Input.Args = reduced, nil
	twin.LegacyText = reduced
	twin.conflictSource = nil
	return twin, true
}

// operandBoundFindings is the verdict of a call over the operand bound on top
// of the findings of its bounded reading: the evaluation-limit block in the
// strict tier, an alert that never blocks in the others.
func operandBoundFindings(ctx context.Context, findings []RuleFinding, enforcementCapable bool) []RuleFinding {
	has := func(ruleID string) bool {
		return slices.ContainsFunc(findings, func(f RuleFinding) bool { return f.RuleID == ruleID })
	}
	if shareBodyStrictFrom(ctx) {
		if has("ACTION-COMPOUND-LIMIT") {
			return findings
		}
		return append(findings, trustedActionLimitFindings(enforcementCapable)...)
	}
	if has("ACTION-COMPOUND-LIMIT") || has(operandBoundRuleID) {
		return findings
	}
	return append(findings, RuleFinding{
		RuleID: operandBoundRuleID, Severity: "MEDIUM", Confidence: 1,
		Title: fmt.Sprintf("Command has more than %d operands in one statement: the first %d and the operands that may name a protected file were judged, the other plain names were not checked for links",
			actionfacts.MaxOperandsPerStatement, actionfacts.MaxOperandsPerStatement),
		enforcement: findingEnforcementAlertOnly,
	})
}
