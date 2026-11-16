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

// A call with more operands (and redirection targets) than
// actionfacts.MaxOperandsPerCall, counted over all its statements, keeps a
// hook call past its answer window on a Windows host, where every operand
// costs a few reads of the file system, though the gateway is up
// (rel-1-0-9:GAP-0943). Such a call is unresolved: the readers
// judge the first operands and every later word that could name a protected
// file by its text (hookpaths.BoundCommandOperands), exactly as for a call
// below the bound, so a protected file or link named directly, or through a
// value the gateway knows, is blocked in every profile, and so is a later
// plain name that one read finds to be a link or a second name of a keys file.
// The other plain names are left out and not resolved further. The policy
// tier of the request decides that: the strict tier (and managed strict) keeps the
// evaluation-limit block, and the default and permissive tiers allow the
// call with an alert that names the bound, as for an unread share body
// (shareBodyUnreadFindings).

// operandBoundRuleID is the alert the default and permissive tiers raise for
// a call over the operand bound. It is not the evaluation-limit rule, so a
// strict request that met the alert in a twin dispatch still adds the block.
const operandBoundRuleID = "ACTION-OPERAND-BOUND"

// operandBoundDispatch judges a shell call that a bound of the readers
// applies to; handled is false when none does, or the call is not a shell
// call. A call over the operand bound is judged by its bounded reading
// (hookpaths.BoundCommandOperands) and the tier adds its verdict (GAP-0943);
// a call below it by its full reading, as before. A statement of more argv
// words than the analysis reads has no path facts in either reading, so the
// statement-bounded reading (hookpaths.BoundStatementCommandOperands), whose
// statements keep their path facts, adds its findings (GAP-1069).
func operandBoundDispatch(parent context.Context, request trustedActionRequest) (findings []RuleFinding, handled bool) {
	if request.operandBounded {
		return nil, false
	}
	command, known := trustedBashCommandInput(request.Input)
	if !known {
		return nil, false
	}
	cwd, home := request.Input.CWD, request.Input.ActiveHome
	reading := request
	reading.operandBounded = true
	bounded, over := hookpaths.BoundCommandOperands(command, cwd, home)
	if over {
		reading = operandBoundReading(reading, bounded)
	}
	statements := hookpaths.BoundStatementCommandOperands(command, cwd, home)
	if !over && statements == command {
		return nil, false
	}
	findings = dispatchTrustedAction(parent, reading)
	if statements != command && statements != reading.Input.Command {
		twin := operandBoundReading(reading, statements)
		twin.statementBounded = true
		twin.record, twin.recordTelemetry = nil, nil
		findings = mergeBoundedFindings(findings, dispatchTrustedAction(parent, twin))
	}
	if over {
		findings = operandBoundFindings(parent, findings, request.EnforcementCapable)
	}
	return findings, true
}

// operandBoundReading is request judged as the shell command reduced.
func operandBoundReading(request trustedActionRequest, reduced string) trustedActionRequest {
	request.Input.Command, request.Input.Args = reduced, nil
	request.LegacyText = reduced
	request.conflictSource = nil
	return request
}

// mergeBoundedFindings is findings with every finding of bounded that does not
// repeat one of them (the same rule, severity and enforcement).
func mergeBoundedFindings(findings, bounded []RuleFinding) []RuleFinding {
	for _, finding := range bounded {
		if !slices.ContainsFunc(findings, func(f RuleFinding) bool {
			return f.RuleID == finding.RuleID && f.Severity == finding.Severity && f.enforcement == finding.enforcement
		}) {
			findings = append(findings, finding)
		}
	}
	return findings
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
		Title: fmt.Sprintf("Command has more than %d operands: the first %d and every later word that may name a protected file or is a link were judged, the other plain names were not resolved further",
			actionfacts.MaxOperandsPerCall, actionfacts.MaxOperandsPerCall),
		enforcement: findingEnforcementAlertOnly,
	})
}
