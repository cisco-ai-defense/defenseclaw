// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"slices"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
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
// The other plain names are left out and not resolved further: the call is
// truncated at the operand bound (bound rule, internal/guardrail/bounded,
// cap items), so withBoundedTruncation adds the evaluation-limit finding with
// the reason "bounded_truncated cap=items", which the profile maps to an alert
// in the default and permissive packs and a block in the strict pack
// (rel-1-0-10:GAP-0313; the former ACTION-OPERAND-BOUND alert mapped to allow
// in the permissive pack).

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
	reduced, over := hookpaths.BoundCommandOperands(command, cwd, home)
	if over {
		reading = operandBoundReading(reading, reduced)
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
		findings = withBoundedTruncation(findings, bounded.Of(bounded.Items), request)
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

// mergeBoundedFindings is findings with every finding of more that does not
// repeat one of them (the same rule, severity and enforcement).
func mergeBoundedFindings(findings, more []RuleFinding) []RuleFinding {
	for _, finding := range more {
		if !slices.ContainsFunc(findings, func(f RuleFinding) bool {
			return f.RuleID == finding.RuleID && f.Severity == finding.Severity && f.enforcement == finding.enforcement
		}) {
			findings = append(findings, finding)
		}
	}
	return findings
}
