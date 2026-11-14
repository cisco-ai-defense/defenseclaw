// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"slices"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

// A shell call whose POSIX analysis stopped at a byte bound (limit_exceeded,
// input_limit: a word past the string bound of 4 KiB, the command text past
// 64 KiB, the arguments past 256 KiB) has commands the analysis never read. It
// is truncated in the sense of the bound rule (internal/guardrail/bounded):
// judged at the unknown tier of the pack (an alert in the default and
// permissive packs, a managed install's included, a block in the strict
// pack), never below what the text read before the bound proves, which keeps
// deciding on its own. Before this, one word past the bound ended the
// analysis with no command and the readers had nothing to judge: the call was
// allowed with no finding in every pack (rel-1-0-10:GAP-0382).
//
// Not here: a count bound (a statement of more argv words than the analysis
// keeps) belongs to the operand bound (operandBoundDispatch); the node and
// depth bounds of the analysis lie inside the reading budget, whose own caps
// the property test of the bound rule pins (parse_budget_lanes_test.go); and
// a Windows host call (a PowerShell or cmd tool or dialect) keeps its own rule
// (rel-1-0-10:GAP-0345, GAP-0318: one long ordinary PowerShell statement is
// not limited).

// posixParseTruncation is the cap of the byte bound the POSIX analysis of a
// shell call hit, empty when it read the call to the end, stopped at another
// bound, the call is not a POSIX shell call, or a call over the text bound only
// by the white space or comments that pad it, whose bounded twin
// (overLimitCommandBoundedTwinRequest) is read in full and judged as the
// unpadded command (GAP-0934).
func posixParseTruncation(request trustedActionRequest, facts actionfacts.Facts) bounded.CapSet {
	input := request.Input
	if facts.Parse.Status != actionfacts.StatusLimitExceeded ||
		!slices.Contains(facts.Parse.Issues, actionfacts.IssueInputLimit) ||
		!trustedBashExecutionTool(input.Tool) {
		return bounded.CapSet{}
	}
	switch facts.Parse.Dialect {
	case "", actionfacts.DialectNone, actionfacts.DialectPOSIX:
	default:
		return bounded.CapSet{}
	}
	if input.DialectHint != "" && input.DialectHint != actionfacts.DialectPOSIX {
		return bounded.CapSet{}
	}
	command, known := trustedBashCommandInput(input)
	if !known || !actionfacts.ShellInputPastByteBound(command, len(input.Args)) {
		return bounded.CapSet{}
	}
	if _, twinRead := overLimitCommandBoundedTwinRequest(request, facts); twinRead {
		return bounded.CapSet{}
	}
	return bounded.Of(bounded.Bytes)
}
