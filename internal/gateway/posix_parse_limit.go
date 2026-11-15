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

// A word past the bound that the local shell only passes on is not truncated:
// a big quoted script handed to a program that runs it elsewhere (dcx, ssh,
// docker exec) is DATA to the local shell, whose hook never sees what runs
// there. The call is judged as its twin, the same call with each such word
// shortened (actionfacts.SplitOverLimitWords), so every other statement is
// read in full, and the word itself leaves a detection-only record
// (posixDataWordTwinRequest, withPosixDataWordRecord). A word the local shell
// runs as code (the command name, a shell or interpreter operand, a wrapper's
// command, a redirect target, a here-document) stays truncated; the grammar
// position decides, no program is named for being data (rel-1-0-10:GAP-0382,
// second round).

// posixByteBoundCommand is the command text of a POSIX shell call the
// analysis stopped reading at a byte bound, "" for any other call.
func posixByteBoundCommand(request trustedActionRequest, facts actionfacts.Facts) string {
	input := request.Input
	if facts.Parse.Status != actionfacts.StatusLimitExceeded ||
		!slices.Contains(facts.Parse.Issues, actionfacts.IssueInputLimit) ||
		!trustedBashExecutionTool(input.Tool) {
		return ""
	}
	switch facts.Parse.Dialect {
	case "", actionfacts.DialectNone, actionfacts.DialectPOSIX:
	default:
		return ""
	}
	if input.DialectHint != "" && input.DialectHint != actionfacts.DialectPOSIX {
		return ""
	}
	command, known := trustedBashCommandInput(input)
	if !known || !actionfacts.ShellInputPastByteBound(command, len(input.Args)) {
		return ""
	}
	return command
}

// posixParseTruncation is the cap of the byte bound the POSIX analysis of a
// shell call hit, empty when it read the call to the end, stopped at another
// bound, the call is not a POSIX shell call, a call over the text bound only
// by the white space or comments that pad it, whose bounded twin
// (overLimitCommandBoundedTwinRequest) is read in full and judged as the
// unpadded command (GAP-0934), or a call whose every over-limit word is DATA
// (posixDataWordTwinRequest).
func posixParseTruncation(request trustedActionRequest, facts actionfacts.Facts) bounded.CapSet {
	if posixByteBoundCommand(request, facts) == "" {
		return bounded.CapSet{}
	}
	if _, twinRead := overLimitCommandBoundedTwinRequest(request, facts); twinRead {
		return bounded.CapSet{}
	}
	if _, dataOnly := posixDataWordTwinRequest(request, facts); dataOnly {
		return bounded.CapSet{}
	}
	return bounded.Of(bounded.Bytes)
}

// posixDataWordTwinRequest is the request for the twin of a call whose every
// over-limit word is DATA: the same call with each such word shortened, which
// the analysis reads to the end. false when a word is in code position, the
// text cannot be read with certainty, or the twin is still past a bound.
func posixDataWordTwinRequest(request trustedActionRequest, facts actionfacts.Facts) (trustedActionRequest, bool) {
	command := posixByteBoundCommand(request, facts)
	if command == "" || len(command) > actionfacts.MaxCommandTextBytes {
		return trustedActionRequest{}, false
	}
	split, ok := actionfacts.SplitOverLimitWords(command)
	if !ok || split.Code > 0 || split.Data == 0 ||
		actionfacts.ShellInputPastByteBound(split.Twin, len(request.Input.Args)) {
		return trustedActionRequest{}, false
	}
	twin := bashReadingRequest(request, command, split.Twin)
	if !actionfacts.OverLimitTwinWithinBounds(twin.Input, split.Twin) {
		return trustedActionRequest{}, false
	}
	return twin, true
}

// posixDataWordTitle is the reason of the record a data word leaves.
const posixDataWordTitle = "Shell word past the analysis bound is data to the local shell, not read (bounded_truncated cap=bytes, operand)"

// withPosixDataWordRecord adds to the findings of a call a detection-only
// record of the word the analysis did not read: the call keeps the verdict of
// its twin, and the record is no action raise. A limit finding the call
// already carries, or a record a twin left, is kept as it is. The record is
// marked (dataWordRecord) so no cap logic reads it as a cap the call hit
// (rel-1-0-10:GAP-0760).
func withPosixDataWordRecord(findings []RuleFinding) []RuleFinding {
	if boundedLimitIndex(findings) >= 0 || slices.ContainsFunc(findings, func(f RuleFinding) bool { return f.dataWordRecord }) {
		return findings
	}
	record := trustedActionLimitFindings(false)[0]
	record.Title = posixDataWordTitle
	record.Evidence = bounded.Of(bounded.Bytes).Reason() + "; operand"
	record.enforcement = findingEnforcementDetectionOnly
	record.dataWordRecord = true
	return append(slices.Clip(findings), record)
}
