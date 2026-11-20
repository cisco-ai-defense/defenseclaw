// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"reflect"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
	"github.com/defenseclaw/defenseclaw/internal/psparse"
)

// windowsReadingTwinRequests are the other readings a Windows hook's shell
// call is judged with when the reading its dialect choice picked is partial
// (rel-1-0-10:GAP-0367). One statement the PowerShell reading cannot read
// makes the whole call partial, and a partial call proves none of the
// multi-statement findings its readable statements make together, so the
// statements that each parse complete are also judged alone
// (actionfacts.PowerShellReadableStatementsTwin). The callers merge only what a
// twin proves (withTwinProvenBlocks): no finding of the chosen reading is
// dropped and a twin only adds.
//
// The hook's selection (selectWindowsShellDialectReading) places such a call in no
// dialect, and its unhinted reading is then an ambiguous PowerShell reading.
// That reading is kept as the call's own: it enforces findings the hinted
// partial reading leaves detection-only, so the call is not moved to
// PowerShell. Its readable statements are taken from the PowerShell reading
// of the same call, the one the selection already made when the hook passes
// it (windowsPowerShellReading), made only when that reading is partial (not
// invalid, not a cap) (rel-1-0-10:GAP-0405). When no statement of such a call
// parses complete on its own there is no readable-statements reading, and the
// PowerShell reading of the whole call is the extra reading instead: it may
// prove what the ambiguous reading does not (an NTDS export next to an
// unreadable statement, rel-1-0-10:GAP-0425). An argument-command reading also
// judges inner argument calls before their parent (GAP-0988). No extra
// reading makes readings of its own.
//
// The statements of the readable-statements reading are bounded through the
// call's bounded.Truncated: the returned CapSet is the cap the reading hit,
// which the caller adds to the call's findings (withBoundedTruncation).
//
// The call is deliberately not also judged as the other shell. A Git Bash call
// read as PowerShell, or a PowerShell call read as POSIX, gains findings the
// shell that runs it never has: TestR105GAP2304WindowsGitBashHomeDrivePaths
// blocked its benign copy cases with that twin. The NetExec identity of
// GAP-0366 is one program name in every dialect instead (netExecProgramFamily).
func windowsReadingTwinRequests(request trustedActionRequest, facts actionfacts.Facts) ([]trustedActionRequest, bounded.CapSet) {
	if !request.windowsDialectReadings || request.readingTwin || request.simpleCommandPass {
		return nil, bounded.CapSet{}
	}
	input := request.Input
	placedNowhere := input.DialectHint == "" && request.windowsPowerShellReading != nil
	if placedNowhere {
		input.DialectHint = actionfacts.DialectPowerShell
		facts = request.windowsPowerShellReading.factsFor(input)
	}
	if facts.Authoritative() || facts.Parse.Status == actionfacts.StatusLimitExceeded {
		return nil, bounded.CapSet{}
	}
	unplaced := facts.Parse.Dialect == actionfacts.DialectPowerShell && facts.Parse.Status == actionfacts.StatusAmbiguous &&
		(input.DialectHint == "" || request.windowsPowerShellReading != nil)
	if unplaced {
		input.DialectHint = actionfacts.DialectPowerShell
		facts = request.windowsPowerShellReading.factsFor(input)
	}
	var argumentTwins []trustedActionRequest
	if facts.Parse.Dialect == actionfacts.DialectPowerShell && facts.Parse.Status == actionfacts.StatusPartial {
		command, known := trustedBashCommandInput(input)
		if known {
			text, changed, cut := psparse.ArgumentCommandReading(command)
			if changed {
				twin := windowsReadingTwin(request)
				twin.Input = input
				twin.Input.Args, twin.Input.Argv = nil, nil
				twin.Input.Command, twin.LegacyText = text, text
				twin.Input.DialectHint = actionfacts.DialectPowerShell
				argumentTwins = append(argumentTwins, twin)
			}
			if cut.Any() {
				return argumentTwins, cut
			}
		}
	}
	var trunc bounded.Truncated
	readable, ok := actionfacts.PowerShellReadableStatementsTwin(input, facts, &trunc)
	if cut := trunc.Set(); cut.Any() {
		return argumentTwins, cut
	}
	if !ok {
		// A folder move the selection's reading cannot follow (the POSIX
		// reading of Set-Location, or of cd C:\x, names no folder) keeps
		// the readable statements out (a left-out move changes where the
		// others write), so a relative write after it was read only in the
		// hook's folder, never where the move, or a move that failed, left
		// the shell: the PowerShell reading of the whole call, which reads
		// it in each of those folders, is the extra reading
		// (rel-1-0-10:GAP-1150).
		moves := placedNowhere && facts.MovesWindowsFolder()
		if !unplaced && !moves || facts.Parse.Status != actionfacts.StatusPartial || facts.Parse.Dialect != actionfacts.DialectPowerShell {
			return argumentTwins, bounded.CapSet{}
		}
		readable = input
	}
	twin := windowsReadingTwin(request)
	twin.Input = readable
	if readable.Command != "" {
		twin.LegacyText = readable.Command
	}
	return append([]trustedActionRequest{twin}, argumentTwins...), bounded.CapSet{}
}

// windowsHintedReading is the PowerShell reading selectWindowsShellDialectReading
// made of a call it placed in no dialect, kept so the readings of the same
// call do not parse it again.
type windowsHintedReading struct {
	input actionfacts.Input
	facts actionfacts.Facts
}

// factsFor is the reading's facts when it was made of input, else
// Analyze(input).
func (reading *windowsHintedReading) factsFor(input actionfacts.Input) actionfacts.Facts {
	if reading != nil && reflect.DeepEqual(reading.input, input) {
		return reading.facts
	}
	return actionfacts.Analyze(input)
}

// windowsReadingTwin is a copy of request that judges one more reading: it
// records nothing (the call's own judgment is the recorded one) and makes no
// further readings.
func windowsReadingTwin(request trustedActionRequest) trustedActionRequest {
	twin := request
	twin.readingTwin = true
	twin.windowsDialectReadings = false
	twin.record = nil
	twin.recordTelemetry = nil
	return twin
}

// withUnreadPowerShellFloor gives the unknown tier to a PowerShell call whose
// reading skipped part of its text without reading it
// (actionfacts.ParseResult.Unread, GAP-0988): no reader saw what that text
// runs. A partial reading alone is not enough: almost every ordinary
// PowerShell call reads as partial because a command's operand grammar is
// not modeled, and those calls were read (GAP-1015). The finding is the
// shared unknown-tier one, which the profile maps by pack: an alert in
// default, permissive and the managed default pack, a block in strict and
// managed-strict (GAP-1016). Proven findings keep their own verdict.
func withUnreadPowerShellFloor(findings []RuleFinding, request trustedActionRequest, facts actionfacts.Facts) []RuleFinding {
	if !request.windowsDialectReadings || request.readingTwin || request.simpleCommandPass {
		return findings
	}
	input := request.Input
	if input.DialectHint == "" && (request.windowsPowerShellReading != nil ||
		facts.Parse.Dialect == actionfacts.DialectPowerShell && facts.Parse.Status == actionfacts.StatusAmbiguous) {
		input.DialectHint = actionfacts.DialectPowerShell
		facts = request.windowsPowerShellReading.factsFor(input)
	}
	if facts.Parse.Dialect != actionfacts.DialectPowerShell || facts.Parse.Status != actionfacts.StatusPartial ||
		!facts.Parse.Unread {
		return findings
	}
	return withUnknownFinding(findings, unknownReasonFinding("PowerShell call is only partly read",
		"powershell_unread", request.EnforcementCapable))
}
