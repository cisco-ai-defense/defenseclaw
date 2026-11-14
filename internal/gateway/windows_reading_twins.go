// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"reflect"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
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
// unreadable statement, rel-1-0-10:GAP-0425). Either way a call gets one
// extra reading at most, and that reading makes none of its own.
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
	if !request.windowsDialectReadings || request.readingTwin || request.simpleCommandPass ||
		facts.Authoritative() || facts.Parse.Status == actionfacts.StatusLimitExceeded {
		return nil, bounded.CapSet{}
	}
	input := request.Input
	unplaced := facts.Parse.Dialect == actionfacts.DialectPowerShell && facts.Parse.Status == actionfacts.StatusAmbiguous &&
		input.DialectHint == ""
	if unplaced {
		input.DialectHint = actionfacts.DialectPowerShell
		facts = request.windowsPowerShellReading.factsFor(input)
	}
	var trunc bounded.Truncated
	readable, ok := actionfacts.PowerShellReadableStatementsTwin(input, facts, &trunc)
	if cut := trunc.Set(); cut.Any() {
		return nil, cut
	}
	if !ok {
		if !unplaced || facts.Parse.Status != actionfacts.StatusPartial || facts.Parse.Dialect != actionfacts.DialectPowerShell {
			return nil, bounded.CapSet{}
		}
		readable = input
	}
	twin := windowsReadingTwin(request)
	twin.Input = readable
	if readable.Command != "" {
		twin.LegacyText = readable.Command
	}
	return []trustedActionRequest{twin}, bounded.CapSet{}
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
