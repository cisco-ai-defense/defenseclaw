// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
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
// The hook's selection (selectWindowsShellDialect) places such a call in no
// dialect, and its unhinted reading is then an ambiguous PowerShell reading.
// That reading is kept as the call's own: it enforces findings the hinted
// partial reading leaves detection-only, so the call is not moved to
// PowerShell. Its readable statements are taken from the PowerShell reading
// of the same call, made only when that reading is partial (not invalid, not
// a cap), so it is still one extra reading at most (rel-1-0-10:GAP-0405).
//
// The call is deliberately not also judged as the other shell. A Git Bash call
// read as PowerShell, or a PowerShell call read as POSIX, gains findings the
// shell that runs it never has: TestR105GAP2304WindowsGitBashHomeDrivePaths
// blocked its benign copy cases with that twin. The NetExec identity of
// GAP-0366 is one program name in every dialect instead (netExecProgramFamily).
func windowsReadingTwinRequests(request trustedActionRequest, facts actionfacts.Facts) []trustedActionRequest {
	if !request.windowsDialectReadings || request.readingTwin || request.simpleCommandPass ||
		facts.Authoritative() || facts.Parse.Status == actionfacts.StatusLimitExceeded {
		return nil
	}
	input := request.Input
	if facts.Parse.Dialect == actionfacts.DialectPowerShell && facts.Parse.Status == actionfacts.StatusAmbiguous &&
		input.DialectHint == "" {
		input.DialectHint = actionfacts.DialectPowerShell
		facts = actionfacts.Analyze(input)
	}
	readable, ok := actionfacts.PowerShellReadableStatementsTwin(input, facts)
	if !ok {
		return nil
	}
	twin := windowsReadingTwin(request)
	twin.Input = readable
	twin.LegacyText = readable.Command
	return []trustedActionRequest{twin}
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
