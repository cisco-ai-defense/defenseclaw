// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// windowsReadingTwinRequests are the other ways a Windows hook's shell call
// can read when the reading its dialect choice picked is not complete
// (rel-1-0-10:GAP-0366, GAP-0367). The hook has one hint per call, but the
// harness runs PowerShell or a POSIX shell (Git Bash), and a call that one
// reading cannot place may be exactly what the other reads. Each twin is the
// call judged as that other shell where the hook placed it in none, and, for
// a partial PowerShell reading, as its readable statements alone. The callers merge only what a twin proves
// (withTwinProvenBlocks), so no finding of the chosen reading is dropped and
// a twin only adds.
func windowsReadingTwinRequests(request trustedActionRequest, facts actionfacts.Facts) []trustedActionRequest {
	if !request.windowsDialectReadings || request.readingTwin || request.simpleCommandPass ||
		facts.Authoritative() || facts.Parse.Status == actionfacts.StatusLimitExceeded {
		return nil
	}
	var twins []trustedActionRequest
	chosen := facts.Parse.Dialect
	// The other shell is judged only where the hook placed the call in no
	// shell: a call it did place (the Claude Code PowerShell tool, a Bash call
	// that Git Bash reads alone, a Codex call whose PowerShell parse it took) is
	// the shell it was placed in, and reading it as another shell would add
	// findings the shell that runs it never has.
	if request.Input.DialectHint == "" {
		for _, other := range []actionfacts.Dialect{actionfacts.DialectPowerShell, actionfacts.DialectPOSIX} {
			if other == chosen {
				continue
			}
			twin := windowsReadingTwin(request)
			twin.Input.DialectHint = other
			twins = append(twins, twin)
		}
	}
	if readable, ok := actionfacts.PowerShellReadableStatementsTwin(request.Input, facts); ok {
		twin := windowsReadingTwin(request)
		twin.Input = readable
		twin.LegacyText = readable.Command
		twins = append(twins, twin)
	}
	return twins
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
