// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "strings"

const (
	// maxCappedRuns bounds the readings PowerShellCappedRuns returns for one
	// call, and maxCappedRunAnalyses the analyses it makes to find them.
	maxCappedRuns        = 8
	maxCappedRunAnalyses = 16
)

// PowerShellCappedRuns returns the readings of a PowerShell call whose
// analysis stopped at its command cap (StatusLimitExceeded) under the
// statement budget (rel-1-0-10:GAP-0589).
//
// The reading of such a call is truncated: the caller floors it at the unknown
// tier of its pack (the one bound rule). A statement the capped reading proves
// nothing for is still a command the shell runs, though: one statement of
// `$o = & git rev-parse HEAD` is two commands, so about 64 statements fill the
// cap, and a registry write placed before or after 100 such lines was found
// but left detection-only in every pack. So the top-level statements of the
// call (powerShellTopLevelStatements, the statement budget's own scanner,
// which reads past the constructs the Windows lexer stops at) that each read
// complete on their own are kept in their order, as
// PowerShellReadableStatementsTwin keeps them, and cut into consecutive runs
// that each read under the cap: the whole kept list when it fits, else its
// halves, down to one statement, within maxCappedRunAnalyses analyses and
// maxCappedRuns runs. A block proven on a run counts for the call, as for the
// other twins (withTwinProvenBlocks in the gateway). A statement left out (one
// that does not read complete alone, or a run past the bounds) is judged by
// the floor.
//
// No run is returned when a left-out statement may change what the statements
// after it run or where their paths point (powerShellStatementMayChangeNext),
// when the call is over the statement budget (the caller refuses it whole), or
// when the statements cannot be split. facts must be Analyze(input).
func PowerShellCappedRuns(input Input, facts Facts) (runs []Input) {
	defer func() {
		if recover() != nil {
			runs = nil
		}
	}()
	if facts.Parse.Dialect != DialectPowerShell || facts.Parse.Status != StatusLimitExceeded ||
		len(input.Argv) != 0 {
		return nil
	}
	source := input.Command
	if source == "" {
		extracted := extractArgsForTool(input.Args, input.Tool)
		if len(extracted.issues) != 0 || extracted.status != StatusComplete || len(extracted.argv) != 0 {
			return nil
		}
		source = extracted.command
	}
	if source == "" {
		return nil
	}
	statements, ok := powerShellTopLevelStatements(source, maxStatementsAlone)
	if !ok || len(statements) < 2 {
		return nil
	}
	// The statements that each read complete on their own, in their order
	// (as PowerShellReadableStatementsTwin keeps them): an unreadable
	// statement is left out, and the floor judges it.
	var kept []string
	for _, statement := range statements {
		one := input
		one.Args, one.Argv = nil, nil
		one.Command = statement
		one.DialectHint = DialectPowerShell
		parsed := Analyze(one)
		if parsed.Parse.Status == StatusComplete && parsed.Authoritative() && parsed.EnforcementEligible() {
			kept = append(kept, statement)
			continue
		}
		if powerShellStatementMayChangeNext(statement) {
			return nil
		}
	}
	analyses := 0
	var cut func([]string)
	cut = func(part []string) {
		if len(part) == 0 || len(runs) >= maxCappedRuns || analyses >= maxCappedRunAnalyses {
			return
		}
		run := input
		run.Args, run.Argv = nil, nil
		run.Command = strings.Join(part, "\n")
		run.DialectHint = DialectPowerShell
		analyses++
		if Analyze(run).Parse.Status != StatusLimitExceeded {
			runs = append(runs, run)
			return
		}
		if len(part) == 1 {
			return
		}
		half := len(part) / 2
		cut(part[:half])
		cut(part[half:])
	}
	cut(kept)
	return runs
}
