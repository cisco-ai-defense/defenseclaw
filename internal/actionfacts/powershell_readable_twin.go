// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

// PowerShellReadableStatementsTwin returns the input of a partial PowerShell
// action reduced to the top-level statements that each parse complete on their
// own, in their order (rel-1-0-10:GAP-0367). One statement the analysis cannot
// read makes the whole action partial, and a partial action proves none of the
// multi-statement findings its readable statements make together (a registry
// write followed by the program it hijacks, a download piped to its
// interpreter): the unreadable statement, placed anywhere, hid them. The twin
// is one more way the call can run, with the statements the reader cannot
// place left out; a block proven on it counts, as for the other twins.
//
// It is not offered when a left-out statement may change what the others do
// (a location, alias, environment or evaluation statement, an exit), when no
// statement is left out (PowerShellStatementsOnePerLine reads that call), or
// when none is readable. facts must be Analyze(input).
//
// Its statements and pipeline stages are counted against the reading's own
// command bound (maxCommands) through trunc, the call's bounded.Truncated (the one bound
// rule, internal/guardrail/bounded): past it no twin is offered and the cap is
// recorded there, so the caller floors the call at the unknown tier of its
// pack instead of reading the statements before the cap as a smaller call.
func PowerShellReadableStatementsTwin(input Input, facts Facts, trunc *bounded.Truncated) (Input, bool) {
	twin, every, ok := powerShellReadableStatements(input, facts, trunc)
	if !ok || every {
		return Input{}, false
	}
	return twin, true
}

// PowerShellStatementsOnePerLine returns the input of a partial PowerShell
// action whose top-level statements each parse complete on their own as the
// same statements one per line. The reader leaves a call joined by ";"
// partial for the separator alone, so the eventvwr handler chain on one line
// was proven by no reading while the same chain one statement per line
// blocked in strict (rel-1-0-10:GAP-1231): such a call is read as its
// statements, not judged once more. It is not offered when a statement does
// not parse complete alone, when it would be the call itself, or past the
// reading's command bound (the caller's own readings floor that call).
// facts must be Analyze(input).
func PowerShellStatementsOnePerLine(input Input, facts Facts) (Input, bool) {
	var trunc bounded.Truncated
	lines, every, ok := powerShellReadableStatements(input, facts, &trunc)
	if !ok || !every || trunc.Any() {
		return Input{}, false
	}
	return lines, true
}

// powerShellReadableStatements is the reading of PowerShellReadableStatementsTwin
// and PowerShellStatementsOnePerLine: the statements of input that parse
// complete alone, one per line, and whether every statement is one of them.
func powerShellReadableStatements(input Input, facts Facts, trunc *bounded.Truncated) (twin Input, every, ok bool) {
	defer func() {
		if recover() != nil {
			twin, every, ok = Input{}, false, false
		}
	}()
	if facts.Parse.Dialect != DialectPowerShell || facts.Parse.Status != StatusPartial ||
		len(input.Argv) != 0 {
		return Input{}, false, false
	}
	source, cwd := input.Command, input.CWD
	if source == "" {
		extracted := extractArgsForTool(input.Args, input.Tool)
		if len(extracted.issues) != 0 || extracted.status != StatusComplete || len(extracted.argv) != 0 {
			return Input{}, false, false
		}
		source = extracted.command
		if cwd == "" {
			cwd = extracted.cwd
		}
	}
	segmentBound := bounded.NewCounter(trunc, bounded.Items, maxCommands)
	segments, scanned := scanPowerShellSegments(source, 0, true, &segmentBound)
	if trunc.Any() || !scanned || len(segments) == 0 {
		return Input{}, false, false
	}
	var statements []string
	for _, segment := range segments {
		if segment.piped && len(statements) > 0 {
			statements[len(statements)-1] += " | " + segment.text
			continue
		}
		statements = append(statements, segment.text)
	}
	if len(statements) < 2 {
		return Input{}, false, false
	}
	var kept []string
	for _, statement := range statements {
		statementInput := input
		statementInput.Args, statementInput.Argv = nil, nil
		statementInput.Command = statement
		statementInput.DialectHint = DialectPowerShell
		parsed := Analyze(statementInput)
		if parsed.Parse.Status == StatusComplete && parsed.Authoritative() && parsed.EnforcementEligible() {
			kept = append(kept, statement)
			continue
		}
		if powerShellStatementMayChangeNext(statement) {
			return Input{}, false, false
		}
	}
	if len(kept) == 0 {
		return Input{}, false, false
	}
	twin = input
	twin.Args, twin.Argv = nil, nil
	twin.Command, twin.CWD = strings.Join(kept, "\n"), cwd
	every = len(kept) == len(statements)
	if every && twin.Command == source {
		// No statement is left out and the twin is the call itself.
		return Input{}, false, false
	}
	twin.DialectHint = DialectPowerShell
	return twin, every, true
}

// powerShellStatementMayChangeNext reports whether an unread statement may
// change what the statements after it run or where their paths point.
func powerShellStatementMayChangeNext(statement string) bool {
	fields := strings.Fields(strings.TrimLeft(strings.TrimSpace(statement), "&. "))
	if len(fields) == 0 {
		return false
	}
	first := strings.ToLower(fields[0])
	switch first {
	case "set-location", "sl", "cd", "chdir", "push-location", "pushd", "pop-location", "popd",
		"set-alias", "sal", "new-alias", "nal", "set-variable", "sv", "invoke-expression", "iex",
		"import-module", "ipmo", "exit", "function", "filter", "param":
		return true
	}
	return strings.HasPrefix(first, "$env:") || strings.HasPrefix(first, "$global:") ||
		strings.HasPrefix(first, "$script:")
}
