// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "strings"

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
// statement is left out, or when none is readable. facts must be Analyze(input).
func PowerShellReadableStatementsTwin(input Input, facts Facts) (twin Input, ok bool) {
	defer func() {
		if recover() != nil {
			twin, ok = Input{}, false
		}
	}()
	if facts.Parse.Dialect != DialectPowerShell || facts.Parse.Status != StatusPartial ||
		len(input.Argv) != 0 {
		return Input{}, false
	}
	source := input.Command
	if source == "" {
		extracted := extractArgsForTool(input.Args, input.Tool)
		if len(extracted.issues) != 0 || extracted.status != StatusComplete || len(extracted.argv) != 0 {
			return Input{}, false
		}
		source = extracted.command
	}
	segments, scanned := scanPowerShellSegments(source, 0, true)
	if !scanned || len(segments) == 0 {
		return Input{}, false
	}
	var statements []string
	for _, segment := range segments {
		if segment.piped && len(statements) > 0 {
			statements[len(statements)-1] += " | " + segment.text
			continue
		}
		statements = append(statements, segment.text)
	}
	if len(statements) < 2 || len(statements) > maxCommands {
		return Input{}, false
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
			return Input{}, false
		}
	}
	if len(kept) == 0 || len(kept) == len(statements) {
		return Input{}, false
	}
	twin = input
	twin.Args, twin.Argv = nil, nil
	twin.Command = strings.Join(kept, "\n")
	twin.DialectHint = DialectPowerShell
	return twin, true
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
