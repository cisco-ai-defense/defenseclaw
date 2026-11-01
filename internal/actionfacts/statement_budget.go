// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

// ShellStatementsOverBudget reports whether a POSIX shell command has more
// statements than one action evaluates (maxStatementsAlone, 128), counted
// as SimpleCommands splits it: list members, pipeline stages and the
// commands of bodies. SimpleCommands reports such a command as a "limit"
// failure while the analysis keeps its text; a command whose analysis
// stopped earlier, at the node or input bound, is over the same budget, so
// the limit is the same at every size up to the hook payload cap (GAP-0146,
// GAP-0568). A command that does not parse is not counted here.
func ShellStatementsOverBudget(command string) bool {
	if command == "" {
		return false
	}
	statements, _, ok := sequenceStatementDetails(command, true, true)
	return ok && len(statements) > maxStatementsAlone
}

// PowerShellStatementsOverBudget reports whether a command has more
// statements than one action evaluates (maxStatementsAlone) as PowerShell
// splits it: list members (;, &&, ||, line ends) and pipeline stages, the
// separators windowsSimpleCommands splits on. It is the budget of a call
// that PowerShell may run but that no analysis read to its end, such as a
// Codex call on Windows past the 64 KiB input bound (rel-1-0-6:GAP-0318).
// The Windows lexer stops at its token bound, so a long command is lexed
// again from the last separator it reached; a separator is never inside a
// quoted word or a here-string, so each piece starts between statements.
func PowerShellStatementsOverBudget(command string) bool {
	statements := 1
	rest := []rune(command)
	for len(rest) > 0 {
		out := newParseOutput(DialectPowerShell, 1)
		lexemes, ok := windowsLex(string(rest), windowsPowerShell, &out)
		next := 0
		for _, lexeme := range lexemes {
			if lexeme.kind != windowsSeparatorLexeme && lexeme.kind != windowsPipeLexeme {
				continue
			}
			if statements++; statements > maxStatementsAlone {
				return true
			}
			next = lexeme.end
		}
		if ok || out.status != StatusLimitExceeded || next <= 0 || next > len(rest) {
			return false
		}
		rest = rest[next:]
	}
	return false
}
