// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"strings"
	"unicode"
)

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

// ShellStatementTexts returns the statements of a POSIX command as the
// statement budget counts them (ShellStatementsOverBudget), in order; ok is
// false when the command does not parse.
func ShellStatementTexts(command string) ([]string, bool) {
	statements, _, ok := sequenceStatementDetails(command, true, true)
	if !ok {
		return nil, false
	}
	texts := make([]string, len(statements))
	for i, statement := range statements {
		texts[i] = statement.text
	}
	return texts, true
}

// PowerShellStatementsOverBudget reports whether a command has more
// statements than one action evaluates (maxStatementsAlone) as PowerShell
// splits it: list members (;, &&, ||, line ends) and pipeline stages, at
// every depth of a subexpression ($( ), @( ), ( )) and a script block
// ({ }). It is the budget of a call that PowerShell may run but that no
// analysis read to its end, such as a Codex call on Windows past the 64 KiB
// input bound (rel-1-0-6:GAP-0318).
//
// It reads the command with its own scanner, not the Windows lexer: the
// lexer stops at the first subexpression, array, hashtable, braced
// variable or here-string and leaves the rest unread, so a single
// $(Get-Date) in front hid every later statement from the count
// (rel-1-0-6:GAP-0331). Text in quotes, here-strings and comments is not
// counted, nor are the entries of a hashtable (@{ a = 1; b = 2 }); an
// opening bracket or brace starts a new statement count inside it, and a
// closing one continues the statement around it, so a block never counts
// more statements than it holds.
func PowerShellStatementsOverBudget(command string) bool {
	statements, _ := powerShellStatements(command, maxStatementsAlone+1)
	return statements > maxStatementsAlone
}

// PowerShellReadingStopsEarly reports a command with a construct, outside
// quotes, at which the Windows lexer stops reading and leaves the rest of
// the command unread: a subexpression $( ), an array @( ), a hashtable
// @{ }, a braced variable ${ }, a here-string, the stop-parsing token --%
// or an & call. The split of such a reading holds only the statements before it
// (rel-1-0-6:GAP-0331).
func PowerShellReadingStopsEarly(command string) bool {
	_, opaque := powerShellStatements(command, len(command)+1)
	return opaque
}

// powerShellStatements counts the statements of command, stopping at limit,
// and reports whether it met a construct that stops the Windows lexer.
func powerShellStatements(command string, limit int) (int, bool) {
	const (
		frameCode = iota
		frameHashtable
		frameDouble
		frameVariable
		// frameParen is a bare ( ): one expression or pipeline, so a line
		// end inside it continues the statement (a multi-line param( )).
		frameParen
	)
	runes := []rune(command)
	frames := []int{frameCode}
	statements := 0
	inStatement := false
	opaque := false
	// lastSignificant is the last non-blank character before i: a line end
	// right after a comma continues the statement (a multi-line array).
	lastSignificant := rune(0)
	boundary := func() {
		if inStatement {
			statements++
			inStatement = false
		}
	}
	// lineStart reports that i begins a line (for a here-string end).
	lineStart := func(i int) bool { return i == 0 || runes[i-1] == '\n' || runes[i-1] == '\r' }
	tokenStart := func(i int) bool {
		return i == 0 || unicode.IsSpace(runes[i-1]) || strings.ContainsRune(";|&(){}", runes[i-1])
	}
	for i := 0; i < len(runes) && statements < limit; i++ {
		r := runes[i]
		top := frames[len(frames)-1]
		switch top {
		case frameDouble:
			switch {
			case r == '`':
				i++
			case windowsPowerShellQuoteDelimiter(r) == '"':
				if i+1 < len(runes) && windowsPowerShellQuoteDelimiter(runes[i+1]) == '"' {
					i++ // a doubled quote is one quote character
				} else {
					frames = frames[:len(frames)-1]
				}
			case r == '$' && i+1 < len(runes) && runes[i+1] == '(':
				frames = append(frames, frameCode)
				i++
			}
			continue
		case frameVariable:
			if r == '`' {
				i++
			} else if r == '}' {
				frames = frames[:len(frames)-1]
			}
			continue
		}
		// Code, paren and hashtable frames.
		if i > 0 && !unicode.IsSpace(runes[i-1]) {
			lastSignificant = runes[i-1]
		}
		next := rune(0)
		if i+1 < len(runes) {
			next = runes[i+1]
		}
		switch {
		case r == '#' && tokenStart(i):
			for i+1 < len(runes) && runes[i+1] != '\n' && runes[i+1] != '\r' {
				i++
			}
		case r == '<' && next == '#':
			j := i + 2
			for j+1 < len(runes) && (runes[j] != '#' || runes[j+1] != '>') {
				j++
			}
			if j+1 >= len(runes) {
				return statements, opaque
			}
			i = j + 1
		case r == '-' && next == '-' && i+2 < len(runes) && runes[i+2] == '%' && tokenStart(i):
			// The stop-parsing token: the rest of the line is one argument.
			opaque, inStatement = true, true
			for i+1 < len(runes) && runes[i+1] != '\n' && runes[i+1] != '\r' {
				i++
			}
		case r == '`':
			// An escaped character, or a line continuation.
			inStatement = true
			i++
		case r == '@' && windowsPowerShellQuoteDelimiter(next) != 0 && powerShellHereStringOpens(runes, i+2):
			quote := windowsPowerShellQuoteDelimiter(next)
			inStatement = true
			j := i + 2
			for ; j+1 < len(runes); j++ {
				if lineStart(j) && windowsPowerShellQuoteDelimiter(runes[j]) == quote && runes[j+1] == '@' {
					break
				}
			}
			if j+1 >= len(runes) {
				return statements, opaque
			}
			opaque = true
			i = j + 1
		case windowsPowerShellQuoteDelimiter(r) == '\'':
			inStatement = true
			for i++; i < len(runes); i++ {
				if windowsPowerShellQuoteDelimiter(runes[i]) == '\'' {
					if i+1 < len(runes) && windowsPowerShellQuoteDelimiter(runes[i+1]) == '\'' {
						i++
						continue
					}
					break
				}
			}
		case windowsPowerShellQuoteDelimiter(r) == '"':
			inStatement = true
			frames = append(frames, frameDouble)
		case r == '$' && next == '{':
			inStatement, opaque = true, true
			frames = append(frames, frameVariable)
			i++
		case r == '@' && next == '{':
			inStatement, opaque = true, true
			frames = append(frames, frameHashtable)
			i++
		case (r == '$' || r == '@') && next == '(':
			frames = append(frames, frameCode)
			inStatement, opaque = false, true
			i++
		case r == '(':
			frames = append(frames, frameParen)
			inStatement = false
		case r == '{':
			frames = append(frames, frameCode)
			inStatement = false
		case r == ')' || r == '}':
			// The statement around the bracket goes on; the last statement
			// inside it is counted with it.
			if len(frames) > 1 {
				frames = frames[:len(frames)-1]
			}
			inStatement = true
		case top == frameHashtable && (r == ';' || r == '\n' || r == '\r'):
			// Entry separators of a hashtable, not statements.
		case (r == '\n' || r == '\r') && (top == frameParen || lastSignificant == ','):
			// A line end inside a bare ( ) or after a trailing comma
			// continues the statement.
		case r == ';' || r == '|' || r == '\n' || r == '\r':
			boundary()
		case r == '&' && next == '&':
			boundary()
			i++
		case r == '&' && (i == 0 || runes[i-1] != '>'):
			// After a statement, the PowerShell 7 background operator ends
			// it; at a statement start, the call operator. The Windows
			// lexer stops at a call whose target is not quoted.
			opaque = true
			if inStatement {
				boundary()
			} else {
				inStatement = true
			}
		case !unicode.IsSpace(r):
			inStatement = true
		}
	}
	if inStatement {
		statements++
	}
	return statements, opaque
}

// powerShellHereStringOpens reports that only blanks follow position i up to
// the end of its line: @' and @" open a here-string only at a line end.
func powerShellHereStringOpens(runes []rune, i int) bool {
	for ; i < len(runes); i++ {
		switch runes[i] {
		case '\n', '\r':
			return true
		case ' ', '\t':
		default:
			return false
		}
	}
	return false
}
