// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"strings"
	"unicode"
)

// windowsPowerShellOpaqueEnd finds the end of one balanced value without
// interpreting its contents as commands. A failed match leaves the Windows
// reading at the opener; guessing an end could turn data into a command.
func windowsPowerShellOpaqueEnd(runes []rune, start int) (int, bool) {
	if start+1 >= len(runes) {
		return 0, false
	}
	if runes[start] == '@' && windowsPowerShellQuoteDelimiter(runes[start+1]) != 0 {
		if !powerShellHereStringOpens(runes, start+2) {
			return 0, false
		}
		return windowsPowerShellHereStringEnd(runes, start)
	}
	var close rune
	switch runes[start+1] {
	case '(':
		close = ')'
	case '{':
		close = '}'
	default:
		return 0, false
	}
	if runes[start] == '$' && close == '}' {
		close = 'v' // braced variable: its contents are a name, not code
	}
	frames := []rune{close}
	argumentMode := []bool{false}
	push := func(close rune) {
		frames = append(frames, close)
		argumentMode = append(argumentMode, false)
	}
	pop := func() {
		frames = frames[:len(frames)-1]
		argumentMode = argumentMode[:len(argumentMode)-1]
	}
	for i := start + 2; i < len(runes); i++ {
		r := runes[i]
		top := frames[len(frames)-1]
		if top == 'v' {
			if r == '`' {
				i++
			} else if r == '}' {
				pop()
			}
		} else if top == '\'' || top == '"' {
			switch {
			case top == '"' && r == '`':
				i++
			case top == '"' && r == '$' && i+1 < len(runes) && runes[i+1] == '(':
				push(')')
				i++
			case windowsPowerShellQuoteDelimiter(r) == top:
				if i+1 < len(runes) && windowsPowerShellQuoteDelimiter(runes[i+1]) == top {
					i++
				} else {
					pop()
				}
			}
		} else {
			if !argumentMode[len(argumentMode)-1] && windowsPowerShellCommandWordBeforeBlank(runes, i) {
				argumentMode[len(argumentMode)-1] = true
			}
			if strings.ContainsRune(";|\r\n", r) || r == '&' && (i == 0 || runes[i-1] != '>') {
				argumentMode[len(argumentMode)-1] = false
			}
			next := rune(0)
			if i+1 < len(runes) {
				next = runes[i+1]
			}
			switch {
			case r == '`':
				i++
			case r == '<' && next == '#' && windowsPowerShellCommentStarts(runes, i, !argumentMode[len(argumentMode)-1]):
				end, ok := windowsPowerShellBlockCommentEnd(runes, i)
				if !ok {
					return 0, false
				}
				i = end
			case r == '#' && windowsPowerShellCommentStarts(runes, i, !argumentMode[len(argumentMode)-1]):
				for i+1 < len(runes) && runes[i+1] != '\n' && runes[i+1] != '\r' {
					i++
				}
			case r == '-' && next == '-' && i+2 < len(runes) && runes[i+2] == '%' &&
				(i+3 == len(runes) || unicode.IsSpace(runes[i+3])) &&
				windowsPowerShellTokenStart(runes, i):
				i = windowsPowerShellStopParsingEnd(runes, i+3) - 1
			case r == '@' && windowsPowerShellQuoteDelimiter(next) != 0:
				if !powerShellHereStringOpens(runes, i+2) {
					return 0, false
				}
				end, ok := windowsPowerShellHereStringEnd(runes, i)
				if !ok {
					return 0, false
				}
				i = end
			case r == '$' && next == '{':
				push('v')
				i++
			case windowsPowerShellQuoteDelimiter(r) != 0:
				// Adjacent delimiters of the same family in an active string
				// are consumed by the quote frame above. Reaching the second
				// one as code means the value cannot be read reliably.
				if i > 0 && windowsPowerShellQuoteDelimiter(runes[i-1]) == windowsPowerShellQuoteDelimiter(r) {
					return 0, false
				}
				push(windowsPowerShellQuoteDelimiter(r))
			case r == '(':
				push(')')
			case r == '{':
				push('}')
			case r == ')' || r == '}':
				if r != top {
					return 0, false
				}
				pop()
			}
		}
		if i >= len(runes) {
			return 0, false
		}
		if len(frames) == 0 {
			return i, true
		}
	}
	return 0, false
}

func windowsPowerShellHereStringEnd(runes []rune, start int) (int, bool) {
	quote := windowsPowerShellQuoteDelimiter(runes[start+1])
	for i := start + 2; i+1 < len(runes); i++ {
		if (runes[i-1] == '\n' || runes[i-1] == '\r') &&
			windowsPowerShellQuoteDelimiter(runes[i]) == quote && runes[i+1] == '@' {
			return i + 1, true
		}
	}
	return 0, false
}

func windowsPowerShellBlockCommentEnd(runes []rune, start int) (int, bool) {
	for i := start + 2; i+1 < len(runes); i++ {
		if runes[i] == '#' && runes[i+1] == '>' {
			return i + 1, true
		}
	}
	return 0, false
}

// A comment begins at a token boundary. A closing quote ends an argument
// token only when that token was quoted from its start. Expression values
// also accept a closing bracket as a boundary.
func windowsPowerShellCommentStarts(runes []rune, i int, expressionMode bool) bool {
	if i == 0 {
		return true
	}
	previous := runes[i-1]
	if unicode.IsSpace(previous) || strings.ContainsRune(";|&(){},", previous) {
		return true
	}
	if previous == '=' {
		// An assignment operator ends a token, but '=' in an argument
		// such as --format=#%h does not. The target before an assignment
		// is a variable expression at the start of this statement. A
		// variable after the call operator is an argument, not a target.
		start := i - 2
		for start >= 0 && !strings.ContainsRune(";|&(){}\r\n", runes[start]) {
			start--
		}
		if start >= 0 && runes[start] == '&' {
			return false
		}
		target := strings.TrimSpace(string(runes[start+1 : i-1]))
		if !strings.ContainsAny(target, " \t") &&
			(strings.HasPrefix(target, "$") || strings.HasPrefix(target, "[") && strings.Contains(target, "$")) {
			return true
		}
	}
	if expressionMode && strings.ContainsRune("]'\"", previous) {
		return true
	}
	return !expressionMode &&
		(runes[i] == '#' || runes[i] == '<' && i+1 < len(runes) && runes[i+1] == '#') &&
		windowsPowerShellQuotedTokenBoundary(runes, i)
}

// Match the lexer's quotedTokenBoundary rule for a quoted-only word. Walk
// back through doubled or escaped quote characters to find its opener.
func windowsPowerShellQuotedTokenBoundary(runes []rune, i int) bool {
	quote := windowsPowerShellQuoteDelimiter(runes[i-1])
	if quote == 0 {
		return false
	}
	for j := i - 2; j >= 0; j-- {
		if windowsPowerShellQuoteDelimiter(runes[j]) != quote {
			continue
		}
		if quote == '"' {
			backticks := 0
			for k := j - 1; k >= 0 && runes[k] == '`'; k-- {
				backticks++
			}
			if backticks%2 != 0 {
				continue
			}
		}
		if j > 0 && windowsPowerShellQuoteDelimiter(runes[j-1]) == quote {
			j--
			continue
		}
		return j == 0 || unicode.IsSpace(runes[j-1]) || strings.ContainsRune(";|&(){},", runes[j-1])
	}
	return false
}

// A bare command name followed by a blank switches a value expression to
// argument mode. A hashtable key followed by '=' remains an expression.
func windowsPowerShellCommandWordBeforeBlank(runes []rune, i int) bool {
	if i == 0 || !unicode.IsSpace(runes[i]) || unicode.IsSpace(runes[i-1]) {
		return false
	}
	start := i - 1
	for start >= 0 && !unicode.IsSpace(runes[start]) && !strings.ContainsRune(";|&(){}=,", runes[start]) {
		start--
	}
	if start+1 == i || !unicode.IsLetter(runes[start+1]) {
		return false
	}
	next := i + 1
	for next < len(runes) && (runes[next] == ' ' || runes[next] == '\t') {
		next++
	}
	return next >= len(runes) || runes[next] != '='
}

// Keep a dynamic call opaque, but return to the lexer at its next top-level
// separator. The following command can then be read on its own.
func windowsPowerShellDynamicCallEnd(runes []rune, from int) int {
	var quote rune
	var closes []rune
	argumentMode := []bool{true}
	for i := from; i < len(runes); i++ {
		r := runes[i]
		if quote != 0 {
			switch {
			case quote == '"' && r == '`':
				i++
			case windowsPowerShellQuoteDelimiter(r) == quote:
				if i+1 < len(runes) && windowsPowerShellQuoteDelimiter(runes[i+1]) == quote {
					i++
				} else {
					quote = 0
				}
			}
			continue
		}
		if r == '`' {
			i++
			continue
		}
		if !argumentMode[len(argumentMode)-1] && windowsPowerShellCommandWordBeforeBlank(runes, i) {
			argumentMode[len(argumentMode)-1] = true
		}
		if r == '-' && i+2 < len(runes) && runes[i+1] == '-' && runes[i+2] == '%' &&
			(i+3 == len(runes) || unicode.IsSpace(runes[i+3])) && windowsPowerShellTokenStart(runes, i) {
			i = windowsPowerShellStopParsingEnd(runes, i+3) - 1
			continue
		}
		if i+1 < len(runes) &&
			(r == '@' && windowsPowerShellQuoteDelimiter(runes[i+1]) != 0 ||
				(r == '$' || r == '@') && (runes[i+1] == '(' || runes[i+1] == '{')) {
			end, ok := windowsPowerShellOpaqueEnd(runes, i)
			if !ok {
				return len(runes)
			}
			i = end
			continue
		}
		if r == '<' && i+1 < len(runes) && runes[i+1] == '#' &&
			windowsPowerShellCommentStarts(runes, i, len(closes) > 0 && !argumentMode[len(argumentMode)-1]) {
			end, ok := windowsPowerShellBlockCommentEnd(runes, i)
			if !ok {
				return len(runes)
			}
			i = end
			continue
		}
		if r == '#' && windowsPowerShellCommentStarts(runes, i, len(closes) > 0 && !argumentMode[len(argumentMode)-1]) {
			for i+1 < len(runes) && runes[i+1] != '\n' && runes[i+1] != '\r' {
				i++
			}
			continue
		}
		if windowsPowerShellQuoteDelimiter(r) != 0 {
			quote = windowsPowerShellQuoteDelimiter(r)
			continue
		}
		switch r {
		case '(', '{':
			argumentMode = append(argumentMode, false)
			if r == '(' {
				closes = append(closes, ')')
			} else {
				closes = append(closes, '}')
			}
		case ')', '}':
			if len(closes) == 0 || closes[len(closes)-1] != r {
				return len(runes)
			}
			closes = closes[:len(closes)-1]
			argumentMode = argumentMode[:len(argumentMode)-1]
		case ';', '|', '\n', '\r':
			if len(closes) == 0 {
				return i
			}
			argumentMode[len(argumentMode)-1] = false
		case '&':
			if len(closes) == 0 && (i == 0 || runes[i-1] != '>') {
				return i
			}
			if i == 0 || runes[i-1] != '>' {
				argumentMode[len(argumentMode)-1] = false
			}
		}
	}
	return len(runes)
}

// Return the first pipeline, chain, or physical line boundary outside double quotes.
// The boundary itself belongs to the surrounding PowerShell reading.
func windowsPowerShellStopParsingEnd(runes []rune, from int) int {
	quoted := false
	for i := from; i < len(runes); i++ {
		switch runes[i] {
		case '\n', '\r':
			return i
		case '"':
			quoted = !quoted
		case '|':
			if !quoted {
				return i
			}
		case '&':
			if !quoted && i+1 < len(runes) && runes[i+1] == '&' {
				return i
			}
		}
	}
	return len(runes)
}

func windowsPowerShellTokenStart(runes []rune, i int) bool {
	return i == 0 || unicode.IsSpace(runes[i-1]) || strings.ContainsRune(";|&(){}", runes[i-1])
}
