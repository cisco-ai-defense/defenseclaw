// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"strconv"
	"strings"
	"unicode"
)

// windowsPowerShellOpaqueEnd finds the end of one balanced value without
// interpreting its contents as commands. A failed match leaves the Windows
// reading at the opener; guessing an end could turn data into a command.
func windowsPowerShellOpaqueEnd(runes []rune, start int) (int, bool) {
	if start >= len(runes) {
		return 0, false
	}
	codeStart := start + 2
	bareParen := runes[start] == '('
	if bareParen {
		codeStart = start + 1
	} else if start+1 >= len(runes) {
		return 0, false
	}
	if !bareParen && runes[start] == '@' && windowsPowerShellQuoteDelimiter(runes[start+1]) != 0 {
		if !powerShellHereStringOpens(runes, start+2) {
			return 0, false
		}
		return windowsPowerShellHereStringEnd(runes, start)
	}
	var close rune
	switch {
	case bareParen || runes[start+1] == '(':
		close = ')'
	case runes[start+1] == '{':
		close = '}'
	default:
		return 0, false
	}
	if runes[start] == '$' && close == '}' {
		close = 'v' // braced variable: its contents are a name, not code
	}
	frames := []rune{close}
	argumentMode := []bool{false}
	hashtable := []bool{runes[start] == '@' && close == '}'}
	statementStart := []bool{!hashtable[0]}
	push := func(close rune, table bool) {
		frames = append(frames, close)
		argumentMode = append(argumentMode, false)
		hashtable = append(hashtable, table)
		statementStart = append(statementStart, !table)
	}
	pop := func() {
		frames = frames[:len(frames)-1]
		argumentMode = argumentMode[:len(argumentMode)-1]
		hashtable = hashtable[:len(hashtable)-1]
		statementStart = statementStart[:len(statementStart)-1]
	}
	for i := codeStart; i < len(runes); i++ {
		r := runes[i]
		top := frames[len(frames)-1]
		switch top {
		case 'v':
			switch r {
			case '`':
				i++
			case '}':
				pop()
			}
		case '\'', '"':
			switch {
			case top == '"' && r == '`':
				i++
			case top == '"' && r == '$' && i+1 < len(runes) && runes[i+1] == '(':
				push(')', false)
				i++
			case windowsPowerShellQuoteDelimiter(r) == top:
				if i+1 < len(runes) && windowsPowerShellQuoteDelimiter(runes[i+1]) == top {
					i++
				} else {
					pop()
				}
			}
		default:
			next := rune(0)
			if i+1 < len(runes) {
				next = runes[i+1]
			}
			comment := (r == '#' || r == '<' && next == '#') &&
				windowsPowerShellCommentStarts(runes, i, !argumentMode[len(argumentMode)-1])
			if statementStart[len(statementStart)-1] && windowsPowerShellStatementCommandWord(runes, i) {
				argumentMode[len(argumentMode)-1] = true
			}
			if statementStart[len(statementStart)-1] && !unicode.IsSpace(r) && r != '&' && !comment {
				statementStart[len(statementStart)-1] = false
			}
			if strings.ContainsRune(";|\r\n", r) || r == '&' && (i == 0 || runes[i-1] != '>') {
				argumentMode[len(argumentMode)-1] = false
				statementStart[len(statementStart)-1] = !hashtable[len(hashtable)-1]
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
				push('v', false)
				i++
			case windowsPowerShellQuoteDelimiter(r) != 0:
				// Adjacent delimiters of the same family in an active string
				// are consumed by the quote frame above. Reaching the second
				// one as code means the value cannot be read reliably.
				if i > 0 && windowsPowerShellQuoteDelimiter(runes[i-1]) == windowsPowerShellQuoteDelimiter(r) {
					return 0, false
				}
				push(windowsPowerShellQuoteDelimiter(r), false)
			case r == '(':
				push(')', false)
			case r == '{':
				push('}', i > 0 && runes[i-1] == '@')
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

// PowerShellCommentStarts shares the comment boundary with the gateway's
// independent state-write reader.
func PowerShellCommentStarts(runes []rune, i int, expressionMode bool) bool {
	return windowsPowerShellCommentStarts(runes, i, expressionMode)
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

// A command word at statement start puts PowerShell in argument mode. A
// leading digit or punctuation can also be part of a command word when the
// rest of that word is not an expression (for example, 1a"b" or -a"b").
// Read only this word: a later quoted argument cannot change its mode.
func windowsPowerShellStatementCommandWord(runes []rune, start int) bool {
	if start < 0 || start >= len(runes) {
		return false
	}
	r := runes[start]
	if unicode.IsSpace(r) || strings.ContainsRune("$@(['\"+<>,;|&{}#)]", r) {
		return false
	}
	if !unicode.IsDigit(r) && !strings.ContainsRune("-*/%!?=", r) {
		return true
	}
	end := start + 1
	for end < len(runes) && !unicode.IsSpace(runes[end]) &&
		!strings.ContainsRune(";|&(){}#<>,", runes[end]) {
		if windowsPowerShellQuoteDelimiter(runes[end]) != 0 {
			return true // a quote glued to this token makes a command word
		}
		end++
	}
	word := string(runes[start:end])
	if strings.Trim(word, "-*/%!?=") == "" {
		return false
	}
	if unicode.IsDigit(r) || r == '-' {
		unsigned := strings.TrimPrefix(word, "-")
		if windowsPowerShellNumericWord(unsigned) {
			return false
		}
	}
	for _, c := range word {
		if unicode.IsLetter(c) {
			return true
		}
	}
	return false
}

// Numeric literals are expressions, including PowerShell's type and size
// suffixes. Keep their glued comments in expression mode.
func windowsPowerShellNumericWord(word string) bool {
	if _, err := strconv.ParseInt(word, 0, 64); err == nil {
		return true
	}
	if _, err := strconv.ParseFloat(word, 64); err == nil {
		return true
	}
	lower := strings.ToLower(word)
	for _, suffix := range []string{"uy", "us", "ul", "un", "kb", "mb", "gb", "tb", "pb", "y", "s", "l", "n", "u", "d", "m"} {
		if !strings.HasSuffix(lower, suffix) {
			continue
		}
		base := word[:len(word)-len(suffix)]
		if _, err := strconv.ParseInt(base, 0, 64); err == nil {
			return true
		}
		if _, err := strconv.ParseFloat(base, 64); err == nil {
			return true
		}
	}
	return false
}

// PowerShellStatementCommandWord shares the statement-start mode choice with
// the gateway's independent state-write reader.
func PowerShellStatementCommandWord(runes []rune, start int) bool {
	return windowsPowerShellStatementCommandWord(runes, start)
}

// A type literal at statement start is an expression. The lexer and simple
// command splitter read top-level text without expression frames, so they
// use this local check when a comment is glued to a closing type bracket.
func windowsPowerShellTypeExpressionBeforeComment(runes []rune, i int) bool {
	if i < 3 || runes[i-1] != ']' {
		return false
	}
	open := i - 2
	for open >= 0 && i-open <= 64 && runes[open] != '[' {
		if !unicode.IsLetter(runes[open]) && !unicode.IsDigit(runes[open]) && runes[open] != '.' {
			return false
		}
		open--
	}
	if open < 0 || runes[open] != '[' || open == i-2 || !unicode.IsLetter(runes[open+1]) {
		return false
	}
	for j := open - 1; j >= 0; j-- {
		if unicode.IsSpace(runes[j]) && runes[j] != '\n' && runes[j] != '\r' {
			continue
		}
		return strings.ContainsRune(";|&({}\r\n", runes[j])
	}
	return true
}

// Keep a dynamic call opaque, but return to the lexer at its next top-level
// separator. The following command can then be read on its own.
func windowsPowerShellDynamicCallEnd(runes []rune, from int) int {
	var quote rune
	var closes []rune
	argumentMode := []bool{true}
	statementStart := []bool{false}
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
		next := rune(0)
		if i+1 < len(runes) {
			next = runes[i+1]
		}
		comment := (r == '#' || r == '<' && next == '#') &&
			windowsPowerShellCommentStarts(runes, i, len(closes) > 0 && !argumentMode[len(argumentMode)-1])
		if statementStart[len(statementStart)-1] && windowsPowerShellStatementCommandWord(runes, i) {
			argumentMode[len(argumentMode)-1] = true
		}
		if statementStart[len(statementStart)-1] && !unicode.IsSpace(r) && r != '&' && !comment {
			statementStart[len(statementStart)-1] = false
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
			statementStart = append(statementStart, true)
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
			statementStart = statementStart[:len(statementStart)-1]
		case ';', '|', '\n', '\r':
			if len(closes) == 0 {
				return i
			}
			argumentMode[len(argumentMode)-1] = false
			statementStart[len(statementStart)-1] = true
		case '&':
			if len(closes) == 0 && (i == 0 || runes[i-1] != '>') {
				return i
			}
			if i == 0 || runes[i-1] != '>' {
				argumentMode[len(argumentMode)-1] = false
				statementStart[len(statementStart)-1] = true
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
