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
	for i := start + 2; i < len(runes); i++ {
		r := runes[i]
		top := frames[len(frames)-1]
		if top == 'v' {
			if r == '`' {
				i++
			} else if r == '}' {
				frames = frames[:len(frames)-1]
			}
		} else if top == '\'' || top == '"' {
			switch {
			case top == '"' && r == '`':
				i++
			case top == '"' && r == '$' && i+1 < len(runes) && runes[i+1] == '(':
				frames = append(frames, ')')
				i++
			case windowsPowerShellQuoteDelimiter(r) == top:
				if i+1 < len(runes) && windowsPowerShellQuoteDelimiter(runes[i+1]) == top {
					i++
				} else {
					frames = frames[:len(frames)-1]
				}
			}
		} else {
			next := rune(0)
			if i+1 < len(runes) {
				next = runes[i+1]
			}
			switch {
			case r == '`':
				i++
			case r == '<' && next == '#':
				end, ok := windowsPowerShellBlockCommentEnd(runes, i)
				if !ok {
					return 0, false
				}
				i = end
			case r == '#' && windowsPowerShellTokenStart(runes, i):
				for i+1 < len(runes) && runes[i+1] != '\n' && runes[i+1] != '\r' {
					i++
				}
			case r == '-' && next == '-' && i+2 < len(runes) && runes[i+2] == '%' &&
				(i+3 == len(runes) || unicode.IsSpace(runes[i+3])) &&
				windowsPowerShellTokenStart(runes, i):
				for i+1 < len(runes) && runes[i+1] != '\n' && runes[i+1] != '\r' {
					i++
				}
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
				frames = append(frames, 'v')
				i++
			case windowsPowerShellQuoteDelimiter(r) != 0:
				frames = append(frames, windowsPowerShellQuoteDelimiter(r))
			case r == '(':
				frames = append(frames, ')')
			case r == '{':
				frames = append(frames, '}')
			case r == ')' || r == '}':
				if r != top {
					return 0, false
				}
				frames = frames[:len(frames)-1]
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
	depth := 1
	for i := start + 2; i+1 < len(runes); i++ {
		switch {
		case runes[i] == '<' && runes[i+1] == '#':
			depth++
			i++
		case runes[i] == '#' && runes[i+1] == '>':
			depth--
			i++
			if depth == 0 {
				return i, true
			}
		}
	}
	return 0, false
}

func windowsPowerShellTokenStart(runes []rune, i int) bool {
	return i == 0 || unicode.IsSpace(runes[i-1]) || strings.ContainsRune(";|&(){},=", runes[i-1])
}
