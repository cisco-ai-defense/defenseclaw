// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"strings"
	"unicode"
)

// powerShellQuotedPathMax bounds the quoted paths of one call the client
// walks; a call with more is described as incomplete.
const powerShellQuotedPathMax = 128

// powerShellQuotedDepth bounds how deep quoted text is read again as code.
const powerShellQuotedDepth = 4

// powerShellQuotedPathOperands lists the quoted path literals of a
// PowerShell call as state operands. A managed gateway proves a write
// through a bound or quoted path from the Set-Content reading of that path
// (gateway provenPowerShellStateWrite) and, as it cannot walk the user's
// links, places the path only from the hook client map: a path that reaches
// the DefenseClaw state tree through a junction in the project is listed with
// its state name (GAP-1023). Single-quoted text is its value (a doubled quote
// is one); double-quoted text counts only when nothing in it expands. Quoted
// text is also read again as code, so the literals of a pwsh -Command body
// are listed too. The typographic quotes PowerShell accepts count as quotes.
// over is true past powerShellQuotedPathMax paths.
func powerShellQuotedPathOperands(command, cwd string) (operands []stateOperand, over bool) {
	seen := map[string]bool{}
	var read func(text string, depth int) bool
	read = func(text string, depth int) bool {
		runes := []rune(text)
		for i := 0; i < len(runes); i++ {
			single := psQuoteOfKind(runes[i], true)
			if !single && !psQuoteOfKind(runes[i], false) {
				continue
			}
			var value strings.Builder
			j := i + 1
			for ; j < len(runes); j++ {
				if !single && runes[j] == '`' && j+1 < len(runes) {
					value.WriteRune(runes[j])
					value.WriteRune(runes[j+1])
					j++
					continue
				}
				if psQuoteOfKind(runes[j], single) {
					if j+1 < len(runes) && psQuoteOfKind(runes[j+1], single) {
						value.WriteRune(runes[j])
						j++
						continue
					}
					break
				}
				value.WriteRune(runes[j])
			}
			if j >= len(runes) {
				return true
			}
			i = j
			literal := value.String()
			if !seen[literal] && psQuotedPath(literal, single) {
				if len(seen) >= powerShellQuotedPathMax {
					return false
				}
				seen[literal] = true
				operands = append(operands, stateOperand{path: OperandPath(literal, cwd)})
			}
			if depth < powerShellQuotedDepth && !read(literal, depth+1) {
				return false
			}
		}
		return true
	}
	return operands, !read(command, 0)
}

// psQuoteOfKind reports a single quote (single) or a double quote of
// PowerShell, ASCII or typographic.
func psQuoteOfKind(r rune, single bool) bool {
	if single {
		return r == '\'' || r == '‘' || r == '’' || r == '‚' || r == '‛'
	}
	return r == '"' || r == '“' || r == '”' || r == '„'
}

// psQuotedPath reports quoted text that may be a file path the client
// walks: one line, no expansion in a double-quoted string, within the map's
// path bound, and spelled with a separator, a drive or an extension.
func psQuotedPath(text string, single bool) bool {
	if text == "" || len(text) > MaxWriteTargetPathBytes || !strings.ContainsAny(text, `\/.:`) ||
		!single && strings.ContainsAny(text, "$`") {
		return false
	}
	return !strings.ContainsFunc(text, unicode.IsControl)
}
