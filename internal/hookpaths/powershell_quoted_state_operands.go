// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"strings"
	"unicode"

	"github.com/defenseclaw/defenseclaw/internal/asciifold"
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
// A double-quoted path or a bare argument whose only expansion is the home
// it starts with ("$HOME\.defenseclaw\config.yaml" as a .NET file method's
// argument, $HOME\.codex\config.toml as a cmdlet's) is listed as the path in
// home (psHomeQuotedPath, rel-1-0-10:GAP-1115): a call Codex runs through
// its Bash tool is not read as PowerShell elsewhere in the client.
// over is true past powerShellQuotedPathMax paths.
func powerShellQuotedPathOperands(command, cwd, home string) (operands []stateOperand, over bool) {
	seen := map[string]bool{}
	var read func(text string, depth int) bool
	read = func(text string, depth int) bool {
		runes := []rune(text)
		for i := 0; i < len(runes); i++ {
			single := psQuoteOfKind(runes[i], true)
			if !single && !psQuoteOfKind(runes[i], false) {
				// A bare argument that starts with the home is the same path
				// to PowerShell: Add-Content -Path $HOME\.codex\config.toml,
				// Get-Item ~\.defenseclaw\config.yaml (its FileSystem provider
				// reads a leading ~ as the home, rel-1-0-10:GAP-1191).
				tilde := runes[i] == '~' && i+1 < len(runes) && (runes[i+1] == '\\' || runes[i+1] == '/')
				if runes[i] != '$' && !tilde || i > 0 && !strings.ContainsRune(" \t\r\n(,=:;|{", runes[i-1]) {
					continue
				}
				j := i + 1
				if j < len(runes) && runes[j] == '{' {
					// ${HOME} and ${env:USERPROFILE} end at their brace.
					for j < len(runes) && runes[j] != '}' {
						j++
					}
					if j < len(runes) {
						j++
					}
				}
				for j < len(runes) && !strings.ContainsRune(" \t\r\n;|(){},'\"`", runes[j]) && !psQuoteOfKind(runes[j], true) &&
					!psQuoteOfKind(runes[j], false) {
					j++
				}
				word := string(runes[i:j])
				path, ok := psHomeQuotedPath(word, home)
				if tilde {
					path, ok = psTildeHomePath(word, home)
				}
				if ok && !seen[word] {
					if len(seen) >= powerShellQuotedPathMax {
						return false
					}
					seen[word] = true
					operands = append(operands, stateOperand{path: OperandPath(path, cwd)})
				}
				i = j - 1
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
			path, quotedPath := literal, psQuotedPath(literal, single)
			if !quotedPath && !single {
				path, quotedPath = psHomeQuotedPath(literal, home)
			}
			if !seen[literal] && quotedPath {
				if len(seen) >= powerShellQuotedPathMax {
					return false
				}
				seen[literal] = true
				operands = append(operands, stateOperand{path: OperandPath(path, cwd)})
			}
			if depth < powerShellQuotedDepth && !read(literal, depth+1) {
				return false
			}
		}
		return true
	}
	return operands, !read(command, 0)
}

// psHomeVariables are the spellings of the user's home a PowerShell string
// expands (lower case): the automatic variable and the profile variable.
var psHomeVariables = []string{"$home", "${home}", "$env:userprofile", "${env:userprofile}"}

// psPOSIXHomeVariables are the spellings of the user's home pwsh expands on
// Linux and macOS (lower case).
var psPOSIXHomeVariables = []string{"$home", "${home}"}

// psHomeQuotedPath returns the path a double-quoted string or a bare word
// names when it starts with the home (psHomeVariables) followed by a separator and
// expands nothing else, false for any other string. Under a Linux or macOS
// home only $HOME counts.
func psHomeQuotedPath(text, home string) (string, bool) {
	variables := psHomeVariables
	switch {
	case actionWindowsHome(home):
	case strings.HasPrefix(home, "/"):
		// pwsh on Linux and macOS: $HOME is the home, USERPROFILE is not
		// set (the script of a PowerShell launcher, rel-1-0-10:GAP-1138).
		variables = psPOSIXHomeVariables
	default:
		return "", false
	}
	lower := asciifold.Lower(text)
	for _, variable := range variables {
		rest, ok := strings.CutPrefix(lower, variable)
		if !ok || rest == "" || rest[0] != '\\' && rest[0] != '/' {
			continue
		}
		path := strings.TrimRight(home, `\/`) + text[len(variable):]
		if psQuotedPath(path, false) {
			return path, true
		}
	}
	return "", false
}

// psTildeHomePath returns the path a bare PowerShell word ~\rest or ~/rest
// names: rest in the home, for a Windows home and for pwsh on Linux and
// macOS. A word that expands anything else is no static path.
func psTildeHomePath(word, home string) (string, bool) {
	if !actionWindowsHome(home) && !strings.HasPrefix(home, "/") ||
		len(word) < 3 || word[0] != '~' || word[1] != '\\' && word[1] != '/' {
		return "", false
	}
	rest := word[1:]
	if strings.HasPrefix(home, "/") {
		// pwsh takes \ as a separator on Linux and macOS too.
		rest = strings.ReplaceAll(rest, `\`, "/")
	}
	path := strings.TrimRight(home, `\/`) + rest
	if !psQuotedPath(path, false) {
		return "", false
	}
	return path, true
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
