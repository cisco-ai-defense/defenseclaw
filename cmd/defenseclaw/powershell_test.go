// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"regexp"
	"strings"
	"testing"
)

func TestWindowsPowerShellFunctionExtractorSupportsMultilineParameters(t *testing.T) {
	fixture := `function Before-Fixture { return 'before' }
function Get-MultilineFixture(
    [Parameter(Mandatory)]
    [ValidateScript({ param($value) $value -ne ')' })]
    [string]$Text = "value(with)paren"
) {
    return $Text
}
function After-Fixture { return 'after' }
`
	extracted := windowsPowerShellFunction(t, fixture, "Get-MultilineFixture")
	for _, expected := range []string{
		"[ValidateScript({ param($value) $value -ne ')' })]",
		`[string]$Text = "value(with)paren"`,
		"return $Text",
	} {
		if !strings.Contains(extracted, expected) {
			t.Fatalf("multiline function extraction omitted %q", expected)
		}
	}
	if strings.Contains(extracted, "After-Fixture") {
		t.Fatal("multiline function extraction consumed the next declaration")
	}
}

func windowsPowerShellFunction(t *testing.T, module, name string) string {
	t.Helper()
	location := windowsPowerShellFunctionDeclaration(module, name)
	if location[0] < 0 {
		t.Fatalf("PowerShell function %s was not found", name)
	}
	remainder := module[location[1]:]
	next := regexp.MustCompile(`(?mi)^function[ \t]+`).FindStringIndex(remainder)
	if next == nil {
		return module[location[0]:]
	}
	return module[location[0] : location[1]+next[0]]
}

func windowsPowerShellFunctionDeclaration(module, name string) [2]int {
	declarations := regexp.MustCompile(
		`(?mi)^function[ \t]+`+regexp.QuoteMeta(name),
	).FindAllStringIndex(module, -1)
	for _, location := range declarations {
		cursor := location[1]
		if cursor < len(module) && !strings.ContainsRune(" \t\r\n({", rune(module[cursor])) {
			continue
		}
		cursor = skipPowerShellDeclarationTrivia(module, cursor)
		if cursor < len(module) && module[cursor] == '(' {
			var ok bool
			cursor, ok = scanBalancedPowerShellDeclaration(module, cursor, '(', ')')
			if !ok {
				continue
			}
			cursor = skipPowerShellDeclarationTrivia(module, cursor)
		}
		if cursor < len(module) && module[cursor] == '{' {
			return [2]int{location[0], cursor + 1}
		}
	}
	return [2]int{-1, -1}
}

func skipPowerShellDeclarationTrivia(module string, cursor int) int {
	for cursor < len(module) {
		switch module[cursor] {
		case ' ', '\t', '\r', '\n':
			cursor++
		case '#':
			for cursor < len(module) && module[cursor] != '\r' && module[cursor] != '\n' {
				cursor++
			}
		case '<':
			if cursor+1 >= len(module) || module[cursor+1] != '#' {
				return cursor
			}
			closing := strings.Index(module[cursor+2:], "#>")
			if closing < 0 {
				return len(module)
			}
			cursor += closing + 4
		default:
			return cursor
		}
	}
	return cursor
}

func scanBalancedPowerShellDeclaration(
	module string,
	cursor int,
	opening byte,
	closing byte,
) (int, bool) {
	depth := 0
	for cursor < len(module) {
		switch module[cursor] {
		case '\'':
			cursor++
			for cursor < len(module) {
				if module[cursor] != '\'' {
					cursor++
					continue
				}
				if cursor+1 < len(module) && module[cursor+1] == '\'' {
					cursor += 2
					continue
				}
				cursor++
				break
			}
			continue
		case '"':
			cursor++
			for cursor < len(module) {
				if module[cursor] == '`' && cursor+1 < len(module) {
					cursor += 2
					continue
				}
				if module[cursor] == '"' {
					cursor++
					break
				}
				cursor++
			}
			continue
		case '#':
			for cursor < len(module) && module[cursor] != '\r' && module[cursor] != '\n' {
				cursor++
			}
			continue
		case '<':
			if cursor+1 < len(module) && module[cursor+1] == '#' {
				closingComment := strings.Index(module[cursor+2:], "#>")
				if closingComment < 0 {
					return 0, false
				}
				cursor += closingComment + 4
				continue
			}
		}
		if module[cursor] == opening {
			depth++
		} else if module[cursor] == closing {
			depth--
			if depth == 0 {
				return cursor + 1, true
			}
		}
		cursor++
	}
	return 0, false
}
