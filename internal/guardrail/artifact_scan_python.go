// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package guardrail

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/lazyregexp"
	"github.com/defenseclaw/defenseclaw/internal/pythoninert"
)

// Python path rules describe a write, not a mention. Keep the original byte
// offsets for finding locations while ignoring comments and docstrings.
var pythonAssignment = lazyregexp.New(`^\s*([A-Za-z_][A-Za-z_0-9]*)\s*=`)
var pythonWriteMethod = lazyregexp.New(`\.(?:write_text|write_bytes|unlink|rmdir|rename|touch)\s*\(`)
var pythonModuleWrite = regexp.MustCompile(`\b(?:os\.(?:remove|unlink|rename|replace|truncate|rmdir|removedirs)|shutil\.(?:move|rmtree|copy|copy2|copyfile|copytree))\s*\(`)
var pythonWriteOpen = regexp.MustCompile(`\bopen\s*\([^\n)]*,\s*["'][rbtU]*[wax+]`)
var pythonPathCall = lazyregexp.New(`\bPath\s*\(`)

// pythonPathWriteMatch returns the first match of rule, a path, that a write
// call acts on. The path may sit in a string; the write call must start in
// code (MaskPythonStrings), since a call spelled in a string or in the
// literal text of an f-string runs nothing, unless the code may run a string
// (PythonStringsMayRun), when the masked text counts whole as before.
// script is the absolute path of the file, "" when it is not known: Python
// imports from the script's directory first.
func pythonPathWriteMatch(rule *regexp.Regexp, source, script string) []int {
	code := MaskPythonCommentsAndDocstrings(source)
	calls := pythoninert.MaskPythonStrings(source)
	dir, self := "", ""
	if script != "" {
		dir, self = filepath.Split(script)
		dir = filepath.Clean(dir)
	}
	if pythoninert.PythonScriptStringsMayRun(calls, dir, self) {
		calls = code
	}
	lines := strings.Split(code, "\n")
	callLines := strings.Split(calls, "\n")
	if len(callLines) != len(lines) {
		callLines = lines
	}
	for _, hit := range rule.FindAllStringIndex(code, -1) {
		lineNo := strings.Count(code[:hit[0]], "\n")
		if lineNo >= len(lines) {
			continue
		}
		lineStart := hit[0] - strings.LastIndex(code[:hit[0]], "\n") - 1
		line := lines[lineNo]
		if pythonLineWritesPath(line, callLines[lineNo], lineStart, hit[1]-hit[0]) {
			return hit
		}
		assign := pythonAssignment.FindStringSubmatch(line)
		if len(assign) != 2 || strings.Index(line, "=") > lineStart {
			continue
		}
		// A path assigned to a name is a write when a later statement uses
		// that name as the path argument. This covers Path.home()/"name"
		// followed by open(target, "a"), the common skill-script form.
		for offset, later := range lines[lineNo+1:] {
			if pythonLineWritesName(later, callLines[lineNo+1+offset], assign[1]) {
				return hit
			}
		}
	}
	return nil
}

// pythonLineWritesPath reports whether a write call on line acts on the
// path at column. calls is the line with its string text blanked
// (MaskPythonStrings): a write call must start in code.
func pythonLineWritesPath(line, calls string, column, width int) bool {
	if column < 0 || column+width > len(line) || len(calls) != len(line) {
		return false
	}
	// The path must be inside the argument list, not elsewhere on a line
	// that happens to have another write call.
	for _, re := range []*regexp.Regexp{pythonModuleWrite, pythonWriteOpen} {
		for _, call := range re.FindAllStringIndex(line, -1) {
			if pythonCodeAt(line, calls, call[0]) && pythonCallContains(line, call[0], column, column+width) {
				return true
			}
		}
	}
	// pathlib's mutation methods act on the preceding Path object.
	for _, path := range pythonPathCall.FindAllStringIndex(line, -1) {
		end := pythonCallEnd(line, path[1]-1)
		if end >= column+width && column >= path[1] && pythonCodeAt(line, calls, path[0]) &&
			pythonWriteMethod.MatchString(strings.TrimSpace(calls[end+1:])) {
			return true
		}
	}
	return false
}

// pythonLineWritesName reports whether a write call in the code of line
// (calls, the line with its string text blanked) acts on the variable name.
func pythonLineWritesName(line, calls, name string) bool {
	if len(calls) != len(line) {
		return false
	}
	for _, re := range []*regexp.Regexp{pythonModuleWrite, pythonWriteOpen} {
		for _, call := range re.FindAllStringIndex(line, -1) {
			if !pythonCodeAt(line, calls, call[0]) {
				continue
			}
			end := pythonCallEnd(line, strings.IndexByte(line[call[0]:], '(')+call[0])
			if end > call[0] && containsPythonName(calls[call[0]:end], name) {
				return true
			}
		}
	}
	for _, method := range pythonWriteMethod.FindAllStringIndex(line, -1) {
		if pythonCodeAt(line, calls, method[0]) && containsPythonName(calls[:method[0]], name) {
			return true
		}
	}
	return false
}

// pythonCodeAt reports whether text[i] is code: MaskPythonStrings kept it.
func pythonCodeAt(text, calls string, i int) bool {
	return i >= 0 && i < len(text) && i < len(calls) && text[i] != ' ' && calls[i] == text[i]
}

func containsPythonName(text, name string) bool {
	for _, pos := range pythoninert.PythonName.FindAllStringIndex(text, -1) {
		if text[pos[0]:pos[1]] == name {
			return true
		}
	}
	return false
}

func pythonCallContains(line string, callStart, matchStart, matchEnd int) bool {
	openRel := strings.IndexByte(line[callStart:], '(')
	if openRel < 0 {
		return false
	}
	open := callStart + openRel
	end := pythonCallEnd(line, open)
	return end >= matchEnd && matchStart > open
}

func pythonCallEnd(line string, open int) int {
	if open < 0 || open >= len(line) || line[open] != '(' {
		return -1
	}
	depth := 0
	var quote byte
	escaped := false
	for i := open; i < len(line); i++ {
		switch c := line[i]; {
		case quote != 0:
			if escaped {
				escaped = false
			} else if c == '\\' {
				escaped = true
			} else if c == quote {
				quote = 0
			}
		case c == '\'' || c == '"':
			quote = c
		case c == '(':
			depth++
		case c == ')':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// MaskPythonCommentsAndDocstrings blanks the comments and the triple-quoted
// strings of Python source in place, so matches keep their offsets: they can
// mention paths without executing a write. An f- or t-string runs the
// expressions of its replacement fields, so those are kept and its literal
// text is blanked: the text around the fields, the literal text of a format
// spec (f"{x:spec}", whose nested fields run), a conversion (!r) and a
// self-documenting "=" (f"{x=}"). Source whose strings the scan cannot
// follow (an unclosed string or field, nesting past pythonMaxStringNesting) is
// returned unmasked: blanking from a wrong string boundary could hide code.
func MaskPythonCommentsAndDocstrings(source string) string {
	out := []byte(source)
	for i := 0; i < len(out); {
		switch out[i] {
		case '#':
			for i < len(out) && out[i] != '\n' {
				out[i] = ' '
				i++
			}
		case '\'', '"':
			var exprs [][2]int
			end, ok := pythoninert.PythonStringEnd(out, i, 0, &exprs)
			if !ok {
				return source
			}
			if pythoninert.PythonTripleQuoteAt(out, i) {
				// Blank the literal text around the field expressions, which run.
				from := i
				for _, expr := range exprs {
					pythoninert.BlankPythonText(out[from:expr[0]])
					from = expr[1]
				}
				pythoninert.BlankPythonText(out[from:end])
			}
			i = end
		default:
			i++
		}
	}
	return string(out)
}
