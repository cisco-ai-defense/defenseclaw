// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package guardrail

import (
	"regexp"
	"strings"
)

// Python path rules describe a write, not a mention. Keep the original byte
// offsets for finding locations while ignoring comments and docstrings.
var pythonAssignment = regexp.MustCompile(`^\s*([A-Za-z_][A-Za-z_0-9]*)\s*=`)
var pythonWriteMethod = regexp.MustCompile(`\.(?:write_text|write_bytes|unlink|rmdir|rename|touch)\s*\(`)
var pythonModuleWrite = regexp.MustCompile(`\b(?:os\.(?:remove|unlink|rename|replace|truncate|rmdir|removedirs)|shutil\.(?:move|rmtree|copy|copy2|copyfile|copytree))\s*\(`)
var pythonWriteOpen = regexp.MustCompile(`\bopen\s*\([^\n)]*,\s*["'][rbtU]*[wax+]`)

func pythonPathWriteMatch(rule *regexp.Regexp, source string) []int {
	code := maskPythonCommentsAndDocstrings(source)
	lines := strings.Split(code, "\n")
	for _, hit := range rule.FindAllStringIndex(code, -1) {
		lineNo := strings.Count(code[:hit[0]], "\n")
		if lineNo >= len(lines) {
			continue
		}
		lineStart := hit[0] - strings.LastIndex(code[:hit[0]], "\n") - 1
		line := lines[lineNo]
		if pythonLineWritesPath(line, lineStart, hit[1]-hit[0]) {
			return hit
		}
		assign := pythonAssignment.FindStringSubmatch(line)
		if len(assign) != 2 || strings.Index(line, "=") > lineStart {
			continue
		}
		// A path assigned to a name is a write when a later statement uses
		// that name as the path argument. This covers Path.home()/"name"
		// followed by open(target, "a"), the common skill-script form.
		for _, later := range lines[lineNo+1:] {
			if pythonLineWritesName(later, assign[1]) {
				return hit
			}
		}
	}
	return nil
}

func pythonLineWritesPath(line string, column, width int) bool {
	if column < 0 || column+width > len(line) {
		return false
	}
	// The path must be inside the argument list, not elsewhere on a line
	// that happens to have another write call.
	for _, re := range []*regexp.Regexp{pythonModuleWrite, pythonWriteOpen} {
		for _, call := range re.FindAllStringIndex(line, -1) {
			if pythonCallContains(line, call[0], column, column+width) {
				return true
			}
		}
	}
	// pathlib's mutation methods act on the preceding Path object.
	for _, path := range regexp.MustCompile(`\bPath\s*\(`).FindAllStringIndex(line, -1) {
		end := pythonCallEnd(line, path[1]-1)
		if end >= column+width && column >= path[1] &&
			pythonWriteMethod.MatchString(strings.TrimSpace(line[end+1:])) {
			return true
		}
	}
	return false
}

func pythonLineWritesName(line, name string) bool {
	for _, re := range []*regexp.Regexp{pythonModuleWrite, pythonWriteOpen} {
		for _, call := range re.FindAllStringIndex(line, -1) {
			end := pythonCallEnd(line, strings.IndexByte(line[call[0]:], '(')+call[0])
			if end > call[0] && containsPythonName(line[call[0]:end], name) {
				return true
			}
		}
	}
	for _, method := range pythonWriteMethod.FindAllStringIndex(line, -1) {
		if containsPythonName(line[:method[0]], name) {
			return true
		}
	}
	return false
}

func containsPythonName(text, name string) bool {
	for _, pos := range regexp.MustCompile(`[A-Za-z_][A-Za-z_0-9]*`).FindAllStringIndex(text, -1) {
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

// Comments and triple-quoted strings can mention paths without executing a
// write. Blank them in place so matches retain their source offsets.
func maskPythonCommentsAndDocstrings(source string) string {
	out := []byte(source)
	quote := byte(0)
	triple := false
	escaped := false
	for i := 0; i < len(out); i++ {
		c := out[i]
		if quote != 0 {
			if triple {
				if i+2 < len(out) && out[i] == quote && out[i+1] == quote && out[i+2] == quote {
					out[i], out[i+1], out[i+2] = ' ', ' ', ' '
					i += 2
					quote, triple = 0, false
				} else if c != '\n' {
					out[i] = ' '
				}
				continue
			}
			if escaped {
				escaped = false
			} else if c == '\\' {
				escaped = true
			} else if c == quote {
				quote = 0
			}
			continue
		}
		if c == '#' {
			for i < len(out) && out[i] != '\n' {
				out[i] = ' '
				i++
			}
			continue
		}
		if c == '\'' || c == '"' {
			if i+2 < len(out) && out[i+1] == c && out[i+2] == c {
				quote, triple = c, true
				out[i], out[i+1], out[i+2] = ' ', ' ', ' '
				i += 2
			} else {
				quote = c
			}
		}
	}
	return string(out)
}
