// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/lazyregexp"
)

var pythonInertPathPrefix = lazyregexp.New(`^from\s+pathlib\s+import\s+Path\s*;\s*[A-Za-z_][A-Za-z0-9_]*\s*=\s*Path\.home\(\)\s*(?:/\s*(?:"[^"\\]*"|'[^'\\]*')\s*)+;\s*$`)

type pythonCodeRegion uint8

const (
	pythonSource pythonCodeRegion = iota
	pythonString
	pythonFStringText
	pythonFStringExpr
)

type pythonCodeFrame struct {
	region pythonCodeRegion
	quote  byte
	triple bool
	braces int
}

// pythonExecutableCodePosition distinguishes an f-string replacement field
// from an ordinary string. A writer-looking token inside an ordinary string
// is data; the same token between a live f-string's braces is executed.
func pythonExecutableCodePosition(code string, position int) bool {
	return newPythonCodeScanner(code).at(position)
}

// pythonCodeScanner answers pythonExecutableCodePosition for many positions
// of one program. The reading of a byte never depends on the position asked,
// so the state at the first step at or past one position is the start of the
// reading for a later one: questions in ascending order (the matches of a
// regexp) read the program once. A position before the last one asked starts
// over. Each question read the whole prefix again, the square of dense code
// (rel-1-0-10:GAP-2276).
type pythonCodeScanner struct {
	code    string
	i, last int
	frames  []pythonCodeFrame
	comment bool
}

func newPythonCodeScanner(code string) *pythonCodeScanner {
	return &pythonCodeScanner{code: code, frames: []pythonCodeFrame{{region: pythonSource}}}
}

func (s *pythonCodeScanner) at(position int) bool {
	code := s.code
	if position < 0 || position > len(code) {
		return false
	}
	if position < s.last {
		s.i, s.comment = 0, false
		s.frames = append(s.frames[:0], pythonCodeFrame{region: pythonSource})
	}
	s.last = position
	for s.i < position {
		top := &s.frames[len(s.frames)-1]
		c := code[s.i]
		if s.comment {
			if c == '\n' {
				s.comment = false
			}
			s.i++
			continue
		}
		switch top.region {
		case pythonString, pythonFStringText:
			if c == '\\' {
				s.i += min(2, len(code)-s.i)
				continue
			}
			if c == top.quote && (!top.triple || strings.HasPrefix(code[s.i:], strings.Repeat(string(c), 3))) {
				length := 1
				if top.triple {
					length = 3
				}
				s.frames = s.frames[:len(s.frames)-1]
				s.i += length
				continue
			}
			if top.region == pythonFStringText && c == '{' {
				if s.i+1 < len(code) && code[s.i+1] == '{' {
					s.i += 2
					continue
				}
				s.frames = append(s.frames, pythonCodeFrame{region: pythonFStringExpr})
				s.i++
				continue
			}
			if top.region == pythonFStringText && c == '}' && s.i+1 < len(code) && code[s.i+1] == '}' {
				s.i += 2
				continue
			}
		case pythonSource, pythonFStringExpr:
			if c == '#' {
				s.comment = true
				s.i++
				continue
			}
			if c == '\'' || c == '"' {
				triple := strings.HasPrefix(code[s.i:], strings.Repeat(string(c), 3))
				region := pythonString
				if pythonFStringPrefix(code, s.i) {
					region = pythonFStringText
				}
				s.frames = append(s.frames, pythonCodeFrame{region: region, quote: c, triple: triple})
				if triple {
					s.i += 3
				} else {
					s.i++
				}
				continue
			}
			if top.region == pythonFStringExpr {
				switch c {
				case '{':
					top.braces++
				case '}':
					if top.braces == 0 {
						s.frames = s.frames[:len(s.frames)-1]
						s.i++
						continue
					}
					top.braces--
				}
			}
		}
		s.i++
	}
	region := s.frames[len(s.frames)-1].region
	return !s.comment && (region == pythonSource || region == pythonFStringExpr)
}

func pythonFStringPrefix(code string, quote int) bool {
	start := quote
	for start > 0 && quote-start < 2 && strings.ContainsRune("fFrR", rune(code[start-1])) {
		start--
	}
	if start == quote || start > 0 && (code[start-1] == '_' ||
		code[start-1] >= 'a' && code[start-1] <= 'z' ||
		code[start-1] >= 'A' && code[start-1] <= 'Z' ||
		code[start-1] >= '0' && code[start-1] <= '9') {
		return false
	}
	return strings.ContainsAny(code[start:quote], "fF")
}

// pythonInertTripleStringProgram proves one small read-only Python program:
// construct a pathlib Path and evaluate an ordinary triple-quoted literal.
// The literal's contents may resemble a write call but are never evaluated.
// An f prefix or any statement after the literal leaves this proof false.
func pythonInertTripleStringProgram(code string) bool {
	double := strings.Index(code, `"""`)
	single := strings.Index(code, `'''`)
	start := double
	if start < 0 || single >= 0 && single < start {
		start = single
	}
	if start < 0 || !pythonInertPathPrefix.MatchString(code[:start]) {
		return false
	}
	delimiter := code[start : start+3]
	for i := start + 3; i < len(code); i++ {
		if code[i] == '\\' {
			i++
			continue
		}
		if strings.HasPrefix(code[i:], delimiter) {
			return strings.Trim(strings.TrimSpace(code[i+3:]), "; ") == ""
		}
	}
	return false
}
