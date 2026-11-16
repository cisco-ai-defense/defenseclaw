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
	if position < 0 || position > len(code) {
		return false
	}
	frames := []pythonCodeFrame{{region: pythonSource}}
	comment := false
	for i := 0; i < position; {
		top := &frames[len(frames)-1]
		c := code[i]
		if comment {
			if c == '\n' {
				comment = false
			}
			i++
			continue
		}
		switch top.region {
		case pythonString, pythonFStringText:
			if c == '\\' {
				i += min(2, len(code)-i)
				continue
			}
			if c == top.quote && (!top.triple || strings.HasPrefix(code[i:], strings.Repeat(string(c), 3))) {
				length := 1
				if top.triple {
					length = 3
				}
				frames = frames[:len(frames)-1]
				i += length
				continue
			}
			if top.region == pythonFStringText && c == '{' {
				if i+1 < len(code) && code[i+1] == '{' {
					i += 2
					continue
				}
				frames = append(frames, pythonCodeFrame{region: pythonFStringExpr})
				i++
				continue
			}
			if top.region == pythonFStringText && c == '}' && i+1 < len(code) && code[i+1] == '}' {
				i += 2
				continue
			}
		case pythonSource, pythonFStringExpr:
			if c == '#' {
				comment = true
				i++
				continue
			}
			if c == '\'' || c == '"' {
				triple := strings.HasPrefix(code[i:], strings.Repeat(string(c), 3))
				region := pythonString
				if pythonFStringPrefix(code, i) {
					region = pythonFStringText
				}
				frames = append(frames, pythonCodeFrame{region: region, quote: c, triple: triple})
				if triple {
					i += 3
				} else {
					i++
				}
				continue
			}
			if top.region == pythonFStringExpr {
				switch c {
				case '{':
					top.braces++
				case '}':
					if top.braces == 0 {
						frames = frames[:len(frames)-1]
						i++
						continue
					}
					top.braces--
				}
			}
		}
		i++
	}
	region := frames[len(frames)-1].region
	return !comment && (region == pythonSource || region == pythonFStringExpr)
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
