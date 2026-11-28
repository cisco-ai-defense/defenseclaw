// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"math/rand"
	"strings"
	"testing"
)

// The resumable python reading gives the answers of the reading from byte 0
// for every position, in ascending order, with repeats and with steps back
// (rel-1-0-10:GAP-2276).
func TestGAP2276PythonCodeScannerMatchesOracle(t *testing.T) {
	pieces := []string{"a", " ", "\n", "#", `'`, `"`, `"""`, `'''`, `\`, "f", "F", "r", "rf", "{", "}", "{{", "}}", "(", "open(", "x=", "_"}
	random := rand.New(rand.NewSource(2276))
	questions := 0
	for program := 0; program < 3000; program++ {
		var b strings.Builder
		for n := random.Intn(60); n >= 0; n-- {
			b.WriteString(pieces[random.Intn(len(pieces))])
		}
		code := b.String()
		scan := newPythonCodeScanner(code)
		position := -1
		for step := 0; step < 80; step++ {
			switch random.Intn(8) {
			case 0:
				position = random.Intn(len(code)+3) - 1 // anywhere, maybe out of range
			case 1:
				// the same position again
			default:
				position += random.Intn(4)
			}
			questions++
			if got, want := scan.at(position), pythonExecutableCodePositionOracle(code, position); got != want {
				t.Fatalf("code %q position %d: scanner %v, oracle %v", code, position, got, want)
			}
		}
	}
	if questions < 200000 {
		t.Fatalf("%d questions", questions)
	}
}

// pythonExecutableCodePositionOracle is the reading from byte 0 that the
// scanner replaced, kept as the oracle.
func pythonExecutableCodePositionOracle(code string, position int) bool {
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
