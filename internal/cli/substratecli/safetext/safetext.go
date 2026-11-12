// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

// Package safetext is the one place that makes text from an agent safe to
// print on the person's terminal. Everything an actor controls (file names,
// diff text, task output, ask summaries, error text from the cluster) goes
// through it before it is shown: an agent must not be able to move the
// cursor, erase or hide lines, set the clipboard (OSC 52), the window title
// or a hyperlink, or ask the terminal to type something back.
package safetext

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// maxString bounds how much of an unterminated string sequence (OSC, DCS,
// APC, PM, SOS) is swallowed before the filter gives up and shows the rest.
const maxString = 8 << 10

// Clean returns s without terminal controls: escape sequences of every kind,
// C0 controls other than newline and tab, DEL, C1 controls, bidirectional
// and zero-width format characters, and invalid UTF-8. Carriage returns are
// dropped too (a bare CR rewrites the line). A string sequence that is never
// terminated ends at the next newline.
func Clean(s string) string { return render(s, false) }

// Visible is like Clean but shows what it removed as escapes (\x1b, ‮),
// so a person reading a diff or a review can see that something was there.
func Visible(s string) string { return render(s, true) }

// Line is Clean on one line: newlines and tabs become spaces and runs of
// spaces collapse. Use it for table cells, summaries and one-line messages.
func Line(s string) string {
	return strings.Join(strings.Fields(strings.NewReplacer("\n", " ", "\t", " ").Replace(Clean(s))), " ")
}

// Path returns a file path safe to print. A path with nothing unusual in it
// is returned as it is; otherwise it is shown quoted with every control and
// format character as an escape, so the name cannot paint over the screen.
func Path(s string) string {
	if !unusual(s) {
		return s
	}
	var b strings.Builder
	b.WriteByte('"')
	b.WriteString(escapeAll(s))
	b.WriteByte('"')
	return b.String()
}

func unusual(s string) bool {
	if !utf8.ValidString(s) {
		return true
	}
	for _, r := range s {
		if r == ' ' || r == '"' || r == '\\' || isControl(r) || isFormat(r) {
			return true
		}
	}
	return false
}

func isControl(r rune) bool {
	return r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f)
}

// isFormat reports bidirectional controls and zero-width characters that
// can reorder or hide text.
func isFormat(r rune) bool {
	switch {
	case r >= 0x202a && r <= 0x202e, r >= 0x2066 && r <= 0x2069:
		return true
	case r == 0x200e, r == 0x200f, r == 0x061c, r == 0x200b, r == 0x200c, r == 0x200d, r == 0x2060, r == 0xfeff:
		return true
	}
	return unicode.Is(unicode.Cf, r) && r != 0x00ad
}

func escapeAll(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size == 1:
			fmt.Fprintf(&b, `\x%02x`, s[i])
		case r == '"' || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\t':
			b.WriteString(`\t`)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, `\x%02x`, r)
		case isControl(r) || isFormat(r):
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			b.WriteRune(r)
		}
		i += size
	}
	return b.String()
}

// render walks s once. It drops (or, when visible is set, shows as an
// escape) everything the package documents.
func render(s string, visible bool) string {
	var b strings.Builder
	b.Grow(len(s))
	mark := func(text string) {
		if visible {
			b.WriteString(text)
		}
	}
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == 0x1b:
			end := skipEscape(s, i)
			mark(`\x1b`)
			i = end
			continue
		case c == '\n' || c == '\t':
			b.WriteByte(c)
		case c == '\r':
			mark(`\r`)
		case c < 0x20 || c == 0x7f:
			mark(fmt.Sprintf(`\x%02x`, c))
		case c < utf8.RuneSelf:
			b.WriteByte(c)
		default:
			r, size := utf8.DecodeRuneInString(s[i:])
			switch {
			case r == utf8.RuneError && size == 1:
				mark(fmt.Sprintf(`\x%02x`, c))
			case r == 0x9b || r == 0x9d || r == 0x90 || r == 0x98 || r == 0x9e || r == 0x9f:
				// An 8-bit CSI, OSC, DCS, SOS, PM or APC: take its body too.
				end := skipC1(s, i+size, r)
				mark(fmt.Sprintf(`\u%04x`, r))
				i = end
				continue
			case isControl(r) || isFormat(r):
				mark(fmt.Sprintf(`\u%04x`, r))
			default:
				b.WriteString(s[i : i+size])
			}
			i += size
			continue
		}
		i++
	}
	return b.String()
}

// skipEscape returns the index after the escape sequence that starts at s[i].
func skipEscape(s string, i int) int {
	j := i + 1
	if j >= len(s) {
		return j
	}
	switch s[j] {
	case '[': // CSI: parameters, intermediates, one final byte.
		j++
		for j < len(s) && s[j] >= 0x20 && s[j] <= 0x3f {
			j++
		}
		if j < len(s) && s[j] >= 0x40 && s[j] <= 0x7e {
			j++
		}
		return j
	case ']', 'P', 'X', '^', '_': // OSC, DCS, SOS, PM, APC: until a string terminator.
		return skipString(s, j+1)
	}
	// ESC, intermediates (charset selection and the like), one final byte.
	for j < len(s) && s[j] >= 0x20 && s[j] <= 0x2f {
		j++
	}
	if j < len(s) && s[j] >= 0x30 && s[j] <= 0x7e {
		j++
	}
	return j
}

// skipString skips a string sequence body starting at s[j]: it ends at BEL,
// ESC \, a C1 string terminator, a newline, or after maxString bytes.
func skipString(s string, j int) int {
	start := j
	for j < len(s) {
		switch {
		case s[j] == 0x07:
			return j + 1
		case s[j] == 0x1b && j+1 < len(s) && s[j+1] == '\\':
			return j + 2
		case s[j] == '\n':
			return j
		case s[j] == 0xc2 && j+1 < len(s) && s[j+1] == 0x9c: // U+009C in UTF-8
			return j + 2
		}
		if j-start > maxString {
			return j
		}
		j++
	}
	return j
}

func skipC1(s string, j int, r rune) int {
	if r == 0x9b {
		for j < len(s) && s[j] >= 0x20 && s[j] <= 0x3f {
			j++
		}
		if j < len(s) && s[j] >= 0x40 && s[j] <= 0x7e {
			j++
		}
		return j
	}
	return skipString(s, j)
}
