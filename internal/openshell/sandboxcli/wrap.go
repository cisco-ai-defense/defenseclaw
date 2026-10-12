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

package sandboxcli

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// Output that has to fit a narrow terminal (60 columns in a split pane)
// breaks at word boundaries instead of mid-word, and a table wider than the
// terminal prints one block per row (GAP-0321). Nothing wraps unless IO.Width
// says the output is a terminal, so a pipe or a file gets the lines whole.

// minWrapWidth is the narrowest terminal output is wrapped for; below it the
// width is taken as unknown.
const minWrapWidth = 24

// width is the terminal's width in columns, 0 when output is not wrapped.
func (a *App) width() int {
	if a.IO.Width < minWrapWidth {
		return 0
	}
	return a.IO.Width
}

// visibleLen is the number of characters s shows: the palette's color codes
// take no column.
func visibleLen(s string) int {
	n := 0
	for i := 0; i < len(s); {
		if s[i] == 0x1b {
			if code := paletteCode(s[i:]); code != "" {
				i += len(code)
				continue
			}
		}
		_, size := utf8.DecodeRuneInString(s[i:])
		i += size
		n++
	}
	return n
}

// wrapWords breaks text into lines of at most width columns at the spaces
// between words, indenting every line after the first by hang. The spaces
// inside a line stay as they are (aligned columns), a word longer than a
// line stays whole on a line of its own, and a newline starts a new
// paragraph.
func wrapWords(text string, width int, hang string) []string {
	var out []string
	for _, para := range strings.Split(text, "\n") {
		lead := para[:len(para)-len(strings.TrimLeft(para, " "))]
		cur, curLen, started := lead, visibleLen(lead), false
		rest := strings.TrimLeft(para, " ")
		for rest != "" {
			word := rest
			if i := strings.IndexByte(rest, ' '); i >= 0 {
				word = rest[:i]
			}
			rest = rest[len(word):]
			sep := rest[:len(rest)-len(strings.TrimLeft(rest, " "))]
			rest = rest[len(sep):]
			if started && curLen+visibleLen(word) > width {
				out = append(out, strings.TrimRight(cur, " "))
				cur, curLen, started = hang, visibleLen(hang), false
			}
			cur += word
			curLen += visibleLen(word)
			started = true
			// The spaces after the last word of a line are dropped when it breaks.
			if rest != "" {
				cur += sep
				curLen += len(sep)
			}
		}
		out = append(out, strings.TrimRight(cur, " "))
	}
	return out
}

// hangingIndent is the indent of the lines after the first of a wrapped
// line: that of the line, and two columns more under a status mark.
func hangingIndent(line string) string {
	trimmed := strings.TrimLeft(line, " ")
	indent := line[:len(line)-len(trimmed)]
	for {
		code := paletteCode(trimmed)
		if code == "" {
			break
		}
		trimmed = trimmed[len(code):]
	}
	if r, _ := utf8.DecodeRuneInString(trimmed); strings.ContainsRune("⚠✓✗?•→", r) {
		indent += "  "
	}
	return indent
}

// tableWidth is the width table prints header and rows at.
func tableWidth(header []string, rows [][]string) int {
	cols := make([]int, len(header))
	measure := func(r []string) {
		for i, c := range r {
			if i < len(cols) {
				cols[i] = max(cols[i], utf8.RuneCountInString(sandboxapi.DisplayText(c)))
			}
		}
	}
	measure(header)
	for _, r := range rows {
		measure(r)
	}
	total := 2 * max(len(cols)-1, 0)
	for _, w := range cols {
		total += w
	}
	return total
}

// stackedTable prints a table too wide for the terminal as one block per
// row: its first cell, then each other column as a labelled line.
func (a *App) stackedTable(header []string, rows [][]string) {
	labelW := 0
	for _, h := range header[1:] {
		labelW = max(labelW, utf8.RuneCountInString(h))
	}
	for _, r := range rows {
		cells := sandboxapi.DisplayTexts(r)
		if len(cells) == 0 {
			continue
		}
		a.line(a.bold(cells[0]))
		for i := 1; i < len(header) && i < len(cells); i++ {
			if cells[i] != "" {
				a.labelled("  ", strings.ToLower(header[i]), labelW, cells[i], "")
			}
		}
	}
}

// labelled prints "<indent><label>  <text>" with the text wrapped under
// itself at the terminal's width and tag (a dim "[from ...]") after it: on
// the last line when it fits there, else on a line of its own. The label is
// padded to labelW.
func (a *App) labelled(indent, label string, labelW int, text, tag string) {
	prefix := fmt.Sprintf("%s%-*s  ", indent, labelW, label)
	w := a.width()
	if w == 0 {
		a.line(prefix + text + tag)
		return
	}
	hang := strings.Repeat(" ", len(prefix))
	// a.line adds its own two columns of indent.
	lines := wrapWords(text, max(w-2-len(prefix), 12), "")
	for i, l := range lines {
		lead := hang
		if i == 0 {
			lead = prefix
		}
		if i == len(lines)-1 && tag != "" {
			if visibleLen(lead+l+tag)+2 <= w {
				l += tag
			} else {
				a.line(lead + l)
				a.line(hang + strings.TrimLeft(tag, " "))
				return
			}
		}
		a.line(lead + l)
	}
}
