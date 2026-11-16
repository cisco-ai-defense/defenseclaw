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

// Package hermesargs reads the Hermes native file-tool arguments that both
// the hook client and the gateway decide on, so the two sides name the same
// write targets for one call.
package hermesargs

import (
	"regexp"
	"strings"
	"unicode"

	"github.com/defenseclaw/defenseclaw/internal/lazyregexp"
)

// PlainPath reports a path with no control character and no line or
// paragraph separator.
func PlainPath(path string) bool {
	return !strings.ContainsFunc(path, func(r rune) bool {
		return unicode.IsControl(r) || r == '\u2028' || r == '\u2029'
	})
}

// Target is one file a Hermes V4A patch changes: written (Update, Add, a
// Move destination) or removed (Delete, a Move source). An Add carries the
// contents of its "+" lines as Hermes' parser keeps them (the line after the
// "+", up to but not including its "\n").
type Target struct {
	Path  string
	Write bool
	Add   bool
	Lines []string
}

// space is Python's str whitespace (re's \s for a str pattern and
// str.strip), which the Hermes V4A markers and paths use.
const space = `[\t\n\v\f\r\x1c-\x1f \x{85}\x{a0}\x{1680}\x{2000}-\x{200a}\x{2028}\x{2029}\x{202f}\x{205f}\x{3000}]`

// The Hermes V4A markers (tools/patch_parser.py), matched at the start of a
// line as Python's re.match does.
var (
	v4aBegin = lazyregexp.New(`^\*\*\*` + space + `*Begin` + space + `+Patch` + space + `*$`)
	v4aEnd   = lazyregexp.New(`^\*\*\*` + space + `*End` + space + `+Patch` + space + `*$`)
	v4aOps   = []struct {
		re    *regexp.Regexp
		write bool
		add   bool
		move  bool
	}{
		{re: regexp.MustCompile(`^\*\*\*` + space + `*Update` + space + `+File:` + space + `*(.+)`), write: true},
		{re: regexp.MustCompile(`^\*\*\*` + space + `*Add` + space + `+File:` + space + `*(.+)`), write: true, add: true},
		{re: regexp.MustCompile(`^\*\*\*` + space + `*Delete` + space + `+File:` + space + `*(.+)`)},
		{re: regexp.MustCompile(`^\*\*\*` + space + `*Move` + space + `+File:` + space + `*(.+?)` +
			space + `*->` + space + `*(.+)`), move: true},
	}
)

func strip(text string) string {
	return strings.TrimFunc(text, func(r rune) bool {
		switch {
		case r == '\t', r == '\n', r == '\v', r == '\f', r == '\r', r >= 0x1c && r <= 0x1f, r == ' ',
			r == 0x85, r == 0xa0, r == 0x1680, r >= 0x2000 && r <= 0x200a, r == 0x2028, r == 0x2029,
			r == 0x202f, r == 0x205f, r == 0x3000:
			return true
		}
		return false
	})
}

// V4ATargets lists the files a Hermes V4A patch changes, read as Hermes'
// parse_v4a_patch reads them: the lines after the last Begin marker before
// the first End marker (from the top without one) up to that End marker; an
// operation header starts its line; an Update needs a hunk line. The "+"
// lines of an Add are the lines up to the next operation header that start
// with "+", read on the line as Hermes splits it (at "\n" only, so a "\r"
// before it is kept). parsed is false when Hermes would refuse the patch (an
// empty path, an Update without hunks, a Move without a destination, a ".."
// component, which _collect_v4a_header_paths rejects) or when it names no
// file. The gateway judges these targets (connector.HermesTrustedWriteViews)
// and the hook client resolves the same ones (hookpaths.ResolveConnector).
func V4ATargets(body string) (targets []Target, parsed bool) {
	raw := strings.Split(body, "\n")
	lines := make([]string, len(raw))
	for i := range raw {
		lines[i] = strings.TrimSuffix(raw[i], "\r")
	}
	start, end := -1, len(lines)
	for i, line := range lines {
		if v4aBegin.MatchString(line) {
			start = i
		} else if v4aEnd.MatchString(line) {
			end = i
			break
		}
	}
	update, hunk, add := false, false, -1
	for i, line := range lines[start+1 : end] {
		matched := false
		for _, op := range v4aOps {
			groups := op.re.FindStringSubmatch(line)
			if groups == nil {
				continue
			}
			if update && !hunk {
				return nil, false
			}
			matched, update, hunk, add = true, false, false, -1
			source := strip(groups[1])
			if source == "" || traversal(source) {
				return nil, false
			}
			switch {
			case op.move:
				destination := strip(groups[2])
				if destination == "" || traversal(destination) {
					return nil, false
				}
				targets = append(targets, Target{Path: source},
					Target{Path: destination, Write: true})
			default:
				targets = append(targets, Target{Path: source, Write: op.write, Add: op.add})
				update = op.re == v4aOps[0].re
				if op.add {
					add = len(targets) - 1
				}
			}
			break
		}
		if !matched && update && line != "" && !strings.HasPrefix(line, `\`) {
			// A hunk header or any other line of an Update's hunk.
			hunk = hunk || !strings.HasPrefix(line, "@@")
		}
		if rawLine := raw[start+1+i]; !matched && add >= 0 && strings.HasPrefix(rawLine, "+") {
			targets[add].Lines = append(targets[add].Lines, rawLine[1:])
		}
	}
	if update && !hunk || len(targets) == 0 {
		return nil, false
	}
	return targets, true
}

// traversal reports a ".." path component, under either separator.
func traversal(path string) bool {
	for _, part := range strings.FieldsFunc(path, func(r rune) bool { return r == '/' || r == '\\' }) {
		if part == ".." {
			return true
		}
	}
	return false
}
