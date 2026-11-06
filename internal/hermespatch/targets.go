// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Package hermespatch decodes the file targets of a Hermes V4A patch for
// both the hook client and the gateway.
package hermespatch

import (
	"regexp"
	"strings"
	"unicode"

	"github.com/defenseclaw/defenseclaw/internal/lazyregexp"
)

// Target is a file changed by a V4A patch. A move has two targets.
type Target struct {
	Path  string
	Write bool
}

// DetailedTarget also retains the content lines of an Add operation.
type DetailedTarget struct {
	Target
	Add   bool
	Lines []string
}

// PlainPath reports a path with no control character or line separator.
func PlainPath(path string) bool {
	return !strings.ContainsFunc(path, func(r rune) bool {
		return unicode.IsControl(r) || r == '\u2028' || r == '\u2029'
	})
}

// hermesSpace is Python's str whitespace (re's \s for a str pattern and
// str.strip), which the Hermes V4A markers and paths use.
const hermesSpace = `[\t\n\v\f\r\x1c-\x1f \x{85}\x{a0}\x{1680}\x{2000}-\x{200a}\x{2028}\x{2029}\x{202f}\x{205f}\x{3000}]`

var (
	hermesV4ABegin = lazyregexp.New(`^\*\*\*` + hermesSpace + `*Begin` + hermesSpace + `+Patch` + hermesSpace + `*$`)
	hermesV4AEnd   = lazyregexp.New(`^\*\*\*` + hermesSpace + `*End` + hermesSpace + `+Patch` + hermesSpace + `*$`)
	hermesV4AOps   = []struct {
		re    *regexp.Regexp
		write bool
		add   bool
		move  bool
	}{
		{re: regexp.MustCompile(`^\*\*\*` + hermesSpace + `*Update` + hermesSpace + `+File:` + hermesSpace + `*(.+)`), write: true},
		{re: regexp.MustCompile(`^\*\*\*` + hermesSpace + `*Add` + hermesSpace + `+File:` + hermesSpace + `*(.+)`), write: true, add: true},
		{re: regexp.MustCompile(`^\*\*\*` + hermesSpace + `*Delete` + hermesSpace + `+File:` + hermesSpace + `*(.+)`)},
		{re: regexp.MustCompile(`^\*\*\*` + hermesSpace + `*Move` + hermesSpace + `+File:` + hermesSpace + `*(.+?)` +
			hermesSpace + `*->` + hermesSpace + `*(.+)`), move: true},
	}
)

func hermesStrip(text string) string {
	return strings.TrimFunc(text, func(r rune) bool {
		switch {
		case r == '\t', r == '\n', r == '\v', r == '\f', r == '\r', r >= 0x1c && r <= 0x1f, r == ' ',
			r == 0x85, r == 0xa0, r == 0x1680, r >= 0x2000 && r <= 0x200a, r == 0x2028,
			r == 0x2029, r == 0x202f, r == 0x205f, r == 0x3000:
			return true
		}
		return false
	})
}

// Targets lists the files changed by a V4A patch. Invalid or empty patches
// return false, so callers keep the unverified-target outcome.
func Targets(body string) ([]Target, bool) {
	parsed, ok := Parse(body)
	if !ok {
		return nil, false
	}
	paths := make([]Target, len(parsed))
	for i := range parsed {
		paths[i] = parsed[i].Target
	}
	return paths, true
}

// Parse follows Hermes' V4A header and hunk reading. Add lines are retained
// for the gateway's content rules; the client uses the same target list.
func Parse(body string) (targets []DetailedTarget, parsed bool) {
	raw := strings.Split(body, "\n")
	lines := make([]string, len(raw))
	for i := range raw {
		lines[i] = strings.TrimSuffix(raw[i], "\r")
	}
	start, end := -1, len(lines)
	for i, line := range lines {
		if hermesV4ABegin.MatchString(line) {
			start = i
		} else if hermesV4AEnd.MatchString(line) {
			end = i
			break
		}
	}
	update, hunk, add := false, false, -1
	for i, line := range lines[start+1 : end] {
		matched := false
		for _, op := range hermesV4AOps {
			groups := op.re.FindStringSubmatch(line)
			if groups == nil {
				continue
			}
			if update && !hunk {
				return nil, false
			}
			matched, update, hunk, add = true, false, false, -1
			source := hermesStrip(groups[1])
			if source == "" || hermesTraversal(source) {
				return nil, false
			}
			switch {
			case op.move:
				destination := hermesStrip(groups[2])
				if destination == "" || hermesTraversal(destination) {
					return nil, false
				}
				targets = append(targets, DetailedTarget{Target: Target{Path: source}},
					DetailedTarget{Target: Target{Path: destination, Write: true}})
			default:
				targets = append(targets, DetailedTarget{Target: Target{Path: source, Write: op.write}, Add: op.add})
				update = op.re == hermesV4AOps[0].re
				if op.add {
					add = len(targets) - 1
				}
			}
			break
		}
		if !matched && update && line != "" && !strings.HasPrefix(line, `\`) {
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

func hermesTraversal(path string) bool {
	for _, part := range strings.FieldsFunc(path, func(r rune) bool { return r == '/' || r == '\\' }) {
		if part == ".." {
			return true
		}
	}
	return false
}
