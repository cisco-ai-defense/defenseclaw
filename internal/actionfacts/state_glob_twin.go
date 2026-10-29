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

package actionfacts

import (
	"path/filepath"
	"sort"
	"strings"

	"mvdan.cc/sh/v3/syntax"

	"github.com/defenseclaw/defenseclaw/internal/shellparse"
)

// maxStateGlobMatches bounds the words one pattern may expand to.
const maxStateGlobMatches = 64

// StateGlobTwin returns the POSIX reading of command in which every
// unquoted pathname pattern under a .defenseclaw directory is replaced by
// the names it matches on this host, as the shell expands it before the
// command runs (GAP-2496: cp a.txt ~/.defenseclaw/conf*.yaml writes
// config.yaml, while the pattern itself named no state file). Home words
// are first written as the active home. A pattern that matches nothing
// stays as written, as it does in the shell; a leading wildcard does not
// match a name that starts with a dot. ok is false when no pattern matched.
func StateGlobTwin(command, activeHome string) (twin string, ok bool) {
	defer func() {
		if recover() != nil {
			twin, ok = "", false
		}
	}()
	home, _ := normalizeActiveHome(activeHome)
	home = strings.TrimRight(home, "/")
	if home == "" || !posixShellHome(home) || strings.ContainsAny(home, "\x00\r\n") {
		return "", false
	}
	source := command
	if !strings.Contains(source, ".defenseclaw") || !strings.ContainsAny(source, "*?[") {
		return "", false
	}
	file, parsed := shellparse.Parse(source)
	if !parsed {
		return "", false
	}
	type edit struct {
		start, end int
		text       string
	}
	var edits []edit
	syntax.Walk(file, func(node syntax.Node) bool {
		word, isWord := node.(*syntax.Word)
		if !isWord {
			return true
		}
		pattern, literal := statePatternWord(word, home)
		if !literal || !strings.HasPrefix(pattern, "/") || !strings.Contains(pattern, "/.defenseclaw") ||
			!strings.ContainsAny(pattern, "*?[") {
			return false
		}
		matches, err := filepath.Glob(pattern)
		if err != nil || len(matches) == 0 || len(matches) > maxStateGlobMatches {
			return false
		}
		matches = withoutHiddenWildcardMatches(pattern, matches)
		if len(matches) == 0 {
			return false
		}
		sort.Strings(matches)
		quoted := make([]string, 0, len(matches))
		for _, match := range matches {
			quoted = append(quoted, "\x27"+strings.ReplaceAll(match, "\x27", "\x27\\\x27\x27")+"\x27")
		}
		start, end := int(word.Pos().Offset()), int(word.End().Offset())
		if start >= 0 && end > start && end <= len(source) {
			edits = append(edits, edit{start: start, end: end, text: strings.Join(quoted, " ")})
		}
		return false
	})
	if len(edits) == 0 {
		return "", false
	}
	sort.Slice(edits, func(i, j int) bool { return edits[i].start < edits[j].start })
	var out strings.Builder
	last := 0
	for _, change := range edits {
		if change.start < last {
			return "", false
		}
		out.WriteString(source[last:change.start])
		out.WriteString(change.text)
		last = change.end
	}
	out.WriteString(source[last:])
	return out.String(), true
}

// statePatternWord returns the pathname pattern of a word: unquoted
// literal text keeps its pattern characters, quoted text is matched as
// written, and a leading ~ or ~/ and a plain $HOME or ${HOME} name the
// active home. ok is false for any other expansion or an escape.
func statePatternWord(word *syntax.Word, home string) (string, bool) {
	if word == nil || len(word.Parts) == 0 {
		return "", false
	}
	escape := func(text string) string {
		var out strings.Builder
		for _, char := range text {
			if strings.ContainsRune("*?[]\\", char) {
				out.WriteRune(92)
			}
			out.WriteRune(char)
		}
		return out.String()
	}
	homeParam := func(part syntax.WordPart) bool {
		param, isParam := part.(*syntax.ParamExp)
		return isParam && param.Param != nil && param.Param.Value == "HOME" && param.Exp == nil &&
			param.Repl == nil && param.Slice == nil && param.Index == nil && !param.Length &&
			!param.Width && !param.Excl && !param.IsSet && param.Names == 0 &&
			param.NestedParam == nil && len(param.Modifiers) == 0
	}
	var text strings.Builder
	for index, part := range word.Parts {
		switch typed := part.(type) {
		case *syntax.Lit:
			value := typed.Value
			if strings.Contains(value, "\\") {
				return "", false
			}
			if index == 0 && (value == "~" || strings.HasPrefix(value, "~/")) {
				text.WriteString(escape(home))
				value = value[1:]
			}
			text.WriteString(value)
		case *syntax.SglQuoted:
			text.WriteString(escape(typed.Value))
		case *syntax.ParamExp:
			if !homeParam(typed) {
				return "", false
			}
			text.WriteString(escape(home))
		case *syntax.DblQuoted:
			for _, inner := range typed.Parts {
				switch innerTyped := inner.(type) {
				case *syntax.Lit:
					text.WriteString(escape(innerTyped.Value))
				case *syntax.ParamExp:
					if !homeParam(innerTyped) {
						return "", false
					}
					text.WriteString(escape(home))
				default:
					return "", false
				}
			}
		default:
			return "", false
		}
	}
	return text.String(), true
}

// withoutHiddenWildcardMatches drops a match whose component starts with a
// dot where the pattern component starts with a wildcard: the shell does
// not expand * or ? or [ at the start of a name to a dot file (dotglob is
// off by default), while filepath.Glob does.
func withoutHiddenWildcardMatches(pattern string, matches []string) []string {
	patternParts := strings.Split(pattern, "/")
	kept := matches[:0]
	for _, match := range matches {
		matchParts := strings.Split(match, "/")
		if len(matchParts) != len(patternParts) {
			continue
		}
		hidden := false
		for index, part := range patternParts {
			if part != "" && strings.ContainsRune("*?[", rune(part[0])) && strings.HasPrefix(matchParts[index], ".") {
				hidden = true
				break
			}
		}
		if !hidden {
			kept = append(kept, match)
		}
	}
	return kept
}
