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
	"os"
	"path"
	"sort"
	"strings"
	"time"

	"mvdan.cc/sh/v3/syntax"

	"github.com/defenseclaw/defenseclaw/internal/shellparse"
)

const (
	// maxStateGlobMatches bounds the words one pattern may expand to.
	maxStateGlobMatches = 64
	// maxStateGlobDirEntries bounds the names read from one directory.
	maxStateGlobDirEntries = 4096
	// stateGlobBudget bounds the directory reads of one command, far below
	// the hook answer budget (RV-pod2-1).
	stateGlobBudget = 250 * time.Millisecond
)

// StateGlobTwin returns the POSIX reading of command in which every
// unquoted pathname pattern under a .defenseclaw directory is replaced by
// the names it matches on this host, as the shell expands it before the
// command runs (GAP-2496: cp a.txt ~/.defenseclaw/conf*.yaml writes
// config.yaml, while the pattern itself named no state file). Home words
// are first written as the active home. A pattern that matches nothing
// stays as written, as it does in the shell; a leading wildcard does not
// match a name that starts with a dot. Only a pattern that can name the
// active home .defenseclaw tree is expanded, and only that tree is read,
// within stateGlobBudget: a pattern with wildcards above the home
// (ls /*/*/*/*/*/.defenseclaw/x) walked the whole filesystem past the hook
// answer budget (RV-pod2-1). ok is false when no pattern matched.
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
	// A Git Bash call on Windows has a drive home, C:/Users/x: its patterns
	// are placed and read there too (GAP-2573: cp a.txt
	// ~/.defenseclaw/conf*.yaml and ~/.def*/config.yaml wrote config.yaml
	// with no finding on Windows while they blocked on Linux and macOS).
	drive := DriveSlashPath(home + "/")
	source := command
	if !strings.ContainsAny(source, "*?[") || !strings.Contains(source, "/") {
		return "", false
	}
	deadline := time.Now().Add(stateGlobBudget)
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
		if literal && drive {
			pattern = stateDrivePattern(pattern)
		}
		if !literal || !strings.HasPrefix(pattern, "/") && !(drive && DriveSlashPath(pattern)) ||
			!strings.ContainsAny(pattern, "*?[") {
			return false
		}
		matches, complete := stateGlobMatches(pattern, home, deadline)
		if !complete || len(matches) == 0 {
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

// stateGlobMatches expands pattern as the shell does where it can name
// the active home .defenseclaw tree: each component up to the home must
// match the home itself (no directory above it is read), the next one must
// match .defenseclaw, and only directories of that tree are listed. A
// longer listing, more matches or the deadline end the expansion
// (complete is false); the reading then adds nothing.
func stateGlobMatches(pattern, home string, deadline time.Time) (matches []string, complete bool) {
	// A drive home is on a Windows file system, which opens a name spelled
	// in any case (~/.DefenseClaw/conf*.yaml lists the state); a wildcard
	// component is still matched by the shell as written.
	fold := DriveSlashPath(home + "/")
	match := func(pattern, name string) bool {
		if _, literal := stateGlobLiteral(pattern); fold && literal {
			pattern, name = strings.ToLower(pattern), strings.ToLower(name)
		}
		return stateGlobComponentMatch(pattern, name)
	}
	patternParts := strings.Split(pattern, "/")
	homeParts := strings.Split(home, "/")
	stateIndex := len(homeParts)
	if len(patternParts) <= stateIndex {
		return nil, false
	}
	for index, name := range homeParts {
		if !match(patternParts[index], name) {
			return nil, false
		}
	}
	if !match(patternParts[stateIndex], ".defenseclaw") {
		return nil, false
	}
	current := []string{home + "/.defenseclaw"}
	for _, component := range patternParts[stateIndex+1:] {
		if literal, isLiteral := stateGlobLiteral(component); isLiteral {
			for index := range current {
				current[index] += "/" + literal
			}
			continue
		}
		var next []string
		for _, dir := range current {
			if time.Now().After(deadline) {
				return nil, false
			}
			names, listed := stateGlobDirNames(dir)
			if !listed {
				return nil, false
			}
			for _, name := range names {
				if match(component, name) {
					next = append(next, dir+"/"+name)
					if len(next) > maxStateGlobMatches {
						return nil, false
					}
				}
			}
		}
		current = next
	}
	for _, candidate := range current {
		if _, err := os.Lstat(candidate); err == nil {
			matches = append(matches, candidate)
		}
	}
	return matches, true
}

// stateDrivePattern gives the MSYS spelling of a drive path (/c/Users/x)
// its drive form (c:/Users/x), as Git Bash reads it.
func stateDrivePattern(pattern string) string {
	if len(pattern) >= 3 && pattern[0] == '/' && isASCIILetter(pattern[1]) && pattern[2] == '/' {
		return pattern[1:2] + ":" + pattern[2:]
	}
	return pattern
}

// stateGlobComponentMatch matches one path component as the shell does: a
// leading wildcard does not match a name that starts with a dot (dotglob
// is off by default).
func stateGlobComponentMatch(pattern, name string) bool {
	if strings.HasPrefix(name, ".") && pattern != "" && strings.ContainsRune("*?[", rune(pattern[0])) {
		return false
	}
	matched, err := path.Match(pattern, name)
	return err == nil && matched
}

// stateGlobLiteral returns the name a component without an unescaped
// wildcard stands for.
func stateGlobLiteral(component string) (string, bool) {
	var out strings.Builder
	for index := 0; index < len(component); index++ {
		char := component[index]
		if char == 92 && index+1 < len(component) {
			index++
			out.WriteByte(component[index])
			continue
		}
		if char == 42 || char == 63 || char == 91 {
			return "", false
		}
		out.WriteByte(char)
	}
	return out.String(), true
}

// stateGlobDirNames lists a directory (a missing one, or a name that is
// not a directory, has no names; it is never opened, so a FIFO cannot
// block the reading). listed is false for a directory with more than
// maxStateGlobDirEntries names.
func stateGlobDirNames(dir string) (names []string, listed bool) {
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return nil, true
	}
	file, err := os.Open(dir)
	if err != nil {
		return nil, true
	}
	defer file.Close()
	entries, _ := file.ReadDir(maxStateGlobDirEntries + 1)
	if len(entries) > maxStateGlobDirEntries {
		return nil, false
	}
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	return names, true
}
