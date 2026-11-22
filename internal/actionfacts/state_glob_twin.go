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
	"slices"
	"sort"
	"strings"

	"mvdan.cc/sh/v3/syntax"

	"github.com/defenseclaw/defenseclaw/internal/fixturefs"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
	"github.com/defenseclaw/defenseclaw/internal/shellparse"
)

const (
	// maxStateGlobMatches bounds the words one pattern may expand to.
	maxStateGlobMatches = 64
	// maxStateGlobDirEntries bounds the names read from one directory.
	maxStateGlobDirEntries = 4096
	// maxStateGlobWork bounds the work of the directory reads of one
	// command (RV-pod2-1): one unit for each directory listed and each name
	// examined. A directory is listed and charged once per command, however
	// many patterns read it (rel-1-0-10:GAP-1726). It counts work, never time, so the answer does not depend on
	// the load of the box (rel-1-0-10:GAP-0339). It is what the 250 ms time
	// bound it replaces read on an idle box: the widest component (64 folders
	// of 4,000 names, 256,128 units) took 120 ms on the gate box, so about two
	// such components.
	maxStateGlobWork = 1 << 19
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
// within maxStateGlobWork: a pattern with wildcards above the home
// (ls /*/*/*/*/*/.defenseclaw/x) walked the whole filesystem past the hook
// answer budget (RV-pod2-1). ok is false when no pattern matched.
//
// cut holds the caps the reading hit (the one bound rule, DET111 step 2): a
// pattern that matches more than maxStateGlobMatches names is spelled as its
// first maxStateGlobMatches matches and cut has bounded.Items
// (rel-1-0-10:GAP-1017); a folder with more than maxStateGlobDirEntries names
// (bounded.Items) or a command past maxStateGlobWork (bounded.Time, counted
// work) leaves the pattern as written and is in cut too, so a later state
// pattern behind decoys that used up the work is the unknown tier, never a
// silent literal (rel-1-0-10:GAP-1726).
func StateGlobTwin(command, activeHome string) (twin string, ok bool, cut bounded.CapSet) {
	return stateGlobTwin(command, activeHome, nil)
}

// StateGlobTwinNamed is StateGlobTwin for a gateway that may not list the
// user's home (a managed gateway behind ProtectHome, GAP-2544): a pattern
// component directly under .defenseclaw is expanded against stateNames,
// the names of the protected state files and trees, as if each existed; a
// deeper pattern component stays as written, since any name the shell
// writes there (a match or the pattern itself) lies in that tree. Nothing
// is read from the filesystem. A pattern that names no state name adds
// nothing, so cp a.txt ~/.defenseclaw/*.bak keeps its plain reading.
func StateGlobTwinNamed(command, activeHome string, stateNames []string) (twin string, ok bool, cut bounded.CapSet) {
	if len(stateNames) == 0 {
		return "", false, cut
	}
	return stateGlobTwin(command, activeHome, stateNames)
}

func stateGlobTwin(command, activeHome string, stateNames []string) (twin string, ok bool, cut bounded.CapSet) {
	home, _ := normalizeActiveHome(activeHome)
	home = strings.TrimRight(home, "/")
	if home == "" || !posixShellHome(home) || strings.ContainsAny(home, "\x00\r\n") {
		return "", false, cut
	}
	// A Git Bash call on Windows has a drive home, C:/Users/x: its patterns
	// are placed and read there too (GAP-2573: cp a.txt
	// ~/.defenseclaw/conf*.yaml and ~/.def*/config.yaml wrote config.yaml
	// with no finding on Windows while they blocked on Linux and macOS).
	drive := DriveSlashPath(home + "/")
	source := command
	if !strings.ContainsAny(source, "*?[") || !strings.Contains(source, "/") {
		return "", false, cut
	}
	var trunc bounded.Truncated
	reading := stateGlobReading{
		home: home, stateNames: stateNames, trunc: &trunc,
		work: bounded.NewCounter(&trunc, bounded.Time, maxStateGlobWork),
	}
	twin, ok = globWordTwin(source, home, func(pattern string) []string {
		if drive {
			pattern = stateDrivePattern(pattern)
		}
		if !strings.HasPrefix(pattern, "/") && (!drive || !DriveSlashPath(pattern)) {
			return nil
		}
		matches, _ := reading.matches(pattern)
		return matches
	})
	return twin, ok, trunc.Set(&reading.work)
}

// stateGlobReading is the expansion of the state patterns of one command:
// one work counter and one listing per directory, shared by every pattern.
type stateGlobReading struct {
	home       string
	stateNames []string
	trunc      *bounded.Truncated
	work       bounded.Counter
	listings   map[string]stateGlobListing
}

type stateGlobListing struct {
	names  []string
	listed bool
}

// RelativeGlobTwinsNamed returns the POSIX readings of command in which
// every unquoted relative pathname pattern is replaced by one of the names of
// names it may match, as if each existed in the folder the command runs in:
// names are relative spellings (credentials, .ssh/id_rsa, .aws/credentials),
// and a pattern of more components than a name keeps its leading components
// as written (alice/.ssh/id_* may be alice/.ssh/id_rsa). A component is
// matched as the shell matches it (stateGlobComponentMatch: a leading
// wildcard does not select a name that starts with a dot). Reading i spells
// match i of each pattern (its last one when it has fewer), so every reading
// keeps the words of the call (base64 reads one file). It is the reading of a
// call whose folder is not known: nothing is listed, and a gateway judges
// the readings as it judges the literal spellings (rel-1-0-10:GAP-0960). A
// pattern with no literal character in any component (*, */*, ./*) names
// nothing, as the hook-path walk reads a pattern in a folder it cannot list
// (GlobHasLiteral). None when no pattern matched a name.
//
// A pattern that may match more than maxStateGlobMatches names is read as
// its first maxStateGlobMatches matches and the result is truncated
// (bounded.Items, the one bound rule): the caller judges what was read and
// gives the call at least the unknown tier, never "names nothing"
// (rel-1-0-10:GAP-1003).
func RelativeGlobTwinsNamed(command, activeHome string, names []string) RelativeGlobTwins {
	if len(names) == 0 || !strings.ContainsAny(command, "*?[") {
		return RelativeGlobTwins{}
	}
	home, _ := normalizeActiveHome(activeHome)
	home = strings.TrimRight(home, "/")
	if home == "" || !posixShellHome(home) || strings.ContainsAny(home, "\x00\r\n") {
		return RelativeGlobTwins{}
	}
	var trunc bounded.Truncated
	var capped []string
	edits, ok := globWordEdits(command, home, func(pattern string) []string {
		if strings.HasPrefix(pattern, "/") || DriveSlashPath(pattern) {
			// A home word (~, $HOME) or an absolute pattern: its folder is
			// known, so it is no pattern of an unknown folder.
			return nil
		}
		components := strings.Split(strings.TrimSuffix(pattern, "/"), "/")
		if !slices.ContainsFunc(components, func(component string) bool {
			// . and .. are steps between folders, not names.
			return component != "." && component != ".." && GlobHasLiteral(component)
		}) {
			return nil
		}
		var matches []string
		for _, name := range names {
			parts := strings.Split(name, "/")
			lead := len(components) - len(parts)
			if lead < 0 {
				continue
			}
			matched := true
			for index, part := range parts {
				matched = matched && stateGlobComponentMatch(components[lead+index], part)
			}
			if !matched {
				continue
			}
			match := name
			if lead > 0 {
				prefix := slices.Clone(components[:lead])
				for index, component := range prefix {
					if literal, isLiteral := stateGlobLiteral(component); isLiteral {
						prefix[index] = literal
					}
				}
				match = strings.Join(append(prefix, name), "/")
			}
			if slices.Contains(matches, match) {
				continue
			}
			if !trunc.Within(bounded.Items, len(matches)+1, maxStateGlobMatches) {
				capped = append(capped, matches...)
				break
			}
			matches = append(matches, match)
		}
		return matches
	})
	if !ok {
		return RelativeGlobTwins{}
	}
	count := 0
	for _, change := range edits {
		count = max(count, len(change.words))
	}
	twins := make([]string, 0, count)
	for index := range count {
		twins = append(twins, applyGlobWordEdits(command, edits, func(words []string) string {
			return globQuotedWord(words[min(index, len(words)-1)])
		}))
	}
	return RelativeGlobTwins{Twins: twins, Truncated: trunc.Set(), Capped: capped}
}

// RelativeGlobTwins is the reading RelativeGlobTwinsNamed gives a command.
type RelativeGlobTwins struct {
	// Twins are the readings, one per match.
	Twins []string
	// Truncated is bounded.Items when a pattern may match more names than
	// maxStateGlobMatches: Twins spell its first maxStateGlobMatches
	// matches only.
	Truncated bounded.CapSet
	// Capped are the words a capped pattern is read as in Twins, so a caller
	// can tell the operand the cap cut short from the other words.
	Capped []string
}

// globWordEdit is one pathname pattern word of a command (its byte span)
// and the words it is read as.
type globWordEdit struct {
	start, end int
	words      []string
}

// globWordTwin is command with every word that is an unquoted pathname
// pattern (statePatternWord, home for its home words) replaced by all the
// words expand gives for it, each quoted; a pattern expand gives nothing for
// stays as written. ok is false when no word was replaced.
func globWordTwin(source, home string, expand func(pattern string) []string) (string, bool) {
	edits, ok := globWordEdits(source, home, expand)
	if !ok {
		return "", false
	}
	return applyGlobWordEdits(source, edits, func(words []string) string {
		quoted := make([]string, 0, len(words))
		for _, word := range words {
			quoted = append(quoted, globQuotedWord(word))
		}
		return strings.Join(quoted, " ")
	}), true
}

// globWordEdits are the pathname pattern words of source (statePatternWord,
// home for its home words) that expand gives words for, sorted by place, each
// with those words sorted. ok is false when there is none, or the words
// overlap.
func globWordEdits(source, home string, expand func(pattern string) []string) (edits []globWordEdit, ok bool) {
	defer func() {
		if recover() != nil {
			edits, ok = nil, false
		}
	}()
	file, parsed := shellparse.Parse(source)
	if !parsed {
		return nil, false
	}
	syntax.Walk(file, func(node syntax.Node) bool {
		word, isWord := node.(*syntax.Word)
		if !isWord {
			return true
		}
		pattern, literal := statePatternWord(word, home)
		if !literal || !strings.ContainsAny(pattern, "*?[") {
			return false
		}
		matches := expand(pattern)
		if len(matches) == 0 {
			return false
		}
		sort.Strings(matches)
		start, end := int(word.Pos().Offset()), int(word.End().Offset())
		if start >= 0 && end > start && end <= len(source) {
			edits = append(edits, globWordEdit{start: start, end: end, words: matches})
		}
		return false
	})
	if len(edits) == 0 {
		return nil, false
	}
	sort.Slice(edits, func(i, j int) bool { return edits[i].start < edits[j].start })
	for index := 1; index < len(edits); index++ {
		if edits[index].start < edits[index-1].end {
			return nil, false
		}
	}
	return edits, true
}

// applyGlobWordEdits writes source with each edit's span replaced by the
// text spell gives for its words.
func applyGlobWordEdits(source string, edits []globWordEdit, spell func(words []string) string) string {
	var out strings.Builder
	last := 0
	for _, change := range edits {
		out.WriteString(source[last:change.start])
		out.WriteString(spell(change.words))
		last = change.end
	}
	out.WriteString(source[last:])
	return out.String()
}

// globQuotedWord is a word in single quotes, which the shell reads as written.
func globQuotedWord(word string) string {
	return "\x27" + strings.ReplaceAll(word, "\x27", "\x27\\\x27\x27") + "\x27"
}

// GlobHasLiteral reports whether a pattern component keeps a literal
// character outside *, ? and bracket expressions.
func GlobHasLiteral(component string) bool {
	for i := 0; i < len(component); i++ {
		switch component[i] {
		case '*', '?':
		case '\\':
			return true
		case '[':
			if end := strings.IndexByte(component[i+1:], ']'); end >= 0 {
				i += end + 1
				continue
			}
			return true
		default:
			return true
		}
	}
	return false
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

// matches expands pattern as the shell does where it can name the active
// home .defenseclaw tree: each component up to the home must match the home
// itself (no directory above it is read), the next one must match
// .defenseclaw, and only directories of that tree are listed. More than
// maxStateGlobMatches matches keep the first ones (sorted names) and record
// bounded.Items; a longer listing or more work than maxStateGlobWork end the
// expansion (complete is false, the pattern stays as written) and record
// their cap. With stateNames (StateGlobTwinNamed) nothing is read: the
// .defenseclaw directory holds exactly those names and a deeper pattern
// component is kept as written.
func (r *stateGlobReading) matches(pattern string) (matches []string, complete bool) {
	home, stateNames := r.home, r.stateNames
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
	stateRoot := home + "/.defenseclaw"
	current := []string{stateRoot}
	for _, component := range patternParts[stateIndex+1:] {
		if literal, isLiteral := stateGlobLiteral(component); isLiteral {
			for index := range current {
				current[index] += "/" + literal
			}
			continue
		}
		var next []string
	dirs:
		for _, dir := range current {
			var names []string
			switch {
			case stateNames == nil:
				listing, seen := r.listings[dir]
				if !seen {
					if !r.work.Take() {
						return nil, false
					}
					listing.names, listing.listed = stateGlobDirNames(dir)
					if !r.work.TakeN(len(listing.names)) {
						return nil, false
					}
					if r.listings == nil {
						r.listings = make(map[string]stateGlobListing)
					}
					r.listings[dir] = listing
				}
				if !listing.listed {
					r.trunc.Hit(bounded.Items)
					return nil, false
				}
				names = listing.names
			case dir == stateRoot:
				names = stateNames
			default:
				next = append(next, dir+"/"+component)
				continue
			}
			for _, name := range names {
				if match(component, name) {
					if !r.trunc.Within(bounded.Items, len(next)+1, maxStateGlobMatches) {
						break dirs
					}
					next = append(next, dir+"/"+name)
				}
			}
		}
		current = next
	}
	if stateNames != nil {
		return current, true
	}
	for _, candidate := range current {
		if _, err := os.Lstat(fixturefs.Map(candidate)); err == nil {
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
	info, err := os.Stat(fixturefs.Map(dir))
	if err != nil || !info.IsDir() {
		return nil, true
	}
	file, err := os.Open(fixturefs.Map(dir))
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
