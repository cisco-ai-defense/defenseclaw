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
	"encoding/json"
	"maps"
	"path"
	"regexp"
	"slices"
	"strings"
)

// A shell command over maxCommandBytes that white space does not explain has
// no complete reading: its targets are no path facts, so a content rule
// cannot prove what it writes (GAP-0934). OverLimitCommandContentTarget
// reads its text once more for the one thing the owner steer keeps blocked in
// every profile: a protected file named directly as the target of a write.
// The reading over-approximates on purpose. It finds a write wherever the
// text puts one, also in a quoted string, so no quote can hide a later
// statement from it. Where readCommandLayout follows the text with
// certainty it leaves out what the shell does not run (comments, here-
// document bodies that only feed data) and applies a cd or an assignment in
// the order written, so the later replaces the earlier as it does for the
// shell. Otherwise every cd and assignment counts, wherever it is.

// Bytes the scan compares against. Rune literals are avoided so the
// constants read as the shell grammar they stand for.
const (
	scanGreater   = 0x3e
	scanPipe      = 0x7c
	scanAmpersand = 0x26
	scanSingle    = 0x27
	scanDouble    = 0x22
	scanBackslash = 0x5c
	scanTilde     = 0x7e
	scanHash      = 0x23
)

const (
	// scanWordEnd ends a shell word besides white space: statement
	// separators, parentheses, redirections and the backtick.
	scanWordEnd = ";&|()<>\x60"
	// scanDynamicUnquoted and scanDynamicQuoted are the bytes that make a
	// word depend on the environment (expansion, command substitution, a
	// pattern): it names no file the scan can know.
	scanDynamicUnquoted = "$*?[{\x60"
	scanDynamicQuoted   = "$\x60"
	// scanMaxDirs bounds the directories followed through cd. Only a
	// directory that holds a protected file counts, so padding with other
	// directories never reaches the bound.
	scanMaxDirs = 64
)

var (
	// scanLastOperandWriters are the commands whose last operand is a file
	// written; tee writes every operand and dd names its target as of=.
	scanLastOperandWriters = []string{"cp", "mv", "install", "ln"}
	// scanDirProbes are file names that, joined to a directory, tell whether
	// the directory holds a protected file.
	scanDirProbes = []string{"x", "x.sh", "ld.so.preload", "passwd", "sudoers", "daemon.json"}
)

// OverLimitCommandContentTarget reports a limit-exceeded shell command that
// has no bounded twin and whose text names, as the target of a write, a file
// a content rule judges by its text (contentRuleWriteTarget), and that file
// class. The write is a redirection, tee, dd of=, or the last operand of
// cp, mv, install or ln, in the command text, with a relative name placed
// in the working directory or in a directory it was followed to by cd. The
// path is read as the shell reads it after quote removal and normalization.
// A target that depends on the environment (a substitution, a pattern, a
// variable the text does not assign a protected file or directory) is no
// target: it is not a protected file named directly. Callers
// take the conservative finding of the class where the call is
// enforcement-capable (GAP-0934).
func OverLimitCommandContentTarget(input Input, facts Facts) (string, bool) {
	if facts.Parse.Status != StatusLimitExceeded || StructuredWriteTool(input.Tool) ||
		len(input.Args) > maxOverLimitWriteArgsBytes {
		return "", false
	}
	if _, bounded := OverLimitCommandBoundedTwin(input, facts); bounded {
		return "", false
	}
	texts, dirs := overLimitCommandTexts(input)
	for _, text := range texts {
		scan := commandWriteScan{text: text, dirs: slices.Clone(dirs)}
		if class := scan.protectedWriteClass(); class != "" {
			return class, true
		}
	}
	return "", false
}

// overLimitCommandTexts are the strings of a command call (its command, its
// argv and every string of its arguments) and its working directories.
func overLimitCommandTexts(input Input) ([]string, []string) {
	texts := make([]string, 0, 1+len(input.Argv))
	dirs := []string{input.CWD}
	if input.Command != "" {
		texts = append(texts, input.Command)
	}
	texts = append(texts, input.Argv...)
	var decoded any
	if len(input.Args) != 0 && json.Unmarshal(input.Args, &decoded) == nil {
		if object, ok := decoded.(map[string]any); ok {
			for _, key := range []string{"workdir", "cwd", "working_directory"} {
				if dir, ok := object[key].(string); ok {
					dirs = append(dirs, dir)
				}
			}
		}
		texts = appendJSONStrings(texts, decoded, 0)
	}
	return texts, dirs
}

func appendJSONStrings(texts []string, value any, depth int) []string {
	if depth > maxJSONDepth {
		return texts
	}
	switch value := value.(type) {
	case string:
		texts = append(texts, value)
	case []any:
		for _, element := range value {
			texts = appendJSONStrings(texts, element, depth+1)
		}
	case map[string]any:
		for _, element := range value {
			texts = appendJSONStrings(texts, element, depth+1)
		}
	}
	return texts
}

// commandWriteScan reads one command text for writes to protected files.
type commandWriteScan struct {
	text   string
	layout commandLayout
	// base are the directories the call starts in; dirs are the directories
	// a relative target may be placed in at the point read.
	base []string
	dirs []string
	// previous are the directories the last cd left.
	previous []string
	// vars are the values the text assigns to a variable name, for the names
	// whose value is, or holds, a protected file.
	vars map[string][]string
	// watched are the names some braced expansion of the text may assign
	// (${NAME:=word}): whatever the text assigns them is kept, an ordinary
	// value too, because the expansion assigns only when the name holds none.
	// definite are the watched names the main shell has given a value in the
	// order written (a sequential text): a value set under a condition, in a
	// pipeline or in the background may not be there, so it does not stop the
	// expansion. Never changed in place: a scope keeps the map it opened with.
	watched  map[string]bool
	definite map[string]bool
	// open are the command substitutions and backticks the read is inside:
	// what the directories and values were when each opened, taken back at its
	// close, as a subshell leaves the shell around it as it was. next is the
	// first scope of the layout not opened yet. sharedVars is true while vars
	// is also held by an open scope, so a change copies it first.
	open       []scanScope
	next       int
	sharedVars bool
}

// scanScope is the state a command substitution or backtick opened with.
type scanScope struct {
	end      int
	dirs     []string
	previous []string
	vars     map[string][]string
	shared   bool
	definite map[string]bool
}

// commandOperand is one word read from a command text; plain is false when
// it depends on the environment.
type commandOperand struct {
	word  string
	plain bool
}

func (s *commandWriteScan) protectedWriteClass() string {
	if layout, readable := readCommandLayout(s.text); readable {
		s.layout = layout
	}
	s.base = slices.Clone(s.dirs)
	s.watchExpansions()
	if !s.layout.sequential {
		// Every cd and assignment counts wherever it is. The second reading
		// sees a relative value against the directories the first followed to.
		s.followAssignments()
		s.followAssignments()
	}
	var skipCursor, quotedCursor int
	for index := 0; index < len(s.text); {
		s.syncScopes(index)
		if end := spanEnd(s.layout.skipped, &skipCursor, index); end > index {
			s.followBraced(index, end)
			index = end
			continue
		}
		text := s.readableText(&quotedCursor, index)
		class, next := "", index+1
		switch {
		case text[index] == scanGreater:
			end := index + 1
			for end < len(text) && (text[end] == scanGreater || text[end] == scanPipe || text[end] == scanAmpersand) {
				end++
			}
			word, after, plain := readCommandWord(text, skipBlanks(text, end))
			class, next = s.classOf(word, plain), after
		case hasKeywordAt(text, index, "of=", false):
			word, after, plain := readCommandWord(text, index+len("of="))
			class, next = s.classOf(word, plain), after
		case hasKeywordAt(text, index, "tee", true):
			operands, after := commandOperands(text, index+len("tee"))
			for _, operand := range operands {
				if class = s.classOf(operand.word, operand.plain); class != "" {
					break
				}
			}
			next = after
		default:
			matched := false
			for _, name := range scanLastOperandWriters {
				if !hasKeywordAt(text, index, name, true) {
					continue
				}
				operands, after := commandOperands(text, index+len(name))
				if len(operands) >= 2 {
					last := operands[len(operands)-1]
					class = s.classOf(last.word, last.plain)
				}
				next, matched = after, true
				break
			}
			if !matched && s.layout.sequential {
				next = s.followStatement(text, index)
			}
		}
		if class != "" {
			return class
		}
		index = codeStartIn(text, index+1, max(next, index+1))
	}
	return ""
}

// syncScopes closes the scopes that end at or before index, taking back the
// directories and values they opened with, and opens those that start at or
// before it. A scope the read jumped over whole is not opened.
func (s *commandWriteScan) syncScopes(index int) {
	for n := len(s.open); n > 0 && s.open[n-1].end <= index; n = len(s.open) {
		saved := s.open[n-1]
		s.dirs, s.previous, s.vars, s.sharedVars, s.definite = saved.dirs, saved.previous, saved.vars, saved.shared, saved.definite
		s.open = s.open[:n-1]
	}
	for s.next < len(s.layout.scopes) && s.layout.scopes[s.next].start <= index {
		span := s.layout.scopes[s.next]
		s.next++
		if span.end > index {
			s.open = append(s.open, scanScope{span.end, s.dirs, s.previous, s.vars, s.sharedVars, s.definite})
			s.sharedVars = true
		}
	}
}

// ownVars makes vars safe to change: it is copied while an open scope also
// holds it.
func (s *commandWriteScan) ownVars() {
	if s.sharedVars {
		s.vars, s.sharedVars = maps.Clone(s.vars), false
	}
	if s.vars == nil {
		s.vars = make(map[string][]string)
	}
}

// followAssignments reads the text once for the variables it assigns a
// protected file or directory (NAME=/etc/ld.so.preload, an assignment
// through an earlier variable included) and for the directories it changes
// to with cd when a protected file lives in them, so that a target written
// through $NAME, or a relative target after cd /etc, is read as the file it
// is. It is the reading of a text whose order of statements is not known:
// every assignment and every cd counts, wherever it is, and a later one does
// not hide the earlier one.
func (s *commandWriteScan) followAssignments() {
	var skipCursor, quotedCursor int
	for index := 0; index < len(s.text); {
		if end := spanEnd(s.layout.skipped, &skipCursor, index); end > index {
			s.followBraced(index, end)
			index = end
			continue
		}
		text := s.readableText(&quotedCursor, index)
		index = codeStartIn(text, index+1, max(s.followStatement(text, index), index+1))
	}
}

// followBraced applies the assigning braced expansions written in the skipped
// text from start to end.
func (s *commandWriteScan) followBraced(start, end int) {
	for index := start; index < end; index++ {
		if s.text[index] == shellDollar {
			s.followBracedAssignment(s.text, index)
		}
	}
}

// watchExpansions finds the names the braced expansions of the text assign.
func (s *commandWriteScan) watchExpansions() {
	for index := 0; index < len(s.text); index++ {
		if s.text[index] != shellDollar || !s.layout.expandsAt(index) {
			continue
		}
		if name, _, _, ok := bracedAssignmentAt(s.text, index); ok {
			if s.watched == nil {
				s.watched = make(map[string]bool)
			}
			s.watched[name] = true
		}
	}
}

// followBracedAssignment adds the value of the assigning braced expansion at
// index (${NAME=word}, ${NAME:=word}) to those its variable may hold, when the
// shell expands it there and the variable holds no value at that point: the
// expansion sets a variable that is unset (${NAME:=word}: or empty) and never
// replaces a value, and one in a single quote, after a backslash, in a
// comment or in quoted here-document data sets nothing.
func (s *commandWriteScan) followBracedAssignment(text string, index int) {
	name, start, end, ok := bracedAssignmentAt(text, index)
	if !ok || !s.layout.expandsAt(index) || s.holdsValue(name, start >= 2 && text[start-2] == ':') {
		return
	}
	word, _, plain := readCommandWord(text[:end], start)
	for _, value := range s.expand(word, plain) {
		s.addVariable(name, value)
	}
	if s.layout.sequential && s.layout.bracedStraight[index] && s.watched[name] {
		// The name holds a value from here on, one the scan may not read.
		if _, assigned := s.vars[name]; !assigned {
			s.ownVars()
			s.vars[name] = []string{}
		}
		s.setDefinite(name, true)
	}
}

// setDefinite records whether the main shell has given a watched name a value
// at this point in the order written.
func (s *commandWriteScan) setDefinite(name string, on bool) {
	if s.definite[name] == on {
		return
	}
	next := maps.Clone(s.definite)
	if next == nil {
		next = make(map[string]bool)
	}
	if on {
		next[name] = true
	} else {
		delete(next, name)
	}
	s.definite = next
}

// holdsValue reports whether the text has given a variable a value at this
// point: any value, or, with empty, one that is not empty. A name assigned a
// value the scan cannot read (a substitution) holds one. In a sequential text
// only a value the main shell set in the order written counts: an assignment
// under a condition may not have run, so the expansion still assigns.
func (s *commandWriteScan) holdsValue(name string, nonEmpty bool) bool {
	values, assigned := s.vars[name]
	if !assigned || s.layout.sequential && !s.definite[name] {
		return false
	}
	return !nonEmpty || len(values) == 0 || slices.ContainsFunc(values, func(value string) bool { return value != "" })
}

// markAssigned records that a watched name was assigned a value the scan
// cannot read.
func (s *commandWriteScan) markAssigned(name string) {
	if _, assigned := s.vars[name]; !assigned && s.watched[name] {
		s.ownVars()
		s.vars[name] = []string{}
	}
}

// readableText is the text a read that starts at index may use: all of it,
// and, for a command written inside a quoted word, up to the end of that word.
func (s *commandWriteScan) readableText(cursor *int, index int) string {
	if end := spanEnd(s.layout.quoted, cursor, index); end > index {
		return s.text[:end]
	}
	return s.text
}

// followStatement applies the assignment or the cd that starts at index and
// returns the index after it (index+1 when none starts there). One that the
// layout reads as running in the main shell in the order written replaces
// the value or the directories (a sequential text only); any other adds to
// them.
func (s *commandWriteScan) followStatement(text string, index int) int {
	if text[index] == shellDollar {
		s.followBracedAssignment(text, index)
		return index + 1
	}
	straight := s.layout.sequential && s.layout.straight[index]
	if name := assignmentNameAt(text, index); name != "" && s.layout.assignsAt(index) {
		word, after, plain := readCommandWord(text, index+len(name)+1)
		readings := s.expand(word, plain)
		if straight {
			s.setVariable(name, readings)
		} else {
			for _, value := range readings {
				s.addVariable(name, value)
			}
			if len(readings) == 0 {
				s.markAssigned(name)
			}
		}
		return max(after, index+1)
	}
	if straight && hasKeywordAt(text, index, "unset", true) {
		// A name unset in the order written holds no value any more.
		operands, after := commandOperands(text, index+len("unset"))
		for _, operand := range operands {
			if _, assigned := s.vars[operand.word]; assigned && operand.plain {
				s.ownVars()
				delete(s.vars, operand.word)
				s.setDefinite(operand.word, false)
			}
		}
		return max(after, index+1)
	}
	if hasKeywordAt(text, index, "pushd", true) {
		// pushd keeps the directory it leaves on a stack: it only adds.
		operands, after := commandOperands(text, index+len("pushd"))
		if len(operands) != 0 {
			for _, dir := range s.expand(operands[0].word, operands[0].plain) {
				s.addDirectory(dir)
			}
		}
		return max(after, index+1)
	}
	if hasKeywordAt(text, index, "cd", true) {
		operands, after := commandOperands(text, index+len("cd"))
		readings := s.vars["HOME"]
		if len(operands) != 0 {
			readings = s.expand(operands[0].word, operands[0].plain)
		}
		if straight && len(operands) <= 1 {
			s.changeDirectory(readings)
		} else {
			for _, dir := range readings {
				s.addDirectory(dir)
			}
		}
		return max(after, index+1)
	}
	return index + 1
}

// holdsProtectedFile reports whether an absolute path is a protected file,
// or a directory that holds one.
func holdsProtectedFile(value string) bool {
	if contentRuleWriteTarget(value) != "" {
		return true
	}
	for _, probe := range scanDirProbes {
		if contentRuleWriteTarget(path.Join(value, probe)) != "" {
			return true
		}
	}
	return false
}

// addVariable adds a value a variable may hold: an absolute path that is, or
// holds, a protected file, or a relative one that is, or holds, a protected
// file in a directory the text works in; any value of a watched name.
func (s *commandWriteScan) addVariable(name, value string) {
	if strings.HasPrefix(value, "/") {
		value = path.Clean(value)
	}
	if !s.watched[name] && !s.valueMatters(value) {
		return
	}
	if slices.Contains(s.vars[name], value) || len(s.vars[name]) >= scanMaxDirs {
		return
	}
	s.ownVars()
	s.vars[name] = append(s.vars[name], value)
}

// valueMatters reports whether a value is, or holds, a protected file.
func (s *commandWriteScan) valueMatters(value string) bool {
	if strings.HasPrefix(value, "/") {
		return holdsProtectedFile(value)
	}
	return s.relativeValueMatters(value)
}

func (s *commandWriteScan) relativeValueMatters(value string) bool {
	if value == "" {
		return false
	}
	for _, dir := range s.dirs {
		if strings.HasPrefix(dir, "/") && holdsProtectedFile(path.Join(dir, value)) {
			return true
		}
	}
	return false
}

// setVariable replaces what a variable holds: the shell has the value of the
// last assignment, whatever the variable held before.
func (s *commandWriteScan) setVariable(name string, values []string) {
	s.ownVars()
	delete(s.vars, name)
	if s.watched[name] {
		s.vars[name] = []string{}
		s.setDefinite(name, true)
	}
	for _, value := range values {
		if strings.HasPrefix(value, "/") {
			value = path.Clean(value)
		}
		if len(s.vars[name]) >= scanMaxDirs {
			return
		}
		if !slices.Contains(s.vars[name], value) {
			s.vars[name] = append(s.vars[name], value)
		}
	}
}

// resolveDirectory is the directories a cd word names from the directories
// the text works in.
func (s *commandWriteScan) resolveDirectory(word string) []string {
	if strings.HasPrefix(word, "/") {
		return []string{path.Clean(word)}
	}
	var resolved []string
	for _, dir := range s.dirs {
		if strings.HasPrefix(dir, "/") {
			resolved = append(resolved, path.Join(dir, word))
		}
	}
	return resolved
}

// addDirectory adds a directory the text may work in when a protected file
// lives in it.
func (s *commandWriteScan) addDirectory(word string) {
	for _, candidate := range s.resolveDirectory(word) {
		if len(s.dirs) < len(s.base)+scanMaxDirs && !slices.Contains(s.dirs, candidate) && holdsProtectedFile(candidate) {
			s.dirs = append(s.dirs, candidate)
		}
	}
}

// changeDirectory makes the directories a cd word names the ones the text
// works in; cd - names both the ones it leaves and the ones it left before.
// A word that names none the scan knows (an unknown variable, no HOME) leaves
// them as they are.
func (s *commandWriteScan) changeDirectory(words []string) {
	var next []string
	add := func(dir string) {
		if !slices.Contains(next, dir) {
			next = append(next, dir)
		}
	}
	for _, word := range words {
		switch word {
		case "":
			return
		case "-":
			for _, dir := range append(slices.Clone(s.previous), s.dirs...) {
				add(dir)
			}
		default:
			for _, dir := range s.resolveDirectory(word) {
				add(dir)
			}
		}
	}
	if len(next) != 0 {
		s.previous, s.dirs = s.dirs, next[:min(len(next), len(s.base)+scanMaxDirs)]
	}
}

// variablePrefix finds the variable a word starts with.
var variablePrefix = regexp.MustCompile(`^\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))`)

// expand is the readings of a word: itself when it is plain, and, when it
// starts with a variable the text assigns a protected file or directory
// and holds nothing else dynamic, one reading per value. Nil for any other
// word that depends on the environment.
func (s *commandWriteScan) expand(word string, plain bool) []string {
	if plain {
		return []string{word}
	}
	match := variablePrefix.FindStringSubmatch(word)
	if match == nil {
		return nil
	}
	rest := word[len(match[0]):]
	if strings.ContainsAny(rest, scanDynamicUnquoted) {
		return nil
	}
	name := match[1] + match[2]
	readings := make([]string, 0, len(s.vars[name]))
	for _, value := range s.vars[name] {
		readings = append(readings, value+rest)
	}
	return readings
}

// assignmentNameAt is the name of a variable assignment (NAME=) that starts
// at index, "" when none does. The name in ${NAME=word} is no assignment
// statement: bracedAssignmentAt reads it.
func assignmentNameAt(text string, index int) string {
	if index > 0 && isScanWordByte(text[index-1]) || strings.HasSuffix(text[:index], "${") {
		return ""
	}
	end := nameEnd(text, index)
	if end == index || end >= len(text) || text[end] != 0x3d {
		return ""
	}
	return text[index:end]
}

// nameEnd is the index after the variable name that starts at index; index
// when none does.
func nameEnd(text string, index int) int {
	end := index
	for end < len(text) && (text[end] == 0x5f || text[end] >= 0x41 && text[end] <= 0x5a ||
		text[end] >= 0x61 && text[end] <= 0x7a || end > index && text[end] >= 0x30 && text[end] <= 0x39) {
		end++
	}
	return end
}

// maxBracedAssignment bounds how far the closing brace of an assigning braced
// expansion is looked for, so a text of unclosed ones is read in linear time.
const maxBracedAssignment = 4096

// bracedAssignmentAt reads the assigning braced expansion that starts at
// index: ${NAME=word}, ${NAME:=word} or ${NAME[subscript]=word}. It returns
// the name, the index where the word starts and the index of the first closing
// brace after it; false for any other expansion or one that does not close
// within maxBracedAssignment bytes.
func bracedAssignmentAt(text string, index int) (name string, wordStart, closeAt int, ok bool) {
	if !strings.HasPrefix(text[index:], "${") {
		return "", 0, 0, false
	}
	window := text[:min(len(text), index+maxBracedAssignment)]
	end := nameEnd(window, index+2)
	if end == index+2 {
		return "", 0, 0, false
	}
	name = text[index+2 : end]
	if end < len(window) && window[end] == '[' {
		subscript := strings.IndexByte(window[end:], ']')
		if subscript < 0 {
			return "", 0, 0, false
		}
		end += subscript + 1
	}
	switch {
	case strings.HasPrefix(window[end:], ":="):
		wordStart = end + 2
	case end < len(window) && window[end] == '=':
		wordStart = end + 1
	default:
		return "", 0, 0, false
	}
	closed := strings.IndexByte(window[wordStart:], shellCloseBrace)
	if closed < 0 {
		return "", 0, 0, false
	}
	return name, wordStart, wordStart + closed, true
}

// codeStartIn is the index of the first command substitution, backtick or
// assigning braced expansion that starts in text from start to end, outside
// single quotes; end when none does. A scan that read a word whole resumes
// there, so the code a quoted word holds is read as the code outside it is.
func codeStartIn(text string, start, end int) int {
	double := false
	for index := start; index < end; index++ {
		switch text[index] {
		case scanBackslash:
			index++
		case scanDouble:
			double = !double
		case scanSingle:
			if !double {
				if close := strings.IndexByte(text[index+1:], scanSingle); close >= 0 {
					index += close + 1
				}
			}
		case shellBacktick:
			return index
		case shellDollar:
			if index+1 < len(text) && text[index+1] == shellOpenParen {
				return index
			}
			if _, _, _, ok := bracedAssignmentAt(text, index); ok {
				return index
			}
		}
	}
	return end
}

// classOf is the content-rule class of the file a write word names, ""
// when the word depends on the environment or names an ordinary file.
func (s *commandWriteScan) classOf(word string, plain bool) string {
	for _, reading := range s.expand(word, plain) {
		if reading == "" {
			continue
		}
		if strings.HasPrefix(reading, "/") {
			if class := contentRuleWriteTarget(path.Clean(reading)); class != "" {
				return class
			}
			continue
		}
		for _, dir := range s.dirs {
			if !strings.HasPrefix(dir, "/") {
				continue
			}
			if class := contentRuleWriteTarget(path.Join(dir, reading)); class != "" {
				return class
			}
		}
	}
	return ""
}

// isScanWordByte is a byte that continues a command name: a name that only
// ends in one (a path component, an option) is no such command.
func isScanWordByte(c byte) bool {
	return c >= 0x30 && c <= 0x39 || c >= 0x41 && c <= 0x5a || c >= 0x61 && c <= 0x7a ||
		c == 0x5f || c == 0x2d || c == 0x2e
}

// hasKeywordAt reports whether keyword starts at index as a word of its own:
// not the end of a longer name, and, with blankAfter, followed by white
// space, the end of the word (a separator or redirection) or the end of the
// text. A command path (/usr/bin/tee) and a quote before it are word starts.
func hasKeywordAt(text string, index int, keyword string, blankAfter bool) bool {
	if !strings.HasPrefix(text[index:], keyword) || (index > 0 && isScanWordByte(text[index-1])) {
		return false
	}
	end := index + len(keyword)
	return !blankAfter || end >= len(text) || isShellWhiteSpace(text[end]) || strings.IndexByte(scanWordEnd, text[end]) >= 0
}

// skipBlanks skips blanks, tabs and line continuations.
func skipBlanks(text string, index int) int {
	for index < len(text) {
		switch {
		case text[index] == shellSpace || text[index] == shellTab:
			index++
		case text[index] == scanBackslash && index+1 < len(text) && text[index+1] == shellNewline:
			index += 2
		default:
			return index
		}
	}
	return index
}

// commandOperands are the words after a command name up to the end of its
// statement or comment, without the options (words that start with a dash),
// and the index where the statement ends.
func commandOperands(text string, index int) ([]commandOperand, int) {
	var operands []commandOperand
	for {
		index = skipBlanks(text, index)
		// An unquoted hash starts a comment: its words are no operands.
		if index >= len(text) || text[index] == shellNewline || text[index] == scanHash ||
			strings.IndexByte(scanWordEnd, text[index]) >= 0 {
			return operands, index
		}
		word, next, plain := readCommandWord(text, index)
		if next <= index {
			return operands, index
		}
		if !plain || !strings.HasPrefix(word, "-") || word == "-" {
			operands = append(operands, commandOperand{word: word, plain: plain})
		}
		index = next
	}
}

// readCommandWord reads the shell word at index as the shell reads it after
// quote removal; plain is false when it holds an expansion, a command
// substitution, a pattern or a tilde, so names no file the scan can know.
// It stops at white space or a statement or redirection character.
func readCommandWord(text string, index int) (word string, next int, plain bool) {
	var out strings.Builder
	plain = true
	start := index
	for index < len(text) {
		c := text[index]
		if isShellWhiteSpace(c) || strings.IndexByte(scanWordEnd, c) >= 0 {
			break
		}
		switch c {
		case scanSingle:
			end := strings.IndexByte(text[index+1:], scanSingle)
			if end < 0 {
				out.WriteString(text[index+1:])
				return out.String(), len(text), plain
			}
			out.WriteString(text[index+1 : index+1+end])
			index += end + 2
		case scanDouble:
			index++
			for index < len(text) && text[index] != scanDouble {
				if text[index] == scanBackslash && index+1 < len(text) && strings.IndexByte(scanDynamicQuoted+"\"\\", text[index+1]) >= 0 {
					index++
				} else if strings.IndexByte(scanDynamicQuoted, text[index]) >= 0 {
					plain = false
				}
				out.WriteByte(text[index])
				index++
			}
			index++
		case scanBackslash:
			if index+1 < len(text) && text[index+1] != shellNewline {
				out.WriteByte(text[index+1])
			}
			index += 2
		default:
			if strings.IndexByte(scanDynamicUnquoted, c) >= 0 || (c == scanTilde && index == start) {
				plain = false
			}
			out.WriteByte(c)
			index++
		}
	}
	return out.String(), min(index, len(text)), plain
}
