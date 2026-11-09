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
	"path"
	"regexp"
	"slices"
	"strings"
)

// A shell command over maxCommandBytes that white space does not explain has
// no complete reading: its targets are no path facts, so a content rule
// cannot prove what it writes (GAP-0934). OverLimitCommandContentTarget
// reads its text once more, without the shell grammar, for the one thing the
// owner steer keeps blocked in every profile: a protected file named
// directly as the target of a write. The reading over-approximates on
// purpose. It never reads a quote, a comment or a here-document as ending
// anything, so no text can hide a later statement from it; it also reads a
// write written in a quoted string or a comment as a write.

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
		scan := commandWriteScan{text: text, dirs: dirs}
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
	text string
	// dirs are the directories a relative target may be placed in.
	dirs []string
	// vars are the values the text assigns to a variable name, for the names
	// whose value is, or holds, a protected file.
	vars map[string][]string
}

// commandOperand is one word read from a command text; plain is false when
// it depends on the environment.
type commandOperand struct {
	word  string
	plain bool
}

func (s *commandWriteScan) protectedWriteClass() string {
	s.followAssignments()
	text := s.text
	for index := 0; index < len(text); {
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
			for _, name := range scanLastOperandWriters {
				if !hasKeywordAt(text, index, name, true) {
					continue
				}
				operands, after := commandOperands(text, index+len(name))
				if len(operands) >= 2 {
					last := operands[len(operands)-1]
					class = s.classOf(last.word, last.plain)
				}
				next = after
				break
			}
		}
		if class != "" {
			return class
		}
		index = max(next, index+1)
	}
	return ""
}

// followAssignments reads the text once for the variables it assigns a
// protected file or directory (NAME=/etc/ld.so.preload, an assignment
// through an earlier variable included) and for the directories it changes
// to with cd when a protected file lives in them, so that a target written
// through $NAME, or a relative target after cd /etc, is read as the file it
// is. Every assignment and every cd counts, wherever it is in the text: the
// scan reads no grammar, and a later assignment or cd elsewhere does not
// hide the earlier one.
func (s *commandWriteScan) followAssignments() {
	base := append([]string(nil), s.dirs...)
	text := s.text
	for index := 0; index < len(text); {
		next := index + 1
		if name := assignmentNameAt(text, index); name != "" {
			word, after, plain := readCommandWord(text, index+len(name)+1)
			for _, value := range s.expand(word, plain) {
				s.addVariable(name, value)
			}
			next = after
		} else if hasKeywordAt(text, index, "cd", true) {
			operands, after := commandOperands(text, index+len("cd"))
			next = after
			if len(operands) != 0 {
				for _, dir := range s.expand(operands[0].word, operands[0].plain) {
					s.addDirectory(base, dir)
				}
			}
		}
		index = max(next, index+1)
	}
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

func (s *commandWriteScan) addVariable(name, value string) {
	if !strings.HasPrefix(value, "/") {
		return
	}
	value = path.Clean(value)
	if !holdsProtectedFile(value) || slices.Contains(s.vars[name], value) ||
		len(s.vars[name]) >= scanMaxDirs || len(s.vars) >= scanMaxDirs {
		return
	}
	if s.vars == nil {
		s.vars = make(map[string][]string)
	}
	s.vars[name] = append(s.vars[name], value)
}

func (s *commandWriteScan) addDirectory(base []string, word string) {
	candidates := []string{word}
	if !strings.HasPrefix(word, "/") {
		candidates = candidates[:0]
		for _, dir := range base {
			if strings.HasPrefix(dir, "/") {
				candidates = append(candidates, path.Join(dir, word))
			}
		}
	}
	for _, candidate := range candidates {
		candidate = path.Clean(candidate)
		if len(s.dirs) < len(base)+scanMaxDirs && !slices.Contains(s.dirs, candidate) && holdsProtectedFile(candidate) {
			s.dirs = append(s.dirs, candidate)
		}
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
// at index, "" when none does.
func assignmentNameAt(text string, index int) string {
	if index > 0 && isScanWordByte(text[index-1]) {
		return ""
	}
	end := index
	for end < len(text) && (text[end] == 0x5f || text[end] >= 0x41 && text[end] <= 0x5a ||
		text[end] >= 0x61 && text[end] <= 0x7a || end > index && text[end] >= 0x30 && text[end] <= 0x39) {
		end++
	}
	if end == index || end >= len(text) || text[end] != 0x3d {
		return ""
	}
	return text[index:end]
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
// space. A command path (/usr/bin/tee) and a quote before it are word starts.
func hasKeywordAt(text string, index int, keyword string, blankAfter bool) bool {
	if !strings.HasPrefix(text[index:], keyword) || (index > 0 && isScanWordByte(text[index-1])) {
		return false
	}
	end := index + len(keyword)
	return !blankAfter || (end < len(text) && isShellWhiteSpace(text[end]))
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
