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
	"slices"
	"strings"
)

// A command text over maxCommandBytes whose padding is data has no bounded
// twin, so OverLimitCommandContentTarget reads it once more without the full
// grammar (GAP-0934). This file is the part of that reading that follows the
// shell grammar where it can do so with certainty: where the text puts its
// quotes, comments and here-document bodies, and which statements run in the
// main shell in the order written. It gives the reading three facts:
//
//   - skipped: comments, the bodies of here-documents that only feed data to
//     a command that reads data (cat, tee...), and the quoted words that are
//     the text an echo or a printf prints. Their lines are no command.
//   - quoted: the words that hold a quote. A command written inside one ends
//     with it: a read of its operands never runs on into the statements that
//     follow the closing quote.
//   - straight: the cd and variable-assignment statements that run in the
//     main shell, after the statement before and before the statement after
//     (separated by ";" or a line break only, no redirect), so the later one
//     replaces the earlier, as the shell and the small-command analysis read
//     them.
//   - sequential: the text has no group, subshell, function, loop, trap or
//     alias, so no statement runs later or elsewhere than it is written.
//
// A construct this reading does not follow (a command substitution, a
// parameter expansion beyond ${NAME}, arithmetic, a backtick, ANSI-C
// quoting, process substitution, an unterminated quote) makes the whole
// layout unknown: the caller then reads the text as before, every cd and
// assignment counting wherever it is, nothing skipped.

type textSpan struct{ start, end int }

type commandLayout struct {
	skipped    []textSpan
	quoted     []textSpan
	straight   map[int]bool
	sequential bool
}

// spanEnd is the end of the span that holds index, index when none does.
// cursor remembers the span reached, as index only grows.
func spanEnd(spans []textSpan, cursor *int, index int) int {
	for *cursor < len(spans) && spans[*cursor].end <= index {
		*cursor++
	}
	if *cursor < len(spans) && spans[*cursor].start <= index {
		return spans[*cursor].end
	}
	return index
}

// layoutDataReaders are the commands that read their standard input as data
// and run none of it. A here-document that feeds only these is data; one
// that feeds any other command (a shell, an interpreter, a loop) may be code,
// and the reading then keeps it as text.
var layoutDataReaders = map[string]bool{
	"cat": true, "tee": true, "tr": true, "cut": true, "sort": true, "uniq": true,
	"head": true, "tail": true, "wc": true, "grep": true, "egrep": true, "fgrep": true,
	"base64": true, "od": true, "xxd": true, "md5sum": true, "sha1sum": true,
	"sha256sum": true, "cksum": true, "nl": true, "fold": true, "paste": true,
	"rev": true, "tac": true, "read": true, "true": true, "false": true, ":": true,
	"echo": true, "printf": true,
}

// layoutTextCommands are the commands whose quoted arguments are text they
// print, search or count, never code and never a file they write.
var layoutTextCommands = map[string]bool{
	"echo": true, "printf": true, ":": true, "true": true, "false": true,
	"grep": true, "egrep": true, "fgrep": true, "cat": true, "head": true,
	"tail": true, "wc": true, "tr": true, "cut": true,
}

// layoutReserved are the first words of a statement that open a construct
// whose statements do not run once, in order, in the main shell.
var layoutReserved = map[string]bool{
	"if": true, "then": true, "else": true, "elif": true, "fi": true, "for": true,
	"while": true, "until": true, "do": true, "done": true, "case": true,
	"esac": true, "select": true, "function": true, "coproc": true, "time": true,
	"trap": true, "alias": true, "{": true, "}": true, "!": true, "[[": true,
}

// layoutDeclarations are the builtins whose assignment words set shell
// variables like a bare assignment does.
var layoutDeclarations = map[string]bool{
	"export": true, "readonly": true, "declare": true, "local": true, "typeset": true,
}

type layoutWord struct {
	start, end int
	literal    string
	// plain is false when the word holds a quote, an escape or an expansion;
	// quoted when it holds a quote.
	plain, quoted bool
	assign        bool
}

type layoutDocument struct {
	delimiter string
	stripTabs bool
}

type layoutReader struct {
	text   string
	layout commandLayout
	// words and redirected are the statement being read; before is the
	// separator that ended the statement before it.
	words      []layoutWord
	redirected bool
	before     string
	// target is set after a redirection operator: the next word is its file.
	target bool
	// documents, commands and grouped are the here-documents opened on the
	// logical line being read, the command word of each statement on it, and
	// whether it holds a group or subshell.
	documents []layoutDocument
	commands  []string
	grouped   bool
}

// readCommandLayout reads the layout of a command text; false when the text
// holds a construct the reading does not follow.
func readCommandLayout(text string) (commandLayout, bool) {
	r := &layoutReader{
		text:   text,
		layout: commandLayout{straight: map[int]bool{}, sequential: true},
		before: "start",
	}
	for index := 0; index < len(text); {
		c := text[index]
		switch {
		case c == shellSpace || c == shellTab:
			index++
		case c == shellBackslash && index+1 < len(text) && text[index+1] == shellNewline:
			index += 2
		case c == shellNewline:
			r.endStatement("\n")
			index = r.readDocuments(index + 1)
		case c == shellHash:
			end := strings.IndexByte(text[index:], shellNewline)
			if end < 0 {
				end = len(text) - index
			}
			r.layout.skipped = append(r.layout.skipped, textSpan{index, index + end})
			index += end
		case c == ';':
			index++
			if index < len(text) && (text[index] == ';' || text[index] == '&') {
				r.layout.sequential = false
				index++
			}
			r.endStatement(";")
		case c == '&' && index+1 < len(text) && text[index+1] == '&':
			r.endStatement("&&")
			index += 2
		case c == '&' && index+1 < len(text) && text[index+1] == '>':
			index = r.redirect(index, 2)
		case c == '&':
			r.endStatement("&")
			index++
		case c == '|':
			index++
			if index < len(text) && (text[index] == '|' || text[index] == '&') {
				index++
				r.endStatement("||")
			} else {
				r.endStatement("|")
			}
		case c == '(' || c == ')':
			r.layout.sequential, r.grouped = false, true
			r.endStatement("(")
			index++
		case c == '<' || c == '>':
			next, ok := r.operator(index)
			if !ok {
				return commandLayout{}, false
			}
			index = next
		default:
			word, next, ok := readLayoutWord(text, index)
			if !ok {
				return commandLayout{}, false
			}
			r.addWord(word, next)
			index = next
		}
	}
	r.endStatement("EOF")
	slices.SortFunc(r.layout.skipped, func(a, b textSpan) int { return a.start - b.start })
	return r.layout, true
}

// redirect consumes a redirection operator of length n at index and the
// ones that follow it (">>", ">|", ">&", "<&", "<>").
func (r *layoutReader) redirect(index, n int) int {
	index += n
	if index < len(r.text) && strings.IndexByte(">|&", r.text[index]) >= 0 {
		index++
	}
	r.redirected, r.target = true, true
	return index
}

// operator reads the redirection that starts at index. A here-document opens
// a body that readDocuments reads at the next line break; a herestring and
// the other redirections only name a file or a word. false for a process
// substitution or a here-document with no delimiter.
func (r *layoutReader) operator(index int) (int, bool) {
	text := r.text
	if index+1 < len(text) && text[index+1] == '(' {
		return 0, false
	}
	if !strings.HasPrefix(text[index:], "<<") || strings.HasPrefix(text[index:], "<<<") {
		if strings.HasPrefix(text[index:], "<<<") {
			r.redirected, r.target = true, true
			return index + 3, true
		}
		return r.redirect(index, 1), true
	}
	start := index + 2
	stripTabs := start < len(text) && text[start] == shellDash
	if stripTabs {
		start++
	}
	for start < len(text) && (text[start] == shellSpace || text[start] == shellTab) {
		start++
	}
	delimiter, end, ok := heredocDelimiter(text, start)
	if !ok || end == start {
		return 0, false
	}
	r.documents = append(r.documents, layoutDocument{delimiter: delimiter, stripTabs: stripTabs})
	r.redirected = true
	return end, true
}

// addWord adds a word to the statement: the file of a redirection and a
// file descriptor number before one are no words of the command.
func (r *layoutReader) addWord(word layoutWord, next int) {
	switch {
	case r.target:
		r.target = false
	case word.plain && isDigits(word.literal) && next < len(r.text) && (r.text[next] == '<' || r.text[next] == '>'):
	default:
		if word.plain && (word.literal == "{" || word.literal == "}") {
			r.layout.sequential, r.grouped = false, true
		}
		if word.quoted {
			r.layout.quoted = append(r.layout.quoted, textSpan{word.start, next})
		}
		r.words = append(r.words, word)
	}
}

func isDigits(value string) bool {
	for index := 0; index < len(value); index++ {
		if value[index] < '0' || value[index] > '9' {
			return false
		}
	}
	return value != ""
}

// endStatement closes the statement being read; term is the separator that
// ends it.
func (r *layoutReader) endStatement(term string) {
	words, redirected, before := r.words, r.redirected, r.before
	r.words, r.redirected, r.target = nil, false, false
	if len(words) == 0 && !redirected {
		if term != ";" && term != "\n" && term != "EOF" {
			r.before = term
		}
		return
	}
	r.before = term
	first := 0
	for first < len(words) && words[first].assign {
		first++
	}
	command := ""
	if first < len(words) {
		command = words[first].literal
		if !words[first].plain {
			command = "?"
		}
	}
	r.commands = append(r.commands, command)
	if first < len(words) && layoutTextCommands[command] {
		for _, word := range words[first+1:] {
			if word.quoted {
				r.layout.skipped = append(r.layout.skipped, textSpan{word.start, word.end})
			}
		}
	}
	if layoutReserved[command] {
		r.layout.sequential, r.grouped = false, true
	}
	inOrder := (before == "start" || before == ";" || before == "\n") &&
		(term == ";" || term == "\n" || term == "EOF") && !redirected
	if !inOrder {
		return
	}
	switch {
	case first == len(words):
		for _, word := range words {
			r.layout.straight[word.start] = true
		}
	case layoutDeclarations[command] && first == 0 && allAssignments(words[1:]):
		for _, word := range words[1:] {
			r.layout.straight[word.start] = true
		}
	case command == "cd" && first == 0:
		r.layout.straight[words[0].start] = true
	}
}

func allAssignments(words []layoutWord) bool {
	for _, word := range words {
		if !word.assign {
			return false
		}
	}
	return true
}

// readDocuments reads the bodies of the here-documents opened on the line
// that ended at index, and returns the index after them. A body that feeds
// only commands that read data is skipped.
func (r *layoutReader) readDocuments(index int) int {
	data := !r.grouped
	for _, command := range r.commands {
		if command != "" && !layoutDataReaders[command] {
			data = false
		}
	}
	for _, document := range r.documents {
		end := heredocBodyEnd(r.text, index, document.delimiter, document.stripTabs)
		if data && end > index {
			r.layout.skipped = append(r.layout.skipped, textSpan{index, end})
		}
		index = end
	}
	r.documents, r.commands, r.grouped = nil, nil, false
	return index
}

// readLayoutWord reads the shell word at index; false for a construct the
// reading does not follow.
func readLayoutWord(text string, index int) (layoutWord, int, bool) {
	word := layoutWord{start: index, plain: true, assign: assignmentNameAt(text, index) != ""}
	var literal strings.Builder
	for index < len(text) {
		c := text[index]
		if isShellWhiteSpace(c) || strings.IndexByte(";&|()<>", c) >= 0 {
			break
		}
		switch c {
		case shellSingleQuote:
			end := strings.IndexByte(text[index+1:], shellSingleQuote)
			if end < 0 {
				return layoutWord{}, 0, false
			}
			literal.WriteString(text[index+1 : index+1+end])
			index += end + 2
			word.plain, word.quoted = false, true
		case shellDoubleQuote:
			end, ok := layoutDoubleQuoteEnd(text, index)
			if !ok {
				return layoutWord{}, 0, false
			}
			literal.WriteString(text[index+1 : end-1])
			index = end
			word.plain, word.quoted = false, true
		case shellBackslash:
			if index+1 < len(text) && text[index+1] != shellNewline {
				literal.WriteByte(text[index+1])
				word.plain = false
			}
			index += 2
		case shellBacktick:
			return layoutWord{}, 0, false
		case shellDollar:
			end := layoutDollarEnd(text, index)
			if end < 0 {
				return layoutWord{}, 0, false
			}
			literal.WriteString(text[index:end])
			index = end
			word.plain = false
		default:
			literal.WriteByte(c)
			index++
		}
	}
	word.literal, word.end = literal.String(), min(index, len(text))
	return word, word.end, true
}

// layoutDollarEnd is the index after the dollar construct at index: the
// dollar of a variable (its name is read as plain word bytes) or a
// ${NAME}. -1 for a substitution, an expansion with an operator, arithmetic,
// ANSI-C and locale quoting.
func layoutDollarEnd(text string, index int) int {
	if index+1 >= len(text) {
		return index + 1
	}
	switch text[index+1] {
	case '(', '[', shellSingleQuote, shellDoubleQuote:
		return -1
	case '{':
		end := index + 2
		for end < len(text) && (text[end] == '_' || text[end] >= 'A' && text[end] <= 'Z' ||
			text[end] >= 'a' && text[end] <= 'z' || end > index+2 && text[end] >= '0' && text[end] <= '9') {
			end++
		}
		if end == index+2 || end >= len(text) || text[end] != '}' {
			return -1
		}
		return end + 1
	}
	return index + 1
}

// layoutDoubleQuoteEnd is the index after the double quote that closes the
// string opened at index; false for an unterminated string and for a
// construct inside it that the reading does not follow.
func layoutDoubleQuoteEnd(text string, index int) (int, bool) {
	for next := index + 1; next < len(text); next++ {
		switch text[next] {
		case shellBackslash:
			next++
		case shellDoubleQuote:
			return next + 1, true
		case shellBacktick:
			return 0, false
		case shellDollar:
			end := layoutDollarEnd(text, next)
			if end < 0 {
				return 0, false
			}
			next = end - 1
		}
	}
	return 0, false
}

// heredocBodyEnd is the index after the delimiter line of the here-document
// body that starts at index; the end of the text for a body that has none.
func heredocBodyEnd(text string, index int, delimiter string, stripTabs bool) int {
	for index < len(text) {
		end := strings.IndexByte(text[index:], shellNewline)
		next := len(text)
		line := text[index:]
		if end >= 0 {
			next = index + end + 1
			line = text[index : index+end]
		}
		if stripTabs {
			line = strings.TrimLeft(line, "\t")
		}
		index = next
		if line == delimiter {
			return index
		}
	}
	return index
}
