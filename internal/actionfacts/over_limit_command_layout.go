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
//     a command that reads data (cat, tee...) and that the shell does not
//     expand (a quoted delimiter, or a body with no substitution), and the
//     argument words of a command that only prints or counts text (echo,
//     printf...), quoted or not. Their lines are no command.
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
// A command substitution and a backtick are code that runs in a subshell: a
// cd or an assignment inside it never reaches the statements around it. The
// reading marks each as a scope, so the caller reads what is inside it with
// its own working directory and values and takes them back at its close; the
// text stays sequential. A braced expansion is data, except the
// substitutions inside it; the variable an assigning one (${NAME=word}) may
// set is added to the values the caller follows, where the expansion is
// written when the shell expands it there (braced): an expansion in a single
// quote, after a backslash, in a comment or in a here-document body that is
// quoted is text and sets nothing. A word that holds code is skipped as text
// only outside it. The inside of a command
// substitution is read as a command text of its own, to a bounded depth, so
// the comments, data and printed words inside it are skipped as they are
// outside it. A construct the reading cannot step over (a process
// substitution, an arithmetic bracket, an unterminated quote or
// substitution) makes the whole layout unknown: the caller then reads the
// text as before, every cd and assignment counting wherever it is, nothing
// skipped. Text the reading leaves as text that may still run (the inside of a
// backtick, of a substitution too deep to follow, the body of a here-document
// that feeds a shell) is raw: any expansion in it counts.

type textSpan struct{ start, end int }

// Bytes the layout reading compares against, besides those of the comment
// reader.
const (
	shellCloseParen = 0x29
	shellOpenBrace  = 0x7b
	shellCloseBrace = 0x7d
)

type commandLayout struct {
	skipped    []textSpan
	quoted     []textSpan
	straight   map[int]bool
	sequential bool
	// scopes are the command substitutions and backticks, in text order.
	scopes []textSpan
	// parsed is true for a layout the reading produced, false for the zero
	// layout of a text it does not follow.
	parsed bool
	// braced are the starts of the braced expansions (${) the shell expands
	// where they are written: not those in single quotes, after a backslash,
	// in comments or in the data of a quoted here-document.
	braced map[int]bool
	// raw are the spans left as text that may run; sorted, not overlapping.
	raw []textSpan
}

// expandsAt reports whether a dollar sign at index may start an expansion the
// shell runs: always for a text the reading does not follow and in raw text,
// else only when the reading found it in a place the shell expands.
func (l commandLayout) expandsAt(index int) bool {
	if !l.parsed || l.braced[index] {
		return true
	}
	at, found := slices.BinarySearchFunc(l.raw, index, func(span textSpan, index int) int { return span.start - index })
	return found || at > 0 && l.raw[at-1].end > index
}

// mergeSpans sorts spans and joins those that overlap.
func mergeSpans(spans []textSpan) []textSpan {
	slices.SortFunc(spans, func(a, b textSpan) int { return a.start - b.start })
	merged := spans[:0]
	for _, span := range spans {
		if last := len(merged) - 1; last >= 0 && span.start <= merged[last].end {
			merged[last].end = max(merged[last].end, span.end)
			continue
		}
		merged = append(merged, span)
	}
	return merged
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
	// code are the spans of the word, in text order, that hold a
	// substitution or an expansion the shell runs; braced are the starts of
	// its braced expansions.
	code   []textSpan
	braced []int
}

type layoutDocument struct {
	delimiter string
	stripTabs bool
	// expands is true when the delimiter word holds no quote or escape: the
	// shell then runs the command substitutions in the body.
	expands bool
}

type layoutReader struct {
	text   string
	layout commandLayout
	// depth is how many command substitutions deep the text read is.
	depth int
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
	return readLayoutAt(text, 0)
}

// maxLayoutDepth bounds how many command substitutions deep the reading
// follows; the text of a deeper one stays text.
const maxLayoutDepth = 4

func readLayoutAt(text string, depth int) (commandLayout, bool) {
	r := &layoutReader{
		text:   text,
		depth:  depth,
		layout: commandLayout{straight: map[int]bool{}, sequential: true, parsed: true, braced: map[int]bool{}},
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
	slices.SortFunc(r.layout.quoted, func(a, b textSpan) int { return a.start - b.start })
	slices.SortFunc(r.layout.scopes, func(a, b textSpan) int { return a.start - b.start })
	r.layout.raw = mergeSpans(r.layout.raw)
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
	expands := !strings.ContainsAny(text[start:end], "'\"\\")
	r.documents = append(r.documents, layoutDocument{delimiter: delimiter, stripTabs: stripTabs, expands: expands})
	r.redirected = true
	return end, true
}

// addWord adds a word to the statement: the file of a redirection and a
// file descriptor number before one are no words of the command.
func (r *layoutReader) addWord(word layoutWord, next int) {
	r.readInside(word.code)
	r.markBraced(word.braced)
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

// markBraced records the braced expansions the shell expands.
func (r *layoutReader) markBraced(starts []int) {
	for _, start := range starts {
		r.layout.braced[start] = true
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
		// Every argument word is text, quoted or not, except the code spans
		// of its substitutions: those run.
		for _, word := range words[first+1:] {
			r.skipOutsideCode(word.start, word.end, word.code)
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
	case (command == "cd" || command == "unset") && first == 0:
		r.layout.straight[words[0].start] = true
	}
}

// skipOutsideCode skips the text from start to end except the code spans in
// it, which are in text order.
func (r *layoutReader) skipOutsideCode(start, end int, code []textSpan) {
	for _, span := range code {
		if span.start > start {
			r.layout.skipped = append(r.layout.skipped, textSpan{start, span.start})
		}
		start = max(start, span.end)
	}
	if start < end {
		r.layout.skipped = append(r.layout.skipped, textSpan{start, end})
	}
}

// readInside marks each command substitution and backtick among the code
// spans as a scope and reads the inside of a command substitution as a command
// text of its own, adding what that reading skips, quotes and runs in order.
// A backtick (its backslashes change the text) stays text.
func (r *layoutReader) readInside(code []textSpan) {
	for _, span := range code {
		r.layout.scopes = append(r.layout.scopes, span)
		if r.text[span.start] == shellDollar {
			r.readSubstitution(span)
		} else {
			r.layout.raw = append(r.layout.raw, span)
		}
	}
}

// readSubstitution reads the inside of the command substitution at span.
func (r *layoutReader) readSubstitution(span textSpan) {
	start := span.start + 2
	if r.depth >= maxLayoutDepth {
		r.layout.raw = append(r.layout.raw, span)
		return
	}
	inside, ok := readLayoutAt(r.text[start:span.end-1], r.depth+1)
	if !ok {
		r.layout.raw = append(r.layout.raw, span)
		return
	}
	for brace := range inside.braced {
		r.layout.braced[start+brace] = true
	}
	for _, raw := range inside.raw {
		r.layout.raw = append(r.layout.raw, textSpan{start + raw.start, start + raw.end})
	}
	for _, skipped := range inside.skipped {
		r.layout.skipped = append(r.layout.skipped, textSpan{start + skipped.start, start + skipped.end})
	}
	for _, quoted := range inside.quoted {
		r.layout.quoted = append(r.layout.quoted, textSpan{start + quoted.start, start + quoted.end})
	}
	for _, scope := range inside.scopes {
		r.layout.scopes = append(r.layout.scopes, textSpan{start + scope.start, start + scope.end})
	}
	if inside.sequential {
		for statement := range inside.straight {
			r.layout.straight[start+statement] = true
		}
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
// only commands that read data is skipped, except the command substitutions
// the shell runs in it (an unquoted delimiter): those are code, and stay text.
func (r *layoutReader) readDocuments(index int) int {
	data := !r.grouped
	for _, command := range r.commands {
		if command != "" && !layoutDataReaders[command] {
			data = false
		}
	}
	for _, document := range r.documents {
		end := heredocBodyEnd(r.text, index, document.delimiter, document.stripTabs)
		switch {
		case end <= index:
		case !data:
			r.layout.raw = append(r.layout.raw, textSpan{index, end})
		case document.expands:
			var braced []int
			code := documentCode(r.text[:end], index, &braced)
			r.markBraced(braced)
			r.skipOutsideCode(index, end, code)
			r.readInside(code)
		default:
			r.layout.skipped = append(r.layout.skipped, textSpan{index, end})
		}
		index = end
	}
	r.documents, r.commands, r.grouped = nil, nil, false
	return index
}

// documentCode are the code spans of the body of a here-document with an
// unquoted delimiter that starts at index: a command substitution and a
// backtick that no backslash escapes, also inside a braced expansion. The
// braced expansion itself is data. Quotes are plain text in a body, but not
// inside a substitution. A substitution, or an expansion, that does not close
// runs to the end of the body. The starts of the braced expansions are added
// to braced when it is not nil.
func documentCode(text string, index int, braced *[]int) []textSpan {
	var code []textSpan
	for ; index < len(text); index++ {
		var end int
		switch {
		case text[index] == shellBackslash:
			index++
			continue
		case text[index] == shellBacktick:
			end = layoutBacktickEnd(text, index)
		case text[index] == shellDollar && index+1 < len(text) && text[index+1] == shellOpenParen:
			end = layoutNestedEnd(text, index+2, shellCloseParen)
		case text[index] == shellDollar && index+1 < len(text) && text[index+1] == shellOpenBrace:
			end = layoutNestedEnd(text, index+2, shellCloseBrace)
			if end >= 0 {
				if braced != nil {
					*braced = append(*braced, index)
				}
				code = append(code, documentCode(text[:end-1], index+2, braced)...)
				index = end - 1
				continue
			}
		default:
			continue
		}
		if end < 0 {
			end = len(text)
		}
		code = append(code, textSpan{index, end})
		index = end - 1
	}
	return code
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
			end := layoutDoubleQuoteEnd(text, index, &word.code, &word.braced)
			if end < 0 {
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
			end := layoutBacktickEnd(text, index)
			if end < 0 {
				return layoutWord{}, 0, false
			}
			word.code = append(word.code, textSpan{index, end})
			literal.WriteString(text[index:end])
			index = end
			word.plain = false
		case shellDollar:
			end := layoutDollarEnd(text, index, &word.code, &word.braced)
			if end < 0 {
				return layoutWord{}, 0, false
			}
			if index+1 < len(text) && (text[index+1] == shellSingleQuote || text[index+1] == shellDoubleQuote) {
				word.quoted = true
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

// layoutDollarEnd is the index after the dollar construct at index: a
// variable (its name is read as plain word bytes), a ${NAME}, ANSI-C and
// locale quoting, or code: a command substitution or an expansion with an
// operator, whose span is added to code. -1 for arithmetic brackets and for a
// construct that does not close. The start of a braced expansion is added to
// braced when it is not nil.
func layoutDollarEnd(text string, index int, code *[]textSpan, braced *[]int) int {
	if index+1 >= len(text) {
		return index + 1
	}
	switch text[index+1] {
	case shellOpenParen:
		end := layoutNestedEnd(text, index+2, shellCloseParen)
		if end >= 0 && code != nil {
			*code = append(*code, textSpan{index, end})
		}
		return end
	case '[':
		return -1
	case shellSingleQuote:
		for next := index + 2; next < len(text); next++ {
			switch text[next] {
			case shellBackslash:
				next++
			case shellSingleQuote:
				return next + 1
			}
		}
		return -1
	case shellDoubleQuote:
		return layoutDoubleQuoteEnd(text, index+1, code, braced)
	case shellOpenBrace:
		end := index + 2
		for end < len(text) && (text[end] == '_' || text[end] >= 'A' && text[end] <= 'Z' ||
			text[end] >= 'a' && text[end] <= 'z' || end > index+2 && text[end] >= '0' && text[end] <= '9') {
			end++
		}
		if end > index+2 && end < len(text) && text[end] == shellCloseBrace {
			return end + 1
		}
		end = layoutNestedEnd(text, index+2, shellCloseBrace)
		if end >= 0 && code != nil {
			if braced != nil {
				*braced = append(*braced, index)
			}
			*code = append(*code, documentCode(text[:end-1], index+2, braced)...)
		}
		return end
	}
	return index + 1
}

// layoutDoubleQuoteEnd is the index after the double quote that closes the
// string opened at index, with the code spans inside it added to code; -1 for
// an unterminated string and for arithmetic brackets inside it.
func layoutDoubleQuoteEnd(text string, index int, code *[]textSpan, braced *[]int) int {
	for next := index + 1; next < len(text); next++ {
		switch text[next] {
		case shellBackslash:
			next++
		case shellDoubleQuote:
			return next + 1
		case shellBacktick:
			end := layoutBacktickEnd(text, next)
			if end < 0 {
				return -1
			}
			if code != nil {
				*code = append(*code, textSpan{next, end})
			}
			next = end - 1
		case shellDollar:
			// A dollar before a quote is a plain dollar inside a string.
			if next+1 < len(text) && (text[next+1] == shellSingleQuote || text[next+1] == shellDoubleQuote) {
				continue
			}
			end := layoutDollarEnd(text, next, code, braced)
			if end < 0 {
				return -1
			}
			next = end - 1
		}
	}
	return -1
}

// layoutBacktickEnd is the index after the backtick that closes the one at
// index; -1 when none does.
func layoutBacktickEnd(text string, index int) int {
	for next := index + 1; next < len(text); next++ {
		switch text[next] {
		case shellBackslash:
			next++
		case shellBacktick:
			return next + 1
		}
	}
	return -1
}

// layoutNestedEnd is the index after the closer (a parenthesis or a brace)
// that ends the substitution or expansion whose body starts at index; -1 when
// none does. Quotes, backticks and nested substitutions inside it are read as
// the shell does, so a closer inside one does not end it.
func layoutNestedEnd(text string, index int, closer byte) int {
	depth := 1
	for ; index < len(text); index++ {
		c := text[index]
		switch {
		case c == shellBackslash:
			index++
		case c == shellSingleQuote:
			end := strings.IndexByte(text[index+1:], shellSingleQuote)
			if end < 0 {
				return -1
			}
			index += end + 1
		case c == shellDoubleQuote:
			end := layoutDoubleQuoteEnd(text, index, nil, nil)
			if end < 0 {
				return -1
			}
			index = end - 1
		case c == shellBacktick:
			end := layoutBacktickEnd(text, index)
			if end < 0 {
				return -1
			}
			index = end - 1
		case c == shellDollar && index+1 < len(text) && text[index+1] == shellOpenParen:
			end := layoutNestedEnd(text, index+2, shellCloseParen)
			if end < 0 {
				return -1
			}
			index = end - 1
		case c == shellDollar && index+1 < len(text) && text[index+1] == shellOpenBrace:
			end := layoutNestedEnd(text, index+2, shellCloseBrace)
			if end < 0 {
				return -1
			}
			index = end - 1
		case c == shellOpenParen && closer == shellCloseParen:
			depth++
		case c == closer:
			if depth--; depth == 0 {
				return index + 1
			}
		}
	}
	return -1
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
