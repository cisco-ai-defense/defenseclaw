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
	"regexp"
	"strings"
	"unicode/utf8"
)

// OverLimitCommandBoundedTwin returns, for a limit-exceeded command (a shell
// call whose command text is over maxCommandBytes), the same call with the
// white space that pads each over-long text shortened (boundedCommandText:
// a line of white space longer than maxKeptWhiteSpaceRun is one byte, and
// the line breaks stay). The twin reads the same to the shell and to every
// rule, and is within the limits when the padding was all that put the call
// over them, so every rule judges it as it judges the unpadded command
// (GAP-0934). false when the call is not limit-exceeded, is a structured
// write tool (OverLimitWriteBoundedTwin owns those), has an over-long text
// that is not padded, or when the twin still exceeds a limit.
func OverLimitCommandBoundedTwin(input Input, facts Facts) (Input, bool) {
	if facts.Parse.Status != StatusLimitExceeded || StructuredWriteTool(input.Tool) {
		return Input{}, false
	}
	twin := input
	changed := false
	if len(input.Command) > maxCommandBytes {
		bounded, ok := boundedCommandText(input.Command)
		if !ok {
			return Input{}, false
		}
		twin.Command, changed = bounded, true
	}
	if len(strings.TrimSpace(string(input.Args))) != 0 {
		if len(input.Args) > maxOverLimitWriteArgsBytes || !utf8.Valid(input.Args) {
			return Input{}, false
		}
		reduction, ok := runOverLimitReducer(input.Args, &overLimitArgsReducer{commandTwin: true})
		if !ok {
			return Input{}, false
		}
		if reduction.boundedCommand {
			twin.Args, changed = reduction.args, true
		}
	}
	if !changed || len(twin.Args) > maxArgsJSONBytes || Analyze(twin).Parse.Status == StatusLimitExceeded {
		return Input{}, false
	}
	return twin, true
}

// shell white space is the blank, the tab and the line break: the bytes the
// shell splits words and statements on. Any other byte (a carriage return,
// a no-break space) is a word byte for the shell and stays.
const (
	shellSpace   = 0x20
	shellTab     = 0x09
	shellNewline = 0x0a
)

func isShellWhiteSpace(c byte) bool {
	return c == shellSpace || c == shellTab || c == shellNewline
}

// blankHeredocDelimiter finds a here-document whose delimiter is made of
// white space: a line of white space ends it, so shortening a long line of
// white space could end it where the original does not.
var blankHeredocDelimiter = regexp.MustCompile(`<<-?[ \t]*(?:\x27[ \t]+\x27|"[ \t]+"|\\[ \t])`)

// boundedCommandText is a text over maxCommandBytes without the comments
// (stripShellComments) and the white space that pad it (see
// OverLimitCommandBoundedTwin); false when that form is still over the
// bound, the text had no such padding, or it holds a here-document with a
// white space delimiter. A comment is no part of what the shell runs, so
// the form is the same command.
//
// The form reads to the shell as the text does: only white space changes,
// each line of white space keeps its kind (a blank, or a tab for a line of
// tabs) and each line break stays up to maxKeptWhiteSpaceRun of them, so a
// word never joins its neighbour, a statement never moves, and a line that
// is padded after or before its words is still not a here-document
// delimiter. Only a line break run longer than maxKeptWhiteSpaceRun loses
// its later, empty lines.
func boundedCommandText(text string) (string, bool) {
	if blankHeredocDelimiter.MatchString(text) {
		return "", false
	}
	source := text
	if stripped, ok := stripShellComments(text); ok {
		source = stripped
	}
	var out strings.Builder
	content := false
	for index := 0; index < len(source); {
		if !isShellWhiteSpace(source[index]) {
			out.WriteByte(source[index])
			content = true
			index++
			continue
		}
		end := index
		for end < len(source) && isShellWhiteSpace(source[end]) {
			end++
		}
		out.WriteString(boundedShellWhiteSpace(source[index:end]))
		index = end
	}
	bounded := out.String()
	return bounded, content && len(bounded) <= maxCommandBytes && len(bounded) < len(text)
}

// boundedShellWhiteSpace is one run of shell white space with each line of
// it over maxKeptWhiteSpaceRun shortened to one byte of its kind, and its
// empty lines past maxKeptWhiteSpaceRun left out (the last line, which
// indents the next word, stays).
func boundedShellWhiteSpace(run string) string {
	if len(run) <= maxKeptWhiteSpaceRun {
		return run
	}
	lines := strings.Split(run, "\n")
	if len(lines) > maxKeptWhiteSpaceRun {
		lines = append(lines[:maxKeptWhiteSpaceRun:maxKeptWhiteSpaceRun], lines[len(lines)-1])
	}
	for index, line := range lines {
		switch {
		case len(line) <= maxKeptWhiteSpaceRun:
		case strings.Trim(line, "\t") == "":
			lines[index] = "\t"
		default:
			lines[index] = " "
		}
	}
	return strings.Join(lines, "\n")
}

// Bytes the comment reader compares against.
const (
	shellHash        = 0x23
	shellSingleQuote = 0x27
	shellDoubleQuote = 0x22
	shellBackslash   = 0x5c
	shellBacktick    = 0x60
	shellDollar      = 0x24
	shellLess        = 0x3c
	shellOpenParen   = 0x28
	shellDash        = 0x2d
)

// shellMetaBytes end a word, so a hash after one starts a comment.
const shellMetaBytes = ";&|()<>"

// shellUnreadableAfterDollar are the bytes after a dollar that open a
// construct with a grammar of its own (substitution, expansion, arithmetic,
// ANSI-C and locale quoting).
const shellUnreadableAfterDollar = "({[\x27\""

// stripShellComments is the text without its comments: an unquoted hash that
// starts a word, up to the end of its line. It reads only what it can read
// with certainty: quoted strings, backslash escapes and here-document bodies
// (copied as they are, their lines are data) are skipped, so a hash inside
// one is no comment. A command substitution, a parameter expansion, an
// arithmetic form, a backtick or an unterminated quote has a grammar this
// reading does not follow: the text is then not reduced at all (false).
func stripShellComments(text string) (string, bool) {
	type heredoc struct {
		delimiter string
		stripTabs bool
	}
	var out strings.Builder
	out.Grow(len(text))
	var pending []heredoc
	wordStart := true
	for index := 0; index < len(text); {
		c := text[index]
		switch {
		case c == shellNewline:
			out.WriteByte(c)
			index++
			for _, doc := range pending {
				index = copyHeredocBody(&out, text, index, doc.delimiter, doc.stripTabs)
			}
			pending = pending[:0]
			wordStart = true
		case c == shellBackslash:
			end := min(index+2, len(text))
			out.WriteString(text[index:end])
			index, wordStart = end, false
		case c == shellSingleQuote:
			end := strings.IndexByte(text[index+1:], shellSingleQuote)
			if end < 0 {
				return "", false
			}
			out.WriteString(text[index : index+end+2])
			index, wordStart = index+end+2, false
		case c == shellDoubleQuote:
			end, ok := doubleQuoteEnd(text, index)
			if !ok {
				return "", false
			}
			out.WriteString(text[index:end])
			index, wordStart = end, false
		case c == shellBacktick:
			return "", false
		case c == shellDollar:
			if index+1 < len(text) && strings.IndexByte(shellUnreadableAfterDollar, text[index+1]) >= 0 {
				return "", false
			}
			out.WriteByte(c)
			index, wordStart = index+1, false
		case c == shellOpenParen && index+1 < len(text) && text[index+1] == shellOpenParen:
			return "", false
		case c == shellHash && wordStart:
			for index < len(text) && text[index] != shellNewline {
				index++
			}
		case c == shellLess && index+1 < len(text) && text[index+1] == shellLess:
			if index+2 < len(text) && text[index+2] == shellLess {
				out.WriteString("<<<")
				index, wordStart = index+3, true
				continue
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
			if !ok {
				return "", false
			}
			out.WriteString(text[index:end])
			pending = append(pending, heredoc{delimiter: delimiter, stripTabs: stripTabs})
			index, wordStart = end, false
		default:
			out.WriteByte(c)
			index++
			wordStart = isShellWhiteSpace(c) || strings.IndexByte(shellMetaBytes, c) >= 0
		}
	}
	return out.String(), true
}

// doubleQuoteEnd is the index after the double quote that closes the string
// opened at index. false for an unterminated string and for one that holds
// a substitution or expansion, whose own quotes this reading does not follow.
func doubleQuoteEnd(text string, index int) (int, bool) {
	for next := index + 1; next < len(text); next++ {
		switch text[next] {
		case shellBackslash:
			next++
		case shellDoubleQuote:
			return next + 1, true
		case shellBacktick:
			return 0, false
		case shellDollar:
			if next+1 < len(text) && (text[next+1] == shellOpenParen || text[next+1] == 0x7b) {
				return 0, false
			}
		}
	}
	return 0, false
}

// heredocDelimiter reads the delimiter word of a here-document at index, as
// the shell does after quote removal, and the index after the word.
func heredocDelimiter(text string, index int) (string, int, bool) {
	var word strings.Builder
	for index < len(text) && !isShellWhiteSpace(text[index]) && strings.IndexByte(shellMetaBytes, text[index]) < 0 {
		switch text[index] {
		case shellSingleQuote, shellDoubleQuote:
			quote := text[index]
			end := strings.IndexByte(text[index+1:], quote)
			if end < 0 {
				return "", 0, false
			}
			word.WriteString(text[index+1 : index+1+end])
			index += end + 2
		case shellBackslash:
			if index+1 < len(text) {
				word.WriteByte(text[index+1])
			}
			index += 2
		default:
			word.WriteByte(text[index])
			index++
		}
	}
	return word.String(), min(index, len(text)), true
}

// copyHeredocBody copies the body of a here-document that starts at index,
// up to and including its delimiter line, and returns the index after it.
// A body without a delimiter line runs to the end of the text.
func copyHeredocBody(out *strings.Builder, text string, index int, delimiter string, stripTabs bool) int {
	end := heredocBodyEnd(text, index, delimiter, stripTabs)
	out.WriteString(text[index:end])
	return end
}
