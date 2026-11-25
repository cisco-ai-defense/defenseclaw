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

package hookpaths

import "strings"

// globOptionsChangeWords are the words of the text that can change the glob
// options inside one call (globOptionsChangeScan), one spec string: the
// GAP-0749 bounded sweep reads every package string literal as a word.
var globOptionsChangeWords = strings.Fields("shopt GLOBIGNORE BASHOPTS SHELLOPTS set eval source . bash")

// globOptionsChangeScan reports text that can change the glob options inside
// one call: shopt, set with an option, an assignment of GLOBIGNORE, BASHOPTS
// or SHELLOPTS, eval, source and . (they run text the walk does not read)
// after a separator, a nested bash with -O or -o before the next |, ; or &.
// Read as text on purpose: every later glob word of such a call is
// uncertain. It matches where the expression
//
//	shopt|GLOBIGNORE|BASHOPTS|SHELLOPTS|(^|[;&|(\s])(set\s+[-+]|eval\b|source\b|\.\s)|\bbash\s+[^|;&]*-[Oo]
//
// matches (TestGAP0299GlobOptionsScanMatchesTheExpression), in one pass per
// word. That expression has no literal prefix, so the regexp package ran its
// NFA over the whole call each time a reader asked: a 1 MiB here-document of
// prose (a period before a newline passed the literal pre-check) spent about
// 60% of its hook decision there (rel-1-0-10:GAP-0299).
func globOptionsChangeScan(text string) bool {
	words := globOptionsChangeWords
	for _, name := range words[:4] {
		if strings.Contains(text, name) {
			return true
		}
	}
	set, eval, source, dot, bash := words[4], words[5], words[6], words[7], words[8]
	return globOptionsWordAfterSeparator(text, set, func(rest string) bool {
		n := globOptionsSpaceRun(rest)
		return n > 0 && n < len(rest) && (rest[n] == '-' || rest[n] == '+')
	}) ||
		globOptionsWordAfterSeparator(text, eval, globOptionsWordEnds) ||
		globOptionsWordAfterSeparator(text, source, globOptionsWordEnds) ||
		globOptionsWordAfterSeparator(text, dot, func(rest string) bool {
			return rest != "" && globOptionsSpace(rest[0])
		}) ||
		globOptionsNestedBashOption(text, bash)
}

// globOptionsWordAfterSeparator reports an occurrence of word at the start of
// text or after one of ; & | ( or a space character, whose rest of the text
// satisfies after.
func globOptionsWordAfterSeparator(text, word string, after func(rest string) bool) bool {
	for i := 0; i <= len(text); {
		j := strings.Index(text[i:], word)
		if j < 0 {
			return false
		}
		at := i + j
		if (at == 0 || globOptionsSeparator(text[at-1])) && after(text[at+len(word):]) {
			return true
		}
		i = at + 1
	}
	return false
}

// globOptionsNestedBashOption reports bash as a whole word followed by a
// space character and, before the next |, ; or &, a -O or -o. Each stretch
// up to a separator is read once: a later bash in a stretch already read
// sees a part of it.
func globOptionsNestedBashOption(text, word string) bool {
	end := -1
	for i := 0; i <= len(text); {
		j := strings.Index(text[i:], word)
		if j < 0 {
			return false
		}
		at := i + j
		i = at + 1
		if at > 0 && globOptionsWordByte(text[at-1]) {
			continue
		}
		p := at + len(word)
		if p >= len(text) || !globOptionsSpace(text[p]) || p < end {
			continue
		}
		stretch := text[p+1:]
		end = len(text)
		if k := strings.IndexAny(stretch, "|;&"); k >= 0 {
			stretch, end = stretch[:k], p+1+k
		}
		if strings.Contains(stretch, "-O") || strings.Contains(stretch, "-o") {
			return true
		}
	}
	return false
}

// globOptionsWordEnds reports a word boundary before rest (\b after a word
// character): the end of the text or a byte that is no ASCII word character.
func globOptionsWordEnds(rest string) bool {
	return rest == "" || !globOptionsWordByte(rest[0])
}

// globOptionsSpaceRun is the length of the run of space characters (\s) that
// starts rest.
func globOptionsSpaceRun(rest string) int {
	n := 0
	for n < len(rest) && globOptionsSpace(rest[n]) {
		n++
	}
	return n
}

// globOptionsSpace is \s of the regexp package: tab, newline, form feed,
// carriage return and space.
func globOptionsSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\f' || c == '\r'
}

func globOptionsSeparator(c byte) bool {
	return c == ';' || c == '&' || c == '|' || c == '(' || globOptionsSpace(c)
}

// globOptionsWordByte is \w of the regexp package (ASCII letters, digits and
// _); a byte of a multi-byte character is none.
func globOptionsWordByte(c byte) bool {
	return c == '_' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}
