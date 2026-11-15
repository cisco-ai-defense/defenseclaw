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

package gateway

import "strings"

// This file is the ONE reading of "is this value a relative path, or a
// generated string that holds slashes" (GAP-0665, GAP-0671). The
// SEC-SECRET-ASSIGN path rule (secretAssignmentPathShaped) and the
// SEC-PASSWORD-ASSIGN path rule (relativePathValue) both call weighPath, so a
// random base64 value with a slash is judged the same way by both. The file
// is byte-identical on s7/response-fields and s7/secret-recall.

// pathWeight is a /-joined value weighed by its letters and digits, not by
// its pieces.
type pathWeight struct {
	components int  // components joined by /
	words      int  // word pieces of three or more letters
	idChars    int  // letters and digits that sit in ids
	total      int  // letters and digits that are not counters
	ok         bool // false: an empty component, or a piece too long for a name or an id
}

// namesOnly reports that the ids are at most a quarter of the value. A short
// secret hidden among a few short pieces keeps its ids over a quarter of the
// value; random base64 that holds slashes is short pieces mixed in case and
// full of digits and does not get there either.
func (w pathWeight) namesOnly() bool { return w.ok && w.idChars*4 <= w.total }

// weighPath splits value at / and its components at _ - and ., and weighs
// every piece. A piece is:
//   - a counter (digits only, short): it weighs nothing;
//   - a word: letters of one case shape (all lower, all upper or one capital
//     then lower), three or more of them (three always pass, more hold a vowel
//     and no run of more than five consonants). It counts as a word, and its
//     letters are names;
//   - a short name: one or two letters of that shape. Its letters are names
//     but it counts as no word, so single-letter padding (a/b/c/d) never
//     makes six words;
//   - a short tag (k8s, v2, a999): a lower-case piece of letters and digits
//     of four characters or fewer that starts with a letter. Its letters are
//     names and its digits are ids, because a digit is what an id carries;
//   - with camel set, a camel-case name (LoginForm, dbConfig, getUserName):
//     letters only, every hump a word, and every hump after the first of
//     three letters or more. Its letters are names and it counts as no word.
//     A piece that mixes upper case, lower case and digits is never one;
//   - an id otherwise, when it is no longer than 16 characters (a git short
//     hash, a migration revision, a temporary-file suffix, a longer piece of
//     letters and digits): all its letters and digits are ids. A longer piece
//     rules the value out.
func weighPath(value string, camel bool) pathWeight {
	components := strings.Split(value, "/")
	w := pathWeight{components: len(components)}
	for _, component := range components {
		pieces := strings.FieldsFunc(component, func(r rune) bool { return r == '_' || r == '-' || r == '.' })
		if len(pieces) == 0 {
			return w
		}
		for _, piece := range pieces {
			if secretAssignmentCounter(piece) {
				continue
			}
			size := secretAlnumCount(piece)
			w.total += size
			switch {
			case camel && pathCamelName(piece):
				// Letters of names; no word, no id.
			case !secretAssignmentPathWord(piece):
				if len(piece) > 16 {
					return w
				}
				w.idChars += size
			default:
				letters := countLetters(piece)
				switch {
				case letters == size:
					if letters >= 3 {
						w.words++
					}
				case size > 4:
					// A piece of letters and digits longer than a short tag
					// is as likely a chunk of a secret as a name.
					w.idChars += size
				default:
					w.idChars += size - letters
				}
			}
		}
	}
	w.ok = true
	return w
}

// pathCamelName reports a camel-case name: letters only, up to 32 of them,
// cut into humps where the case turns from lower to upper (LoginForm) and
// before the last capital of a capital run that a lower-case letter follows
// (HTTPServer). Every hump is a word shape or an acronym, and every hump after the first
// has three letters or more, so random upper and lower case letters (humps of
// one or two) are not a name.
func pathCamelName(piece string) bool {
	if len(piece) < 4 || len(piece) > 32 {
		return false
	}
	upper := func(c byte) bool { return c >= 'A' && c <= 'Z' }
	lower := func(c byte) bool { return c >= 'a' && c <= 'z' }
	humps, start := 0, 0
	check := func(end int) bool {
		hump := piece[start:end]
		if humps > 0 && len(hump) < 3 || !secretAssignmentPathWord(hump) && !pathAcronym(hump) {
			return false
		}
		humps++
		start = end
		return true
	}
	for i := 0; i < len(piece); i++ {
		if !upper(piece[i]) && !lower(piece[i]) {
			return false
		}
		if i == 0 {
			continue
		}
		turn := upper(piece[i]) && (lower(piece[i-1]) || upper(piece[i-1]) && i+1 < len(piece) && lower(piece[i+1]))
		if turn && !check(i) {
			return false
		}
	}
	return check(len(piece)) && humps >= 2
}

// pathAcronym reports a hump of three to five capitals (HTTP, JSON, XML).
func pathAcronym(hump string) bool {
	if len(hump) < 3 || len(hump) > 5 {
		return false
	}
	for i := 0; i < len(hump); i++ {
		if hump[i] < 'A' || hump[i] > 'Z' {
			return false
		}
	}
	return true
}

// secretAssignmentPathWord reports a path piece that a person wrote: letters
// of one case shape (all lower, all upper or one capital then lower) that are
// three or fewer, or hold a vowel and no run of more than five consonants; or
// a short lower-case piece of letters and digits that is not token-like.
func secretAssignmentPathWord(piece string) bool {
	if piece == "" || len(piece) > 16 {
		return false
	}
	upper, lower, digits := 0, 0, 0
	for i := 0; i < len(piece); i++ {
		switch c := piece[i]; {
		case c >= 'A' && c <= 'Z':
			upper++
		case c >= 'a' && c <= 'z':
			lower++
		case c >= '0' && c <= '9':
			digits++
		default:
			return false
		}
	}
	if upper != 0 && lower != 0 && (upper != 1 || piece[0] < 'A' || piece[0] > 'Z') {
		return false
	}
	if digits > 0 {
		return len(piece) <= 8 && upper == 0 && secretAssignmentLetter(piece[0]) && !secretAssignmentTokenLike(piece)
	}
	if len(piece) <= 3 {
		return true
	}
	vowel, run := false, 0
	for i := 0; i < len(piece); i++ {
		if strings.IndexByte("aeiouyAEIOUY", piece[i]) >= 0 {
			vowel = true
			run = 0
			continue
		}
		run++
		if run > 5 {
			return false
		}
	}
	return vowel
}

// secretAssignmentTokenLike reports a segment of eight characters or more
// that turns from letters to digits or back three times or more
// (7f8a9b0c1d2e): a generated token, where a name has its digits in one run
// (summer2026, v2).
func secretAssignmentTokenLike(segment string) bool {
	if len(segment) < 8 {
		return false
	}
	turns, prev := 0, byte(0)
	for i := 0; i < len(segment); i++ {
		class := byte('l')
		if segment[i] >= '0' && segment[i] <= '9' {
			class = 'd'
		} else if !secretAssignmentLetter(segment[i]) {
			continue
		}
		if prev != 0 && class != prev {
			turns++
		}
		prev = class
	}
	return turns >= 3
}

// secretAssignmentCounter reports a segment that is only digits and is short
// or the length of an epoch in milliseconds.
func secretAssignmentCounter(segment string) bool {
	if segment == "" || strings.Trim(segment, "0123456789") != "" {
		return false
	}
	return len(segment) <= 10 || len(segment) == 13
}

func secretAssignmentLetter(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

func countLetters(value string) int {
	n := 0
	for i := 0; i < len(value); i++ {
		if secretAssignmentLetter(value[i]) {
			n++
		}
	}
	return n
}

// secretAlnumCount counts the letters and digits of s; = + / padding carries no secret.
func secretAlnumCount(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' {
			n++
		}
	}
	return n
}
