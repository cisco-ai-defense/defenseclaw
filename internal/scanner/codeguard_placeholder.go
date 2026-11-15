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

package scanner

import (
	"slices"
	"strings"
	"unicode"

	"github.com/defenseclaw/defenseclaw/internal/lazyregexp"
)

// hardcodedCredentialAssignment is a credential-named assignment of a quoted
// value of 16 or more characters. Group 2 is the value.
var hardcodedCredentialAssignment = lazyregexp.New(`(?i)(api[_-]?key|secret[_-]?key|access[_-]?token|private[_-]?key)\s*[:=]\s*["']([^\s"']{16,})["']`)

// placeholderCredentialWords are the stand-in words a test fixture or a
// document names its fake key with ("SG.fake.sendgrid.test.token",
// "your-api-key-example-0000"). A word counts only as a whole piece of the
// value, so "fakirjewelry" or "examplesys" do not.
var placeholderCredentialWords = []string{
	"changeme", "dummy", "example", "fake", "mock", "notreal", "placeholder",
	"redacted", "sample", "test", "tests", "your", "xxx",
}

// randomPieceLength is the length from which a single-case, letters-only
// piece reads as random rather than as a word: the shortest value the rule
// reads at all, so such a run alone is long enough to be the whole secret.
// Measured on the corpora (GAP-0942): the longest non-stand-in letters piece
// of a value d4's shape rule called a placeholder is 10; every random piece
// of a true-positive value there is mixed with digits or case.
const randomPieceLength = 16

// standInRunLength is the length from which a repeated or sequential piece
// (qqqqqqqq, 12345678) marks the value a stand-in on its own; a shorter run
// (0000 in "your-api-key-example-0000") is only neutral.
const standInRunLength = 8

// placeholderCredentialValue reports a value that is plainly not a secret: a
// low-entropy shape only. A template (<your-key>, ${API_KEY}), a run of one
// repeated character, unit or alphabet sequence (xxxxxxxx, abcabcabc,
// abcdefghijklmnop, 0123456789), or a value that names itself a stand-in
// with a whole placeholder word or a long low-entropy piece and holds no
// random-looking piece. Any other
// value stays a finding, a random string of letters only included
// (GAP-0942): the shape of words alone does not make a stand-in.
func placeholderCredentialValue(value string) bool {
	if templateCredentialValue(value) {
		return true
	}
	pieces := strings.FieldsFunc(value, func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	})
	compact := strings.Join(pieces, "")
	if compact == "" {
		return false
	}
	if lowEntropyRun(strings.ToLower(compact)) {
		return true
	}
	standIn := false
	for _, piece := range pieces {
		switch {
		case slices.Contains(placeholderCredentialWords, strings.ToLower(piece)):
			standIn = true
		case lowEntropyRun(strings.ToLower(piece)):
			standIn = standIn || len(piece) >= standInRunLength
		case randomPiece(piece):
			return false
		}
	}
	return standIn
}

// templateCredentialValue is a value that is a template slot, not a value:
// <...> or ${...}.
func templateCredentialValue(value string) bool {
	return (strings.HasPrefix(value, "<") && strings.HasSuffix(value, ">")) ||
		(strings.HasPrefix(value, "${") && strings.HasSuffix(value, "}"))
}

// lowEntropyRun reports a run that repeats a unit of one to four runes
// (xxxx, 0000, abab, abcabc) or steps through the alphabet or the digits one
// at a time, up or down (abcdef, 123456, zyxw).
func lowEntropyRun(s string) bool {
	r := []rune(s)
	if len(r) < 2 {
		return false
	}
	for unit := 1; unit <= 4 && unit*2 <= len(r); unit++ {
		repeats := true
		for i := unit; i < len(r); i++ {
			if r[i] != r[i-unit] {
				repeats = false
				break
			}
		}
		if repeats {
			return true
		}
	}
	if len(r) < 4 {
		return false
	}
	step := r[1] - r[0]
	if step != 1 && step != -1 {
		return false
	}
	for i := 2; i < len(r); i++ {
		if r[i]-r[i-1] != step {
			return false
		}
	}
	return true
}

// randomPiece reports a piece that reads as random: letters and digits mixed,
// a capital after a small letter three or more times (KqvZmXbT, not
// SendGrid or SG), or a letters run of randomPieceLength or more.
func randomPiece(piece string) bool {
	letters, digits, rises := 0, 0, 0
	var prev rune
	for _, r := range piece {
		switch {
		case unicode.IsDigit(r):
			digits++
		case unicode.IsLetter(r):
			letters++
			if unicode.IsUpper(r) && unicode.IsLower(prev) {
				rises++
			}
		}
		prev = r
	}
	return (letters > 0 && digits > 0) || rises >= 3 || letters >= randomPieceLength
}

// hardcodedCredentialView is the line CG-CRED-001 reads: an assignment whose
// value is a placeholder is blanked, so a test fixture with a fake key is not
// a hardcoded secret (rel-1-0-10:GAP-0018).
func hardcodedCredentialView(line string) string {
	matches := hardcodedCredentialAssignment.FindAllStringSubmatchIndex(line, -1)
	var out strings.Builder
	last := 0
	changed := false
	for _, match := range matches {
		if !placeholderCredentialValue(line[match[4]:match[5]]) {
			continue
		}
		out.WriteString(line[last:match[0]])
		out.WriteByte(' ')
		last, changed = match[1], true
	}
	if !changed {
		return line
	}
	out.WriteString(line[last:])
	return out.String()
}
