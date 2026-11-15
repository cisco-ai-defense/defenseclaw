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
	"strings"
	"unicode"

	"github.com/defenseclaw/defenseclaw/internal/lazyregexp"
)

// hardcodedCredentialAssignment is a credential-named assignment of a quoted
// value of 16 or more characters. Group 2 is the value.
var hardcodedCredentialAssignment = lazyregexp.New(`(?i)(api[_-]?key|secret[_-]?key|access[_-]?token|private[_-]?key)\s*[:=]\s*["']([^\s"']{16,})["']`)

// placeholderCredentialValue reports a value that is plainly not a secret by
// its shape. A secret is one random string; a stand-in a test fixture or a
// document names its fake key ("SG.fake.sendgrid.test.token",
// "your-api-key-example-0000") reads as words: three or more pieces, split at
// anything but a letter or a digit, each made of letters only or of one
// repeated character. A value that repeats one character (xxxxxxxxxxxxxxxx)
// is a stand-in too. No word is looked up. Other values stay findings: a
// random string, a vendor key with a test prefix, a single long word.
func placeholderCredentialValue(value string) bool {
	pieces := strings.FieldsFunc(value, func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	})
	compact := strings.Join(pieces, "")
	if compact != "" && strings.Trim(compact, compact[:1]) == "" {
		return true
	}
	if len(pieces) < 3 {
		return false
	}
	for _, piece := range pieces {
		if !onlyLetters(piece) && strings.Trim(piece, piece[:1]) != "" {
			return false
		}
	}
	return true
}

func onlyLetters(piece string) bool {
	for _, r := range piece {
		if !unicode.IsLetter(r) {
			return false
		}
	}
	return piece != ""
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
