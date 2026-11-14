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
	"regexp"
	"slices"
	"strings"
	"unicode"
)

// hardcodedCredentialAssignment is a credential-named assignment of a quoted
// value of 16 or more characters. Group 2 is the value.
var hardcodedCredentialAssignment = regexp.MustCompile(`(?i)(api[_-]?key|secret[_-]?key|access[_-]?token|private[_-]?key)\s*[:=]\s*["']([^\s"']{16,})["']`)

// placeholderCredentialWords are the words that make a quoted value a
// stand-in, not a secret: a test fixture or a document names its fake key
// "SG.fake.sendgrid.test.token" or "your-api-key-example". A word must stand
// as a whole piece of the value, so "examplesys" or "fakir" do not count.
var placeholderCredentialWords = []string{
	"fake", "dummy", "example", "placeholder", "changeme", "redacted", "mock", "notreal", "sample",
}

// placeholderCredentialValue reports a value that is plainly not a secret: it
// holds a placeholder word as a whole piece (split at anything but a letter
// or a digit), or it repeats one character (xxxxxxxxxxxxxxxx).
func placeholderCredentialValue(value string) bool {
	pieces := strings.FieldsFunc(strings.ToLower(value), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	})
	for _, piece := range pieces {
		if slices.Contains(placeholderCredentialWords, piece) {
			return true
		}
	}
	compact := strings.Join(pieces, "")
	return compact != "" && strings.Trim(compact, compact[:1]) == ""
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
