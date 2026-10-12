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

package sandboxapi

import (
	"strings"
	"unicode/utf8"
)

// IndefiniteArticle chooses a or an for provider names by their first letter.
func IndefiniteArticle(name string) string {
	first, _ := utf8.DecodeRuneInString(strings.TrimSpace(name))
	if strings.ContainsRune("aeiouAEIOU", first) {
		return "an"
	}
	return "a"
}

// DisplayText makes text a sandbox may control (a directory or tool name, a
// binary path, a proposal's notes) safe to print on the user's terminal:
// tabs and line breaks (U+2028 and U+2029 too, which YAML and some readers
// break lines at) become spaces, and invalid UTF-8, the other C0 and C1
// control characters (ESC among them, which starts terminal escape
// sequences), DEL and the Unicode bidirectional controls become U+FFFD.
// Text without any of them is returned as is.
func DisplayText(s string) string {
	clean := true
	for _, r := range s {
		if r == utf8.RuneError || unsafeRune(r) {
			clean = false
			break
		}
	}
	if clean {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range strings.ToValidUTF8(s, string(utf8.RuneError)) {
		switch {
		case r == '\t' || r == '\n' || r == '\r' || r == 0x2028 || r == 0x2029:
			b.WriteByte(' ')
		case unsafeRune(r):
			b.WriteRune(utf8.RuneError)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// MaxRequestAccessBytes bounds the request-access contact an administrator
// sets (openshell.admin.request_access): config validation refuses more, and
// every surface cuts what it shows to it.
const MaxRequestAccessBytes = 512

// RequestAccessFallback is the contact when the administrator set none.
const RequestAccessFallback = "contact your IT help desk"

// RequestAccessText is the caller's request-access contact made safe to
// print: control characters and bidirectional marks replaced, cut to
// MaxRequestAccessBytes at a character boundary, and RequestAccessFallback
// when it is empty.
func RequestAccessText(contact string) string {
	contact = strings.TrimSpace(DisplayText(contact))
	if len(contact) > MaxRequestAccessBytes {
		contact = strings.ToValidUTF8(contact[:MaxRequestAccessBytes], "")
	}
	if contact == "" {
		return RequestAccessFallback
	}
	return contact
}

// AccountUnknownText is the sentence for an account the computer cannot look
// up right now (the directory does not answer): the managed gateway says it
// to a caller it does not know, and the CLI when ssh finds no user for it.
const AccountUnknownText = "Your account can't be looked up on this computer right now. Try again in a moment."

// AccessContact is the closing sentence of a refusal or an off message:
// "Need an exception? Contact it-security@example.com". With no contact set
// it reads "Need an exception? Please contact your IT help desk".
func AccessContact(contact string) string {
	text := RequestAccessText(contact)
	if text == RequestAccessFallback {
		return "Need an exception? Please " + text + "."
	}
	return "Need an exception? Contact " + text
}

// DisplayTexts applies DisplayText to every element, copying the slice only
// when one changes.
func DisplayTexts(list []string) []string {
	var out []string
	for i, s := range list {
		clean := DisplayText(s)
		if clean != s && out == nil {
			out = append(make([]string, 0, len(list)), list[:i]...)
		}
		if out != nil {
			out = append(out, clean)
		}
	}
	if out == nil {
		return list
	}
	return out
}

func unsafeRune(r rune) bool {
	switch {
	case r < 0x20, r == 0x7f, r >= 0x80 && r <= 0x9f:
		return true
	case r == 0x061c, r == 0x200e, r == 0x200f, r >= 0x202a && r <= 0x202e, r >= 0x2066 && r <= 0x2069:
		return true
	case r == 0x2028, r == 0x2029: // line and paragraph separators
		return true
	}
	return false
}
