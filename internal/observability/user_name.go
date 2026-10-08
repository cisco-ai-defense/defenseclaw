// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package observability

import (
	"strings"
	"sync/atomic"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// userNameMaxBytes is the registry's max_utf8_bytes for defenseclaw.user.name.
const userNameMaxBytes = 256

// OptionalUserName renders an account name for defenseclaw.user.name: NFC,
// at most 256 bytes, starting with a letter or digit, and otherwise letters,
// digits, combining marks and . _ : / @ -. An account name in any script is
// kept (josé, GAP-0587); the ASCII identifier rule the other identifiers
// follow dropped it from every record and sink. Spaces, controls and format
// characters (bidirectional overrides) are refused.
func OptionalUserName(name string) Optional[string] {
	name = norm.NFC.String(strings.TrimSpace(name))
	if name == "" || len(name) > userNameMaxBytes || !utf8.ValidString(name) {
		return Absent[string]()
	}
	for i, r := range name {
		switch {
		case r < utf8.RuneSelf && (r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9'):
		case r >= utf8.RuneSelf && (unicode.IsLetter(r) || unicode.IsDigit(r)):
		case i > 0 && (strings.ContainsRune("._:/@-", r) || r >= utf8.RuneSelf && unicode.IsMark(r)):
		default:
			return Absent[string]()
		}
	}
	return Present(name)
}

// unicodeUserNames turns on the Unicode account-name rule for every producer
// of defenseclaw.user.name. The gateway sets it from its identity posture: it
// is off under the Secure Client integration, where every record keeps the
// ASCII rule of its producer byte for byte (issue #1092).
var unicodeUserNames atomic.Bool

// SetUnicodeUserNames records whether account names in any script are kept.
func SetUnicodeUserNames(v bool) { unicodeUserNames.Store(v) }

// UserName is the one defenseclaw.user.name normaliser every producer uses
// (GAP-0587, GAP-0822). A name with a non-ASCII character goes through
// OptionalUserName while Unicode names are on; an ASCII name, and every name
// while they are off, keeps the rule of the producer, so those records do not
// change.
func UserName(name string, ascii func(string) Optional[string]) Optional[string] {
	if unicodeUserNames.Load() && !isASCII(name) {
		return OptionalUserName(name)
	}
	return ascii(name)
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}
