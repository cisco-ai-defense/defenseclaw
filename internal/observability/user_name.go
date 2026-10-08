// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package observability

import (
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// userNameMaxBytes is the registry's max_utf8_bytes for defenseclaw.user.name.
const userNameMaxBytes = 256

// OptionalUserName renders an account name for defenseclaw.user.name: NFC,
// at most 256 bytes, starting with a letter or digit, and otherwise letters,
// digits, combining marks and . _ : / @ -. An account name in any script is
// kept (dcad-eoé, GAP-0587); the ASCII identifier rule the other identifiers
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
