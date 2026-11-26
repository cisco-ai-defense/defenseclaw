// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package winpath

import (
	"unicode"
	"unicode/utf8"
)

// equalNames compares rune by rune through the simple uppercase mapping, the
// rule the NTFS uppercase table follows; invalid UTF-8 compares by byte.
func equalNames(a, b string) bool {
	if a == b {
		return true
	}
	for a != "" && b != "" {
		left, leftSize := utf8.DecodeRuneInString(a)
		right, rightSize := utf8.DecodeRuneInString(b)
		if left == utf8.RuneError && leftSize == 1 || right == utf8.RuneError && rightSize == 1 {
			if a[:leftSize] != b[:rightSize] {
				return false
			}
		} else if left != right && unicode.ToUpper(left) != unicode.ToUpper(right) {
			return false
		}
		a, b = a[leftSize:], b[rightSize:]
	}
	return a == "" && b == ""
}
