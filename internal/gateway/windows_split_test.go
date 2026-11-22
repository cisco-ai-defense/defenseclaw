// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"math/rand/v2"
	"slices"
	"testing"
	"unicode/utf8"
)

// TestWindowsSplitInPlaceMatchesTheRuneSplit pins the in-place split of a
// valid UTF-8 text to the rune split it replaced (rel-1-0-10:GAP-0299), in
// every dialect, for pipeline stages and statements, and the first tokens
// of a text to the first of all its tokens.
func TestWindowsSplitInPlaceMatchesTheRuneSplit(t *testing.T) {
	alphabet := []rune("ab |;&\n\r\t'\"`^é€ \u00a0x/\\-")
	separators := map[string]func(rune) bool{
		"segments":   func(r rune) bool { return r == '|' },
		"statements": func(r rune) bool { return r == ';' || r == '&' || r == '\n' || r == '\r' },
	}
	random := rand.New(rand.NewPCG(299, 4))
	for range 20000 {
		text := make([]rune, random.IntN(30))
		for i := range text {
			text[i] = alphabet[random.IntN(len(alphabet))]
		}
		command := string(text)
		if !utf8.ValidString(command) {
			t.Fatalf("corpus text %q is not valid UTF-8", command)
		}
		for _, dialect := range []windowsShellDialect{windowsDialectUnknown, windowsDialectPowerShell, windowsDialectCMD} {
			for name, separator := range separators {
				if got, want := windowsSplit(command, dialect, separator), windowsSplitRunes(command, dialect, separator); !slices.Equal(got, want) {
					t.Fatalf("%s of %q (dialect %d) = %q, the rune split gives %q", name, command, dialect, got, want)
				}
			}
			all := windowsTokens(command, dialect)
			if got, want := windowsTokensUpTo(command, dialect, 3), all[:min(3, len(all))]; !slices.Equal(got, want) {
				t.Fatalf("first tokens of %q (dialect %d) = %q, want %q", command, dialect, got, want)
			}
		}
	}
	if got := windowsStatements("a\xffb;c", windowsDialectCMD); !slices.Equal(got, []string{"a\uFFFDb", "c"}) {
		t.Fatalf("invalid UTF-8 split = %q, want each invalid byte as U+FFFD", got)
	}
}
