// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"math/rand"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

// TestGAP0299NewItemScansMatchTheirRegexps: the byte scans that find the
// New-Item spellings of a text (rel-1-0-10:GAP-0299) give the matches of the
// regular expressions they replace, on random texts over the bytes the
// expressions read (both cases, every white space, the command separators, a
// word byte, a multi-byte rune) and on fixed rows.
func TestGAP0299NewItemScansMatchTheirRegexps(t *testing.T) {
	name := regexp.MustCompile(`(?i)\bnew-item\b`)
	alias := regexp.MustCompile(`(?i)(?:^|[\s;|&({])ni\s`)
	check := func(text string) {
		t.Helper()
		if got, want := newItemTextIndexes(text), name.FindAllStringIndex(text, -1); !reflect.DeepEqual(got, want) {
			t.Fatalf("newItemTextIndexes(%q) = %v, the regexp %v", text, got, want)
		}
		if got, want := newItemAliasIndexes(text), alias.FindAllStringIndex(text, -1); !reflect.DeepEqual(got, want) {
			t.Fatalf("newItemAliasIndexes(%q) = %v, the regexp %v", text, got, want)
		}
	}
	for _, text := range []string{
		"", "ni", "ni ", "ni x", " ni ni x", "ni ni ni\t", ";ni\n|ni\r&ni\f(ni {ni\v", "xni ", "_ni ", "Ni\tNI ",
		"new-item", "New-Item -ItemType SymbolicLink", "xnew-item", "new-items", "new-item_", "é" + "new-item" + "é",
		"new-itemnew-item", "new-item-new-item", "NEW-ITEM;new-item", "nnew-item", "new-ite", "ni new-item ni ",
		"powershell -c \"ni -Ty SymbolicLink a -Value b\"",
	} {
		check(text)
	}
	alphabet := []string{"n", "N", "i", "I", "e", "w", "-", "t", "m", "M", " ", "\t", "\n", "\r", "\f", "\v", ";", "|", "&", "(", "{", "_", "a", "1", "é", "new-item", "ni "}
	rng := rand.New(rand.NewSource(299))
	for range 20000 {
		var b strings.Builder
		for n := rng.Intn(24); n > 0; n-- {
			b.WriteString(alphabet[rng.Intn(len(alphabet))])
		}
		check(b.String())
	}
}
