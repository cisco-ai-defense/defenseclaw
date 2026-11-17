// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"regexp"
	"strings"
	"testing"
)

// The byte scanner of the mention tokens finds the spans the regexp it
// replaces found, on ASCII, multibyte text and the literal-tilde mark.
func TestActionMentionTokenSpansMatchTheRegexp(t *testing.T) {
	want := regexp.MustCompile(`[A-Za-z0-9_./~*?\[\]\x1e-]+`)
	for _, text := range []string{
		"", " ", "cat ~/.ssh/authorized_keys", "echo é~/x Ω/.ssh", "a;b|c&&d", "x=[3-m,x-y] true",
		"cp a* [b]? " + actionLiteralTilde + "/.ssh/k", "\t\n~", strings.Repeat("ab cd ", 50), "日本/.ssh 語",
	} {
		var got [][]int
		for _, span := range actionMentionTokenSpans(text) {
			got = append(got, []int{span[0], span[1]})
		}
		exp := want.FindAllStringIndex(text, -1)
		if len(got) != len(exp) {
			t.Fatalf("%q: %v, want %v", text, got, exp)
		}
		for i := range exp {
			if got[i][0] != exp[i][0] || got[i][1] != exp[i][1] {
				t.Fatalf("%q: %v, want %v", text, got, exp)
			}
		}
		for i := 0; i < len(text); i++ {
			if actionMentionTokenByte(text[i]) != want.MatchString(text[i:i+1]) {
				t.Fatalf("%q byte %d: %v", text, i, actionMentionTokenByte(text[i]))
			}
		}
	}
}
