// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package shellparse

import (
	"strings"
	"testing"

	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/syntax"
)

// TestMinBraceFieldsIsALowerBoundOfTheExpansion checks MinBraceFields
// against expand.Fields: it is the element count of the largest range, and
// never more fields than the expansion makes, so a reader that refuses a
// word on it returns what the full expansion would have returned.
func TestMinBraceFieldsIsALowerBoundOfTheExpansion(t *testing.T) {
	for _, tc := range []struct {
		word string
		want uint64
	}{
		{"plain", 0},
		{"{a,b}", 0},
		{"{,}", 0},
		{"{,a}", 0},
		{"README.md{,.bak}", 0},
		{"'{1..9}'", 0},
		{`"{1..9}"`, 0},
		// expand.Fields splits an escaped brace too, so the readers see 9.
		{`\{1..9}`, 9},
		{"{1..a}", 0},
		{"{1..}", 0},
		{"{5..5}", 1},
		{"{1..5..10}", 1},
		{"{1..3}", 3},
		{"a{1..3}b", 3},
		{"{a..e}", 5},
		{"{z..a}", 26},
		{"{-2..2}", 5},
		{"{01..10}", 10},
		{"{1..10..3}", 4},
		{"{10..1..-3}", 4},
		{"{1..10..-3}", 10},
		{"{,{1..3}}", 3},
		{"{x,y}{1..4}", 4},
		{"{1..4}{1..7}", 7},
		{"~/.ssh/authorized_key{r..t}", 3},
		{"{1..60000}", 60000},
	} {
		file, err := syntax.NewParser().Parse(strings.NewReader("echo "+tc.word), "")
		if err != nil {
			t.Fatalf("%s: %v", tc.word, err)
		}
		word := file.Stmts[0].Cmd.(*syntax.CallExpr).Args[1]
		got := MinBraceFields(word)
		if got != tc.want {
			t.Errorf("MinBraceFields(%s) = %d, want %d", tc.word, got, tc.want)
		}
		fields, err := expand.Fields(&expand.Config{}, word)
		if err != nil {
			t.Fatalf("%s: expand: %v", tc.word, err)
		}
		if got > uint64(len(fields)) {
			t.Errorf("MinBraceFields(%s) = %d, more than the %d fields it expands to", tc.word, got, len(fields))
		}
	}
	if MinBraceFields(nil) != 0 {
		t.Error("MinBraceFields(nil) != 0")
	}
}
