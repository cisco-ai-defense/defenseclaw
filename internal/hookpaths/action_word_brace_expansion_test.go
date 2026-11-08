// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"strings"
	"testing"

	"mvdan.cc/sh/v3/syntax"
)

// A word is brace-expanded only for an unquoted, closed pair of braces with a
// comma or a sequence at its top level; the other brace characters are literal text.
func TestActionWordBraceExpandsOnlyForACommaOrSequence(t *testing.T) {
	cases := []struct {
		word string
		want bool
	}{
		{"a{b,c}", true},
		{"{a,b}", true},
		{"x{a,b}y", true},
		{"{1..3}", true},
		{"{a..c}", true},
		{"{,a}", true},
		{"{a,{b,c}}", true},
		{"{{a,b}}", true},
		{"a{b}c", false},
		{"home{one}/.defenseclaw/config.yaml", false},
		{"{}", false},
		{"{a", false},
		{"{a,b", false},
		{"a{b,c", false},
		{"notes{a,b", false},
		{"{a..b", false},
		{"{a,{b", false},
		{"{a,{b,c}", true},
		{"{a,b}{c,d", true},
		{"{a,b}x{", true},
		{"a}", false},
		{"a,b", false},
		{"a..b", false},
		{"{a{b}c}", false},
		{"\\{a,b\\}", false},
		{"{a\\,b}", false},
		{"{a\",\"b}", false},
		{"{a$X,b}", true},
		{"\"$X\"{a}", false},
		{"$X{a}", false},
		{"${X}{a,b}", true},
	}
	for _, tc := range cases {
		t.Run(tc.word, func(t *testing.T) {
			file, err := syntax.NewParser().Parse(strings.NewReader("echo "+tc.word), "")
			if err != nil {
				t.Fatal(err)
			}
			call := file.Stmts[0].Cmd.(*syntax.CallExpr)
			if got := actionWordBraceExpands(call.Args[1]); got != tc.want {
				t.Errorf("actionWordBraceExpands(%q)=%v want %v", tc.word, got, tc.want)
			}
		})
	}
}
