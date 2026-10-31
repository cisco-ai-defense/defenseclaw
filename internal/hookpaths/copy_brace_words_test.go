// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"slices"
	"testing"

	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/syntax"
)

// TestCopyBraceWordFields: only plain-text brace words of a call are read
// as the words bash makes of them, within the argv bound (rel-1-0-6
// GAP-0202); anything else keeps the dynamic reading.
func TestCopyBraceWordFields(t *testing.T) {
	// Past the brace budget no reader parses the command (GAP-0187).
	if _, ok := parseShell(`cp a a{1..70000}`); ok {
		t.Error("a copy past the brace budget parses")
	}
	for _, row := range []struct {
		command string
		want    map[int][]string
	}{
		{`cp a.txt{,.orig}`, map[int][]string{1: {"a.txt", "a.txt.orig"}}},
		{`cp {a.txt,b.txt} dir/`, map[int][]string{1: {"a.txt", "b.txt"}}},
		{`cp /p/{a,b}/c x{,y}`, map[int][]string{1: {"/p/a/c", "/p/b/c"}, 2: {"x", "xy"}}},
		{`cp a.txt b.txt`, nil},
		{`cp "a b"{,.x}`, map[int][]string{1: {"a b", "a b.x"}}},
		{`cp a{"b",c}`, map[int][]string{1: {"ab", "ac"}}},
		{`cp {,a} d`, map[int][]string{1: {"a"}}},
		{`cp "$HOME"/k{,.x}`, map[int][]string{1: {"/home/u/k", "/home/u/k.x"}}},
		{`cp $USER{,.x}`, nil},
		{`cp {a,~/b}`, map[int][]string{1: {"a", "/home/u/b"}}},
		{`cp {a,~other/b} c`, nil},
		{`cp *{,.x} d`, nil},
		{`cp $HOME{,.x}`, map[int][]string{1: {"/home/u", "/home/u.x"}}},
		{`cp a{,$(id)}`, nil},
		{`cp a{1..3} d`, map[int][]string{1: {"a1", "a2", "a3"}}},
	} {
		file, ok := parseShell(row.command)
		if !ok {
			t.Fatalf("%s: does not parse", row.command)
		}
		call := file.Stmts[0].Cmd.(*syntax.CallExpr)
		env := expand.ListEnviron("HOME=/home/u")
		static := make([]bool, len(call.Args))
		for i, arg := range call.Args {
			_, static[i] = staticShellWord(arg, env, true)
		}
		got := copyBraceWordFields(call.Args, static, env)
		if len(got) != len(row.want) {
			t.Errorf("%s: got %v, want %v", row.command, got, row.want)
			continue
		}
		for i, words := range row.want {
			if !slices.Equal(got[i], words) {
				t.Errorf("%s: word %d got %v, want %v", row.command, i, got[i], words)
			}
		}
		_, words, wordStatic := spliceCopyBraceWords(call.Args, make([]string, len(call.Args)), static, got)
		if len(got) > 0 && (len(words) != len(wordStatic) || slices.Contains(wordStatic[1:], false) && len(got) == len(call.Args)-1) {
			t.Errorf("%s: splice gave %v %v", row.command, words, wordStatic)
		}
	}
}
