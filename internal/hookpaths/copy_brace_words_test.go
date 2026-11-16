// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"fmt"
	"slices"
	"strings"
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

// TestCopyBraceWordFieldsRangeAtTheCap: the GAP-0568 shortcut refuses a
// range only where the full expansion would take the call past the cap, so
// the GAP-0228 operands of a call at the cap are still read (a quoted part,
// an empty field and $HOME, before or after the range), and a call one past
// it keeps the dynamic reading, as the cap check after expanding gives.
// Commands this long never reach a reader (the brace budget refuses them
// first), so the call is parsed here without parseShell.
func TestCopyBraceWordFieldsRangeAtTheCap(t *testing.T) {
	env := expand.ListEnviron("HOME=/home/u")
	keys := []string{"/home/u/.ssh/authorized_keys", "/home/u/.ssh/authorized_keyx"}
	for _, row := range []struct {
		before, after string
		keysAt        int
	}{
		{`tee "$HOME"/.ssh/authorized_key{"s",x}`, ``, 1},
		{`tee`, `"$HOME"/.ssh/authorized_key{"s",x}`, 2},
		{`tee {,"$HOME"/.ssh/authorized_key{s,x}}`, ``, 1},
	} {
		// argv: tee, keys word, range word; the keys word makes 2 fields.
		for _, n := range []int{maxCopyBraceWords - 3, maxCopyBraceWords - 2} {
			rangeWord := fmt.Sprintf("out{1..%d}", n)
			command := strings.TrimSpace(row.before + " " + rangeWord + " " + row.after)
			file, err := syntax.NewParser().Parse(strings.NewReader(command), "")
			if err != nil {
				t.Fatalf("%s: %v", row.before, err)
			}
			call := file.Stmts[0].Cmd.(*syntax.CallExpr)
			static := make([]bool, len(call.Args))
			for i, arg := range call.Args {
				_, static[i] = staticShellWord(arg, env, true)
			}
			got := copyBraceWordFields(call.Args, static, env)
			past := 3+2-1+n-1 > maxCopyBraceWords
			switch {
			case past && got != nil:
				t.Errorf("%s %s: past the cap, got %d words, want the dynamic reading", row.before, rangeWord, len(got))
			case !past && (!slices.Equal(got[row.keysAt], keys) || len(got) != 2):
				t.Errorf("%s %s: at the cap, keys word %v, want %v", row.before, rangeWord, got[row.keysAt], keys)
			}
		}
	}
}

func TestActionExactOversizedTouchFieldsPaddedRange(t *testing.T) {
	for _, row := range []struct {
		command, middle, last string
	}{
		{`touch {0001..0300}`, "0150", "0300"},
		{`touch file{0001..0300}.txt`, "file0150.txt", "file0300.txt"},
		{`touch {0300..0001}`, "0151", "0001"},
	} {
		file, ok := parseShell(row.command)
		if !ok {
			t.Fatalf("parse %q", row.command)
		}
		word := file.Stmts[0].Cmd.(*syntax.CallExpr).Args[1]
		fields := actionExactOversizedTouchFields(word, "/tmp/home")
		if len(fields) != 300 {
			t.Errorf("%q: got %d fields, want 300", row.command, len(fields))
			continue
		}
		if fields[149] != row.middle || fields[299] != row.last {
			t.Errorf("%q: middle and last = %q, %q; want %q, %q", row.command, fields[149], fields[299], row.middle, row.last)
		}
	}
}

func TestGAP0431PaddedBraceStepAndSignedWidth(t *testing.T) {
	for _, row := range []struct {
		command string
		wantLen int
		at      int
		want    string
	}{
		{`touch {0300..0001..2}`, 150, 74, "0152"},
		{`touch {0001..0300..-2}`, 150, 74, "0149"},
		{`touch {0300..0001..-2}`, 150, 75, "0150"},
		{`touch {-0150..0150}`, 301, 298, "00148"},
		{`touch {-01..1}`, 3, 1, "000"},
	} {
		file, ok := parseShell(row.command)
		if !ok {
			t.Fatalf("parse %q", row.command)
		}
		word := file.Stmts[0].Cmd.(*syntax.CallExpr).Args[1]
		fields := actionMentionBraceFields(word, "/tmp/home")
		if len(fields) == 0 {
			fields = actionExactOversizedTouchFields(word, "/tmp/home")
		}
		got := ""
		if len(fields) > row.at {
			got = fields[row.at]
		}
		if len(fields) != row.wantLen || got != row.want {
			t.Errorf("%q: length %d, field %d = %q; want length %d, %q", row.command,
				len(fields), row.at, got, row.wantLen, row.want)
		}
	}
}

func TestGAP0431SignedStepBraceFields(t *testing.T) {
	for _, row := range []struct {
		command string
		want    []string
	}{
		{`touch {-0..+005..-2}`, []string{"0", "2", "4"}},
		{`touch {+005..-0..2}`, []string{"5", "3", "1"}},
		{`touch {1..5..-2}`, []string{"1", "3", "5"}},
		{`touch {5..1..2}`, []string{"5", "3", "1"}},
	} {
		file, ok := parseShell(row.command)
		if !ok {
			t.Fatalf("parse %q", row.command)
		}
		word := file.Stmts[0].Cmd.(*syntax.CallExpr).Args[1]
		if got := actionMentionBraceFields(word, "/tmp/home"); !slices.Equal(got, row.want) {
			t.Errorf("%q: got %v, want %v", row.command, got, row.want)
		}
	}
}
