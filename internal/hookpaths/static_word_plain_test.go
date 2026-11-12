// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"strings"
	"testing"

	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/syntax"
)

// A word of plain path characters expands to itself: the shortcut of
// plainLiteralWord must give what the full expansion gives, for every word
// it takes and none it should not (GAP-0483).
func TestPlainLiteralWordMatchesTheFullExpansion(t *testing.T) {
	t.Parallel()
	words := []string{
		"lo1.txt", "a/b/c.txt", "./x", "../x", "-n", "--flag=value", "a:b,c@d%e+f=g", "/", ".", "..", "x-y_z",
		"~", "~/x", "~root", "a~b", "a*", "?x", "[ab]", "{a,b}", "{a}", "a{1..3}", "\x27q\x27", "\"q\"", "a\\ b",
		"$HOME", "${HOME}/x", "$X", "$(id)", "`id`", "a#b", "a!b", "ünï", "a\tb",
	}
	env := expand.ListEnviron("HOME=/home/u")
	for _, text := range words {
		file, err := syntax.NewParser().Parse(strings.NewReader("true "+text), "")
		if err != nil {
			continue
		}
		call, ok := file.Stmts[0].Cmd.(*syntax.CallExpr)
		if !ok || len(call.Args) != 2 {
			continue
		}
		word := call.Args[1]
		got, taken := plainLiteralWord(word)
		want, wantOK := expandStaticShellWord(word, env, true)
		if taken && (!wantOK || got != want) {
			t.Errorf("%q: shortcut %q, full expansion %q (%v)", text, got, want, wantOK)
		}
		if full, fullOK := staticShellWord(word, env, true); full != want || fullOK != wantOK {
			t.Errorf("%q: staticShellWord %q (%v), full expansion %q (%v)", text, full, fullOK, want, wantOK)
		}
	}
	for _, plain := range []string{"lo1.txt", "a/b/c.txt", "-n", "x-y_z"} {
		file, _ := syntax.NewParser().Parse(strings.NewReader("true "+plain), "")
		if _, taken := plainLiteralWord(file.Stmts[0].Cmd.(*syntax.CallExpr).Args[1]); !taken {
			t.Errorf("%q: a plain word is not taken by the shortcut", plain)
		}
	}
}

// The answers of resolveWriteTarget are kept by the exact path within an
// evaluation: the scans of one call ask for the same operands again.
func TestTargetMemoResolveWriteTargetIsStableWithinAnEvaluation(t *testing.T) {
	dir := t.TempDir()
	memo := NewTargetMemo()
	first, firstOK := memo.resolveWriteTarget(dir + "/lo1.txt")
	again, againOK := memo.resolveWriteTarget(dir + "/lo1.txt")
	if first != again || firstOK != againOK || !firstOK {
		t.Fatalf("first %q (%v), again %q (%v)", first, firstOK, again, againOK)
	}
	if len(memo.resolved) != 1 {
		t.Fatalf("memo holds %d answers, want 1", len(memo.resolved))
	}
	plain, plainOK := ResolveWriteTarget(dir + "/lo1.txt")
	if plain != first || plainOK != firstOK {
		t.Fatalf("memo %q (%v), plain %q (%v)", first, firstOK, plain, plainOK)
	}
}
