// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"fmt"
	"math/rand/v2"
	"reflect"
	"strings"
	"testing"

	"mvdan.cc/sh/v3/syntax"
)

// gap1152Folders is posixWorkFolders of command, with the second pass of
// every loop read (every) or not.
func gap1152Folders(t *testing.T, command string, every bool) (folders, unread map[*syntax.Stmt]workFolders, file *syntax.File) {
	t.Helper()
	file, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(command), "")
	if err != nil {
		t.Fatalf("%q: %v", command, err)
	}
	workFolderEveryLoopPass = every
	defer func() { workFolderEveryLoopPass = false }()
	folders, unread = posixWorkFolders(file)
	return folders, unread, file
}

// TestGAP1152LoopReadingsAgreeWithEveryPass: a loop whose first pass leaves
// the shell where it started reads its body once; every statement keeps the
// folders the reading of both passes gave it (substrate-1 GAP-1152).
func TestGAP1152LoopReadingsAgreeWithEveryPass(t *testing.T) {
	parts := []string{"ls", "cd src", "cd ..", "cd /tmp", "cd \"$D\"", "pushd a", "popd", "f", "g", "return 0",
		"cd src || exit", "test -d x && cd x", "break", "continue", "echo m > config.yaml", "cat <(cd /tmp; ls)",
		"( cd sub )", "{ cd grp; }", "true | cd pipe"}
	wrap := []func(string) string{
		func(body string) string { return "for i in 1 2; do " + body + "; done" },
		func(body string) string { return "while read l; do " + body + "; done" },
		func(body string) string { return "until cd up; do " + body + "; done" },
		func(body string) string { return "if true; then " + body + "; fi" },
		func(body string) string { return "case $x in a) " + body + ";; esac" },
		func(body string) string { return "h() { " + body + "; }; h" },
	}
	rng := rand.New(rand.NewPCG(1152, 2))
	var build func(depth int) string
	build = func(depth int) string {
		n := 1 + rng.IntN(3)
		stmts := make([]string, 0, n)
		for range n {
			if depth > 0 && rng.IntN(2) == 0 {
				stmts = append(stmts, wrap[rng.IntN(len(wrap))](build(depth-1)))
				continue
			}
			stmts = append(stmts, parts[rng.IntN(len(parts))])
		}
		return strings.Join(stmts, "; ")
	}
	commands := []string{
		strings.Repeat("for i in 1; do ", 6) + ":;" + strings.Repeat(" done;", 6),
		strings.Repeat("for i in 1; do cd a; ", 4) + "ls;" + strings.Repeat(" done;", 4),
		"f() { cd ~/.defenseclaw; }; for i in 1 2; do for j in 1; do f; done; done; echo m > config.yaml",
		"for i in 1 2; do for j in 1; do cd src || return; done; done; ls",
	}
	for range 3000 {
		commands = append(commands, "f() { cd fdir; }; g() { :; }; "+build(4))
	}
	for _, command := range commands {
		got, gotUnread, file := gap1152Folders(t, command, false)
		want, wantUnread, _ := gap1152Folders(t, command, true)
		// The maps are keyed by the statements of two parses: compare them
		// by position.
		byPos := func(m map[*syntax.Stmt]workFolders) map[string]workFolders {
			out := make(map[string]workFolders, len(m))
			for stmt, folders := range m {
				out[fmt.Sprintf("%d-%d", stmt.Pos().Offset(), stmt.End().Offset())] = folders
			}
			return out
		}
		if !reflect.DeepEqual(byPos(got), byPos(want)) || !reflect.DeepEqual(byPos(gotUnread), byPos(wantUnread)) {
			t.Fatalf("%q: folders differ from the every-pass reading", command)
		}
		_ = file
	}
}

// TestGAP1152NestedLoopsReadLinearly: the work of the folder reading of
// nested loops grows with the depth, not 2^depth (substrate-1 GAP-1152: 20
// nested for loops took minutes on the laptop and in the actor).
func TestGAP1152NestedLoopsReadLinearly(t *testing.T) {
	nest := func(depth int) string {
		return strings.Repeat("for i in 1; do ", depth) + "echo 1 >/dev/null; ls docs; git status;" + strings.Repeat(" done;", depth)
	}
	allocs := func(depth int) float64 {
		file, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(nest(depth)), "")
		if err != nil {
			t.Fatal(err)
		}
		return testing.AllocsPerRun(3, func() { posixWorkFolders(file) })
	}
	low, high := allocs(10), allocs(20)
	if high > 4*low {
		t.Fatalf("folder reading of 20 nested loops: %.0f allocations, of 10: %.0f (want linear growth)", high, low)
	}
}
