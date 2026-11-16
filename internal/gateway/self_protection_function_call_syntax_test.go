// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"testing"
)

// rel-1-0-6:GAP-0880, GAP-0885 round 11: the hook client decides from the
// syntax tree whether a command has a straight-line reading to describe, so a
// function spelled any way the parser accepts (f ( ) { ...; }, function<TAB>f)
// is read as f() is. A call that reads a login into its variable and writes
// through a link to the protected config is blocked for a managed gateway too.
func TestSpacedFunctionSyntaxReadsEachCall(t *testing.T) {
	home, project, parent := g235bBinderFixture(t)
	active := filepath.Base(home)
	checkCallStateRows(t, home, project, []callStateRow{
		{"spaced parentheses, protected link", `f ( ) { read d <<< ` + active + `; sed -i s/a/b/ ` + parent + `$d/aliasdir/config.yaml; }; f; read ( ) { :; }; d=ordinary; f`, true},
		{"keyword and tab, protected link", "function\tf { read d <<< " + active + "; sed -i s/a/b/ " + parent + "$d/aliasdir/config.yaml; }; f; function\tread { :; }; d=ordinary; f", true},
		{"spaced parentheses, ordinary link", `f ( ) { read d <<< ordinary; sed -i s/a/b/ ` + parent + `$d/aliasdir/config.yaml; }; f; read ( ) { :; }; d=ordinary; f`, false},
		{"spaced parentheses, for loop, protected link", `f ( ) { for d in ordinary; do read d <<< ` + active + `; sed -i s/a/b/ ` + parent + `$d/aliasdir/config.yaml; done; }; f; read ( ) { :; }; f`, true},
		{"spaced parentheses, for loop, ordinary link", `f ( ) { for d in ordinary; do read d <<< ordinary; sed -i s/a/b/ ` + parent + `$d/aliasdir/config.yaml; done; }; f; read ( ) { :; }; f`, false},
	})
}

// A declare or typeset option after the first name is no option (bash sets the
// name and reports the word), so declare d=x -g inside a function makes d
// local and leaves the caller's d as it was: a write through the caller's d
// still reaches the protected config, directly, through a link, or in a for
// loop over it. Leading -g sets the caller's value.
func TestDeclareOptionAfterAnAssignmentKeepsTheCallersValue(t *testing.T) {
	home, project, _ := g235bBinderFixture(t)
	checkCallStateRows(t, home, project, []callStateRow{
		{"declare late -g, direct", `d=.defenseclaw; f() { declare d=ordinary -g; }; f; sed -i s/a/b/ ` + home + `/$d/config.yaml`, true},
		{"typeset late -g, direct", `d=.defenseclaw; f() { typeset d=ordinary -g; }; f; sed -i s/a/b/ ` + home + `/$d/config.yaml`, true},
		{"declare late -g, link", `d=aliasdir; f() { declare d=ordinary -g; }; f; sed -i s/a/b/ ` + home + `/$d/config.yaml`, true},
		{"declare late -g, for loop over the value", `d=.defenseclaw; f() { declare d=ordinary -g; }; f; for u in $d; do sed -i s/a/b/ ` + home + `/$u/config.yaml; done`, true},
		{"typeset late -g, for loop over a link", `d=aliasdir; f() { typeset d=ordinary -g; }; f; for u in $d; do sed -i s/a/b/ ` + home + `/$u/config.yaml; done`, true},
		{"declare leading -g, direct", `d=.defenseclaw; f() { declare -g d=ordinary; }; f; sed -i s/a/b/ ` + home + `/$d/config.yaml`, false},
		{"declare leading -g, for loop", `d=.defenseclaw; f() { declare -g d=ordinary; }; f; for u in $d; do sed -i s/a/b/ ` + home + `/$u/config.yaml; done`, false},
	})
}

// A here-string read that binds in some calls of its function and not in
// others has a reading for each call. The command blocks when a reading
// reaches state, and an ordinary copy stays allowed in the default and
// permissive packs, managed or not: a managed gateway finds the answer for the
// path a followed variable gives in the hook client map.
func TestMixedCallsOfAHereStringReadJudgeEachReading(t *testing.T) {
	home, project, parent := g235bBinderFixture(t)
	active := filepath.Base(home)
	if err := os.MkdirAll(filepath.Join(project, "build"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "a.txt"), []byte("ordinary\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	checkCallStateRows(t, home, project, []callStateRow{
		{"ordinary copy, later call without the builtin", `f() { read d <<< ordinary; cp a.txt build/$d.txt; }; f; read() { :; }; f`, false},
		{"ordinary copy through a caller", `g() { f; }; f() { read d <<< ordinary; cp a.txt build/$d.txt; }; g; read() { :; }; g`, false},
		{"ordinary copy, every call reads the builtin", `f() { read d <<< ordinary; cp a.txt build/$d.txt; }; f; f`, false},
		{"ordinary copy, plain assignment", `d=ordinary; cp a.txt build/$d.txt`, false},
		{"protected link, later call without the builtin", `f() { read d <<< ` + active + `; sed -i s/a/b/ ` + parent + `$d/aliasdir/config.yaml; }; f; read() { :; }; f`, true},
	})
}
