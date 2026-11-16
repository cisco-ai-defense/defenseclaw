// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A loop whose list is proved empty never runs its body, a body assignment or
// a HOME assignment changes what the later words read, and code the shell
// never runs (a function nothing calls, a literal false branch) is not read
// outside the strict tier. A copy into the root of a protected tree is a
// protected write, as a copy into a file below it is (rel-1-0-6:GAP-0880,
// review 20). A literal false branch is left out of the loop-writer scan (the
// hookpaths test pins it), but the binding readings of the action, which have
// no reachability model, still read a protected path named in one, as they do
// for the same path without a loop; this table does not assert that case.
func TestLoopWriterJudgesKnownValuesAndReachableCode(t *testing.T) {
	home, project, parent := g235bBinderFixture(t)
	if err := os.WriteFile(filepath.Join(project, "a.txt"), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(home, ".defenseclaw", "hooks"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(parent, "ordinary", ".defenseclaw"), 0o700); err != nil {
		t.Fatal(err)
	}
	state := parent + `$u/.defenseclaw/config.yaml`
	rows := []struct {
		name, command string
		// loose is the verdict of the default and permissive tiers; strict
		// is set when the strict tier must block too (the rows that are
		// ordinary there keep the verdict of the other readings).
		protected, strict bool
	}{
		{"known-empty-list", `list=; for u in $list; do cp a.txt ` + state + `; done`, false, false},
		{"known-empty-quoted-word", `for u in ""; do cp a.txt ` + state + `; done`, false, false},
		{"known-empty-list-editor", `list=; for u in $list; do sed -i s/a/b/ ` + state + `; done`, false, false},
		{"body-rebinds-iterator", `for u in $USER; do u=ordinary; cp a.txt ` + state + `; done`, false, false},
		{"reassigned-home-tilde", `HOME=` + project + `; for u in $USER; do cp a.txt ~/.defenseclaw/config.yaml; done`, false, false},
		{"uncalled-function-loop", `f() { for u in $USER; do cp a.txt ` + state + `; done; }; :`, false, true},
		{"empty-word-beside-the-login", `list=; for u in $list $USER; do cp a.txt ` + state + `; done`, true, true},
		{"called-function-loop", `f() { for u in $USER; do cp a.txt ` + state + `; done; }; f`, true, true},
		{"true-branch-loop", `if true; then for u in $USER; do cp a.txt ` + state + `; done; fi`, true, true},
		{"home-unchanged-tilde", `for u in $USER; do cp a.txt ~/.defenseclaw/config.yaml; done`, true, true},
		{"write-before-the-iterator-moves", `for u in $USER; do cp a.txt ` + state + `; u=ordinary; done`, true, true},
		{"protected-source-copy", `source /dev/null; for u in $USER; do cp a.txt ` + state + `; done`, true, true},
		{"protected-literal-tree-root", `cp a.txt ` + filepath.Join(home, ".defenseclaw", "hooks"), true, true},
		{"protected-unknown-tree-root", `for u in $(ls ../..); do cp a.txt ` + parent + `$u/.defenseclaw/hooks; done`, true, true},
		{"protected-unknown-tree-child", `for u in $(ls ../..); do cp a.txt ` + parent + `$u/.defenseclaw/hooks/a.txt; done`, true, true},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			for _, connector := range []string{"claudecode", "codex"} {
				for _, managed := range []bool{false, true} {
					for _, pack := range []string{"", "permissive", "strict"} {
						if pack == "strict" && !row.protected && !row.strict {
							continue
						}
						want := row.protected
						if pack == "strict" {
							want = row.protected || row.strict
						}
						got := postSelfProtectionPackCell(t, home, project, connector, pack, managed, false, row.command)
						blocked := strings.HasPrefix(got, `{"action":"block"`)
						if blocked != want || want && !strings.Contains(got, "tamper.detector_state_write") {
							t.Errorf("%s managed=%t pack=%q: %s = %.240s; want block=%t", connector, managed, pack, row.command, got, want)
						}
					}
				}
			}
		})
	}
}
