// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// rel-1-0-6:GAP-0880, GAP-0885 review 6: a loop variable takes the value its
// loop gives it unless code that the shell certainly runs replaces the
// builtin read or sets IFS first. The default and permissive tiers follow only
// the top-level statements before the loop; a function declared or an IFS set
// in an uncalled function, a branch that does not run, or after the loop is no
// reason to block an ordinary command. The strict tier counts that code
// whether it runs or not, so a protected target judged under it blocks. The
// loops of the two rows as filed block in every tier.
func TestLoopBindingsFollowTopLevelCodeInDefaultTiersAndAllCodeInStrict(t *testing.T) {
	home, project, parent := g235bBinderFixture(t)
	ordinaryDir := filepath.Join(home, "aliasdirx")
	if err := os.MkdirAll(ordinaryDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ordinaryDir, "config.yaml"), []byte("ordinary\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sibling := `sed -i s/a/b/ ` + parent + `$u/aliasdir/config.yaml`
	direct := `sed -i s/a/b/ ` + parent + `$u/.defenseclaw/config.yaml`
	own := `sed -i s/a/b/ ` + home + `/$d/config.yaml`
	readLoop := `echo aliasdirx | while read -r d; do ` + own + `; done`
	missing := filepath.Join(project, "missing", "out")
	rows := []struct {
		name, command string
		// balanced and strict are the verdicts: true is the protected block.
		balanced, strict bool
	}{
		// Code that may never run before the loop: ordinary in the default and
		// permissive tiers, a block in the strict tier.
		{"read-declared-in-an-uncalled-function", `f() { read() { :; }; }; for u in $USER; do read u <<< ordinary; ` + sibling + `; done`, false, true},
		{"read-declared-in-a-false-branch", `if false; then read() { :; }; fi; for u in $USER; do read u <<< ordinary; ` + sibling + `; done`, false, true},
		{"read-declared-after-the-function-that-runs-the-loop", `f() { for u in $USER; do read u <<< ordinary; ` + sibling + `; done; }; f; read() { :; }`, false, true},
		{"ifs-set-in-a-function-declared-before-the-loop-and-never-called", `f() { IFS=x; }; ` + readLoop, false, false},
		{"read-declared-after-the-loop", `for u in $USER; do read u <<< ordinary; ` + sibling + `; done; read() { :; }`, false, false},
		{"ifs-set-by-a-function-declared-after-the-loop", `for i in 1 2; do ` + readLoop + `; f; done; f() { IFS=x; }`, false, true},
		{"ifs-set-by-a-function-called-from-an-uncalled-one", `f() { IFS=x; }; for i in 1 2; do h() { f; }; ` + readLoop + `; done`, false, true},
		{"ifs-set-in-a-false-branch-after-the-read", `for i in 1 2; do ` + readLoop + `; if false; then IFS=x; fi; done`, false, true},
		{"ifs-set-in-a-false-branch-before-the-loop", `if false; then IFS=x; fi; ` + readLoop, false, true},
		// Code that runs on the straight-line path before the loop: a block in
		// every tier.
		{"read-declared-before-the-loop", `read() { :; }; for u in $USER; do read u <<< ordinary; ` + sibling + `; done`, true, true},
		{"read-declared-before-the-while-read-keeps-the-login", `u=$USER; read() { :; }; echo ordinary | while read -r u; do ` + direct + `; break; done`, true, true},
		{"read-declared-before-the-while-read-keeps-the-login-link", `u=$USER; read() { :; }; echo ordinary | while read -r u; do ` + sibling + `; break; done`, true, true},
		{"ifs-set-before-the-loop", `IFS=x; ` + readLoop, true, true},
		{"ifs-exported-before-the-loop", `export IFS=x; ` + readLoop, true, true},
		{"ifs-from-a-variable-before-the-loop", `sep=x; IFS=$sep; ` + readLoop, true, true},
		{"here-string-read-with-a-failing-redirect-link", `for u in $USER; do read u <<< ordinary > ` + missing + `; ` + sibling + `; done`, true, true},
		{"here-string-read-with-a-failing-redirect-direct", `for u in $USER; do read u <<< ordinary > ` + missing + `; ` + direct + `; done`, true, true},
		// The rows as filed, and their benign twins.
		{"filed-for-list-login", `for u in $USER; do ` + direct + `; done`, true, true},
		{"filed-for-list-logname", `for u in ${LOGNAME}; do ` + direct + `; done`, true, true},
		{"filed-while-read-login", `echo $USER | while read -r u; do ` + direct + `; done`, true, true},
		{"filed-while-read-link", `echo aliasdir | while read -r d; do ` + own + `; done`, true, true},
		{"for-list-of-other-names", `for u in alice bob; do sed -i s/a/b/ ` + parent + `$u/notes.txt; done`, false, false},
		{"while-read-of-an-ordinary-name", `echo aliasdirx | while read -r d; do sed -i s/a/b/ ` + home + `/$d/notes.txt; done`, false, false},
	}
	for _, connector := range []string{"claudecode", "codex"} {
		for _, managed := range []bool{false, true} {
			for _, pack := range []string{"", "permissive", "strict"} {
				for _, row := range rows {
					want := row.balanced
					if pack == "strict" {
						want = row.strict
					}
					got := postSelfProtectionPackCell(t, home, project, connector, pack, managed, false, row.command)
					block := strings.HasPrefix(got, `{"action":"block"`)
					if want && (!block || !strings.Contains(got, "tamper.detector_state_write")) {
						t.Errorf("%s %s managed=%t pack=%q: = %.200s, want protected block", row.name, connector, managed, pack, got)
					}
					if !want && block {
						t.Errorf("%s %s managed=%t pack=%q: = %.200s, want ordinary allow", row.name, connector, managed, pack, got)
					}
				}
			}
		}
	}
}
