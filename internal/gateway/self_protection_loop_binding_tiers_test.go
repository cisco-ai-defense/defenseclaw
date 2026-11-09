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
	// resolved is the reading of direct with the login in place of $u.
	resolved := `sed -i s/a/b/ '` + parent + filepath.Base(home) + `/.defenseclaw/config.yaml'`
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
		// The shell runs a top-level statement before it calls the function
		// that follows it, wherever the function is written.
		{"ifs-set-before-the-call-of-the-function-that-runs-the-loop", `f() { ` + readLoop + `; }; IFS=x; f`, true, true},
		{"ifs-set-before-one-call-of-the-function-and-after-another", `f() { ` + readLoop + `; }; f; IFS=x; f`, true, true},
		{"ifs-set-after-the-only-call-of-the-function", `f() { ` + readLoop + `; }; f; IFS=x`, false, false},
		{"read-declared-before-the-call-of-the-function", `f() { read u <<< ordinary; ` + sibling + `; }; u=$USER; read() { :; }; f`, true, true},
		{"read-declared-before-the-call-of-the-function-that-calls-it", `h() { f; }; f() { read u <<< ordinary; ` + sibling + `; }; u=$USER; read() { :; }; h`, true, true},
		{"read-declared-after-the-call-of-the-function", `f() { read u <<< ordinary; ` + sibling + `; }; u=$USER; f; read() { :; }`, false, true},
		// The name IFS as an argument, or as the prefix of one command, leaves
		// the IFS of the shell as it is.
		{"ifs-printed-before-the-here-string-read", `u=$USER; echo IFS=x; read u <<< ordinary; ` + sibling, false, true},
		{"ifs-set-for-one-command-before-the-here-string-read", `u=$USER; IFS=x env true; read u <<< ordinary; ` + sibling, false, true},
		{"while-read-of-an-ordinary-word-after-the-login-was-assigned", `u=$USER; echo ordinary | while read -r u; do ` + sibling + `; done`, false, true},
		{"while-read-of-the-login-after-the-login-was-assigned", `u=$USER; echo $USER | while read -r u; do ` + direct + `; done`, true, true},
		{"ifs-printed-before-the-while-read", `u=$USER; echo IFS=x; echo ordinary | while read -r u; do ` + sibling + `; done`, false, true},
		{"ifs-unset-before-the-here-string-read", `u=$USER; unset IFS; read u <<< ordinary; ` + sibling, true, true},
		// The text of a reading spelled where it does not run hides nothing.
		{"select-with-the-reading-in-a-comment", `select u in $USER; do ` + direct + `; break; done # ` + resolved, true, true},
		{"select-with-the-reading-in-a-quoted-word", `select u in $USER; do ` + direct + `; break; done; echo "` + resolved + `"`, true, true},
		{"select-with-the-reading-in-a-here-document", "select u in $USER; do " + direct + "; break; done; cat <<'EOF'\n" + resolved + "\nEOF", true, true},
		{"select-of-the-login", `select u in $USER; do ` + direct + `; break; done`, true, true},
		{"select-of-other-names-with-a-reading-in-a-comment", `select u in alice bob; do sed -i s/a/b/ ` + parent + `$u/notes.txt; break; done # ` + resolved, false, false},
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
