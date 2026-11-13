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
	// earlier reads the word home, whose last letter an IFS of e strips, and
	// writes the protected directory it names.
	earlier := `f() { echo home | while read -r d; do sed -i s/a/b/ ` + parent + `$d/.defenseclaw/config.yaml; done; }; `
	readBody := `f() { read u <<< ordinary; ` + sibling + `; }; u=$USER; `
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
		// A statement that prints the name, or an option that only prints,
		// changes nothing.
		{"ifs-named-by-printf-text", `u=$USER; printf '%s\n' IFS=x; read u <<< ordinary; ` + sibling, false, true},
		{"ifs-named-by-declare-p", `u=$USER; declare -p IFS; read u <<< ordinary; ` + sibling, false, true},
		{"ifs-named-by-command-echo", `u=$USER; command echo IFS=x; read u <<< ordinary; ` + sibling, false, false},
		{"ifs-named-by-builtin-echo", `u=$USER; builtin echo IFS=x; read u <<< ordinary; ` + sibling, false, false},
		{"ifs-set-by-printf-v", `u=$USER; printf -v IFS x; read u <<< ordinary; ` + sibling, true, true},
		// A function runs with the state of each call the shell reaches. A
		// later call, or a call the shell never reaches, replaces no earlier
		// one.
		{"earlier-call-sees-the-word-a-later-ifs-would-strip", earlier + `f; IFS=e; f`, true, true},
		{"earlier-call-and-a-later-call-in-a-false-branch", earlier + `f; IFS=e; if false; then f; fi`, true, true},
		{"earlier-call-and-a-later-call-in-a-false-branch-through-a-function", `g() { f; }; ` + earlier + `f; IFS=e; if false; then g; fi`, true, true},
		{"earlier-call-and-a-later-call-after-a-failing-command", earlier + `f; IFS=e; false && f`, true, true},
		{"read-declared-after-the-call-and-a-call-in-a-false-branch", readBody + `f; read() { :; }; if false; then f; fi`, false, true},
		{"read-declared-after-the-call-and-a-call-after-a-failing-command", readBody + `f; read() { :; }; false && f`, false, true},
		{"read-declared-after-the-call-and-a-call-after-a-succeeding-command", readBody + `f; read() { :; }; true || f`, false, true},
		{"read-declared-before-a-call-that-runs", readBody + `read() { :; }; f`, true, true},
		{"ifs-set-after-the-call-and-a-call-in-a-false-branch", `f() { ` + readLoop + `; }; f; IFS=x; if false; then f; fi`, false, true},
		{"ifs-set-after-the-call-and-a-call-after-a-failing-command", `f() { ` + readLoop + `; }; f; IFS=x; false && f`, false, true},
		{"ifs-set-after-the-call-and-a-call-in-a-loop-that-never-runs", `f() { ` + readLoop + `; }; f; IFS=x; while false; do f; done`, false, true},
		{"ifs-set-after-the-call-and-a-call-that-may-run", `f() { ` + readLoop + `; }; f; IFS=x; if test -f /x; then f; fi`, true, true},
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
	// Each row is judged twice, not in all 12 cells (connector x per-user or
	// managed x default, permissive or strict), the owner's test budget: once
	// in the strict tier and once in a default-tier cell (the default or the
	// permissive pack), on the other connector and on the other side of
	// per-user and managed. So every row is judged by both connectors, per
	// user and managed, and in strict and a default tier. The rotation counts
	// rows per verdict pair (balanced, strict), so each pair walks all the
	// cells in turn; the check after the loop shows that every cell judged at
	// least one row that must block and one that must stay allowed.
	connectors := []string{"claudecode", "codex"}
	type cell struct {
		connector, pack string
		managed         bool
	}
	type judgment struct {
		name, command string
		cell          cell
		want          bool
		got           string
	}
	var judgments []judgment
	judged := map[cell][2]int{}
	turn := map[[2]bool]int{}
	for _, row := range rows {
		k := turn[[2]bool{row.balanced, row.strict}]
		turn[[2]bool{row.balanced, row.strict}]++
		strictManaged := (k/2)%2 == 1
		balancedPack := []string{"", "permissive"}[(k/4)%2]
		for _, c := range []cell{
			{connectors[k%2], "strict", strictManaged},
			{connectors[(k+1)%2], balancedPack, !strictManaged},
		} {
			want := row.balanced
			if c.pack == "strict" {
				want = row.strict
			}
			counts := judged[c]
			if want {
				counts[0]++
			} else {
				counts[1]++
			}
			judged[c] = counts
			judgments = append(judgments, judgment{name: row.name, command: row.command, cell: c, want: want})
		}
	}
	// Each call builds its own gateway and only reads the fixture, as
	// concurrent hooks do, so the calls run on every CPU; the checks read
	// the verdicts in row order.
	forEachOnEveryCPU(len(judgments), func(i int) {
		j := &judgments[i]
		j.got = postSelfProtectionPackCell(t, home, project, j.cell.connector, j.cell.pack, j.cell.managed, false, j.command)
	})
	for _, j := range judgments {
		c, got := j.cell, j.got
		block := strings.HasPrefix(got, `{"action":"block"`)
		if j.want && (!block || !strings.Contains(got, "tamper.detector_state_write")) {
			t.Errorf("%s %s managed=%t pack=%q: = %.200s, want protected block", j.name, c.connector, c.managed, c.pack, got)
		}
		if !j.want && block {
			t.Errorf("%s %s managed=%t pack=%q: = %.200s, want ordinary allow", j.name, c.connector, c.managed, c.pack, got)
		}
	}
	for _, connector := range connectors {
		for _, managed := range []bool{false, true} {
			for _, pack := range []string{"", "permissive", "strict"} {
				if counts := judged[cell{connector, pack, managed}]; counts[0] == 0 || counts[1] == 0 {
					t.Errorf("cell %s managed=%t pack=%q judged %d protected and %d ordinary rows; the rotation must give it both",
						connector, managed, pack, counts[0], counts[1])
				}
			}
		}
	}
}
