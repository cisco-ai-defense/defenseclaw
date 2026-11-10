// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// callStateRow is a command and what each profile does with it: the default and
// permissive packs allow an ordinary command, the strict pack may block it, and a
// command that writes DefenseClaw state blocks in every profile.
type callStateRow struct {
	name, command string
	protected     bool
}

func checkCallStateRows(t *testing.T, home, project string, rows []callStateRow) {
	t.Helper()
	for _, row := range rows {
		for _, connector := range []string{"claudecode", "codex"} {
			for _, managed := range []bool{false, true} {
				for _, pack := range []string{"", "permissive", "strict"} {
					got := postSelfProtectionPackCell(t, home, project, connector, pack, managed, false, row.command)
					block := strings.HasPrefix(got, `{"action":"block"`)
					if block != row.protected && (row.protected || pack != "strict") {
						t.Errorf("%s %s managed=%t pack=%q: block=%t, want %t: %.180s", row.name, connector, managed, pack, block, row.protected, got)
					}
					if row.protected && block && !strings.Contains(got, "tamper.detector_state_write") {
						t.Errorf("%s %s managed=%t pack=%q: blocked for another reason: %.180s", row.name, connector, managed, pack, got)
					}
				}
			}
		}
	}
}

// rel-1-0-6:GAP-0880, GAP-0885 review 9: a function runs with the state of each
// call. A call that reads its here-string with the builtin names the file it
// writes, whatever a later call of the same function meets (a function named
// read, an IFS); and a command whose calls all name ordinary files stays
// allowed in the default and permissive packs.
func TestFunctionCallsEachRunWithTheirOwnReadOfAHereString(t *testing.T) {
	home, project, parent := g235bBinderFixture(t)
	active := filepath.Base(home)
	protectedBody := `f() { read d <<< ` + active + `; sed -i s/a/b/ ` + parent + `$d/.defenseclaw/config.yaml; }; `
	ordinaryBody := `f() { read u <<< ordinary; sed -i s/a/b/ ` + parent + `$u/aliasdir/config.yaml; }; `
	checkCallStateRows(t, home, project, []callStateRow{
		{"first call reads the login, later call follows a read function", protectedBody + `f; read() { :; }; d=ordinary; f`, true},
		{"same through a caller", `g() { f; }; ` + protectedBody + `g; read() { :; }; d=ordinary; g`, true},
		{"first call reads the login, later call follows an IFS", protectedBody + `f; IFS=x; d=ordinary; f`, true},
		{"every call reads an ordinary word", ordinaryBody + `u=$USER; f; read() { :; }; u=ordinary; f`, false},
		{"same through a caller, ordinary", `g() { f; }; ` + ordinaryBody + `u=$USER; g; read() { :; }; u=ordinary; g`, false},
	})
}

// The same holds when the read is in the body of a for loop in the function:
// the first call binds the loop variable to the login (the file itself or a
// link to it), the later call leaves the word of the list.
func TestFunctionCallsEachRunWithTheirOwnReadInAForLoop(t *testing.T) {
	home, project, parent := g235bBinderFixture(t)
	active := filepath.Base(home)
	loop := func(word, target string) string {
		return `f() { for d in ordinary; do read d <<< ` + word + `; sed -i s/a/b/ ` + parent + `$d/` + target + `; done; }; f; read() { :; }; f`
	}
	checkCallStateRows(t, home, project, []callStateRow{
		{"first call reads the login, file", loop(active, ".defenseclaw/config.yaml"), true},
		{"first call reads the login, link", loop(active, "aliasdir/config.yaml"), true},
		{"every call reads an ordinary word", loop("ordinary", "aliasdir/config.yaml"), false},
	})
}

// A print flag after an assignment of IFS does not stop the assignment: the
// read loop after it splits its word at the new delimiter and names a link to
// DefenseClaw state. A print flag in front of the assignment prints and sets
// nothing.
func TestDeclareOptionAfterAnIFSAssignmentStillSetsIFS(t *testing.T) {
	home, project, _ := g235bBinderFixture(t)
	if err := os.MkdirAll(filepath.Join(home, "aliasdirx"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "aliasdirx", "config.yaml"), []byte("ordinary\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	loop := `echo aliasdirx | while read -r d; do sed -i s/a/b/ ` + home + `/$d/config.yaml; done`
	checkCallStateRows(t, home, project, []callStateRow{
		{"declare assignment then print flag", `declare IFS=x -p; ` + loop, true},
		{"typeset assignment then print flag", `typeset IFS=x -p; ` + loop, true},
		{"declare assignment then function flag", `declare IFS=x -f; ` + loop, true},
		{"declare print flag then assignment", `declare -p IFS=x; ` + loop, false},
	})
}
