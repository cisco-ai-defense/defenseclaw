// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
)

// rel-1-0-6:GAP-0630, GAP-0601, GAP-0681 review 5: USER and LOGNAME keep the
// value the shell gives them where each word is read, whatever else the
// action does to the names later or in another statement. A write that
// names DefenseClaw state through the login the home spells blocks in
// every profile when a select, for, read, assignment, export, eval, printf
// -v or sourced file binds the name after it, in a list, group, if, loop
// or subshell, and when an eval that binds nothing comes before it. A name
// that a read or a loop has bound is not that login: the same write into a
// sibling or a project file stays allowed (default and permissive packs)
// and a file it reaches only through a link on disk is not named.
func TestG235bBinderClassKnownValues(t *testing.T) {
	home, project, parent := g235bBinderFixture(t)
	const sq = "\x27"
	type row struct {
		name, command string
		protected     bool
	}
	var rows []row
	for _, name := range []string{"USER", "LOGNAME"} {
		v := "$" + name
		editor := `sed -i d ` + parent + v + `/aliasdir/config.yaml`
		redirect := `printf x > ` + parent + v + `/statealias`
		later := []string{
			`select ` + name + ` in ordinary; do break; done`,
			`for ` + name + ` in ordinary; do :; done`,
			`read ` + name + ` </dev/null`,
			name + `=ordinary`,
			`export ` + name + `=ordinary`,
			`eval ` + sq + name + `=ordinary` + sq,
			`printf -v ` + name + ` x`,
			`. /dev/null`,
		}
		for i, bind := range later {
			rows = append(rows,
				row{name + "-later-" + strconv.Itoa(i) + "-editor", editor + `; ` + bind, true},
				row{name + "-later-" + strconv.Itoa(i) + "-redirect", redirect + `; ` + bind, true},
				row{name + "-later-" + strconv.Itoa(i) + "-group", `{ ` + editor + `; ` + bind + `; }`, true},
				row{name + "-later-" + strconv.Itoa(i) + "-if", `if true; then ` + editor + `; ` + bind + `; fi`, true},
				row{name + "-later-" + strconv.Itoa(i) + "-subshell", `( ` + redirect + `; ` + bind + ` )`, true},
				row{name + "-later-" + strconv.Itoa(i) + "-while", `while :; do ` + redirect + `; ` + bind + `; break; done`, true},
			)
		}
		rows = append(rows,
			row{name + "-before-select", editor + `; select ` + name + ` in ordinary; do break; done`, true},
			row{name + "-eval-echo", `eval 'echo ` + name + ` >/dev/null'; ` + redirect, true},
			row{name + "-eval-comment", `eval ': # ` + name + `'; ` + redirect, true},
			row{name + "-eval-control", `eval ':'; ` + redirect, true},
			row{name + "-trap-echo", `trap 'echo ` + name + ` >/dev/null' EXIT; ` + redirect, true},
			row{name + "-read-prompt", `read -p ` + name + ` OTHER </dev/null; ` + editor, true},
			row{name + "-nested-late-read", `bash -c '` + redirect + `; read ` + name + ` </dev/null'`, true},
			row{name + "-unset-short-glued", `env -u` + name + ` bash -c '` + redirect + `'`, false},
			row{name + "-read-before-ordinary", `read ` + name + ` </dev/null; ` + redirect, false},
			row{name + "-for-in-ordinary", `for ` + name + ` in ordinary; do ` + redirect + `; done`, false},
			row{name + "-for-after-ordinary", `for ` + name + ` in ordinary; do :; done; ` + redirect, false},
			row{name + "-unset-ordinary-after-assign", name + `=ordinary; env -u ` + name + ` bash -c '` + redirect + `'`, false},
			row{name + "-eval-echo-ordinary", name + `=ordinary; eval 'echo ` + name + ` >/dev/null'; ` + editor, false},
		)
	}
	for _, connector := range []string{"claudecode", "codex"} {
		for _, managed := range []bool{false, true} {
			for _, pack := range []string{"", "strict", "permissive"} {
				for _, row := range rows {
					if !row.protected && pack == "strict" {
						continue
					}
					got := postSelfProtectionPackCell(t, home, project, connector, pack, managed, false, row.command)
					block := strings.HasPrefix(got, `{"action":"block"`)
					t.Logf("R5 %s connector=%s managed=%t pack=%s block=%t protected=%t", row.name, connector, managed, pack, block, row.protected)
					if row.protected && (!block || !strings.Contains(got, "tamper.detector_state_write")) {
						t.Errorf("%s %s managed=%t pack=%s: %s = %.200s, want protected block", row.name, connector, managed, pack, row.command, got)
					}
					if !row.protected && block {
						t.Errorf("%s %s managed=%t pack=%s: %s = %.200s, want ordinary allow", row.name, connector, managed, pack, row.command, got)
					}
				}
			}
		}
	}
	fmt.Fprint(os.Stdout, "R5 done\n")
}
