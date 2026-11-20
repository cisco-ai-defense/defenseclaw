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
//
// Binder i is judged in wrappers 2i and 2i+1 (mod 6), once with each name,
// so every binder meets USER and LOGNAME and every wrapper meets two or
// three binders; the other rows are judged with both names.
// g235bRotate spreads the rows over the cells.
func TestG235bBinderClassKnownValues(t *testing.T) {
	home, project, parent := g235bBinderFixture(t)
	const sq = "\x27"
	names := []string{"USER", "LOGNAME"}
	writes := func(name string) (editor, redirect string) {
		v := "$" + name
		return `sed -i d ` + parent + v + `/aliasdir/config.yaml`, `printf x > ` + parent + v + `/statealias`
	}
	later := func(name string) []string {
		return []string{
			`select ` + name + ` in ordinary; do break; done`,
			`for ` + name + ` in ordinary; do :; done`,
			`read ` + name + ` </dev/null`,
			name + `=ordinary`,
			`export ` + name + `=ordinary`,
			`eval ` + sq + name + `=ordinary` + sq,
			`printf -v ` + name + ` x`,
			`. /dev/null`,
		}
	}
	wrappers := []struct {
		name string
		wrap func(editor, redirect, bind string) string
	}{
		{"editor", func(e, _, b string) string { return e + `; ` + b }},
		{"redirect", func(_, r, b string) string { return r + `; ` + b }},
		{"group", func(e, _, b string) string { return `{ ` + e + `; ` + b + `; }` }},
		{"if", func(e, _, b string) string { return `if true; then ` + e + `; ` + b + `; fi` }},
		{"subshell", func(_, r, b string) string { return `( ` + r + `; ` + b + ` )` }},
		{"while", func(_, r, b string) string { return `while :; do ` + r + `; ` + b + `; break; done` }},
	}
	var rows []g235bRow
	for i := range later("USER") {
		for j := 0; j < 2; j++ {
			name := names[(i+j)%2]
			editor, redirect := writes(name)
			w := wrappers[(2*i+j)%len(wrappers)]
			rows = append(rows, g235bRow{name + "-later-" + strconv.Itoa(i) + "-" + w.name, w.wrap(editor, redirect, later(name)[i]), true})
		}
	}
	for _, name := range names {
		editor, redirect := writes(name)
		rows = append(rows,
			g235bRow{name + "-before-select", editor + `; select ` + name + ` in ordinary; do break; done`, true},
			g235bRow{name + "-eval-echo", `eval 'echo ` + name + ` >/dev/null'; ` + redirect, true},
			g235bRow{name + "-eval-comment", `eval ': # ` + name + `'; ` + redirect, true},
			g235bRow{name + "-eval-control", `eval ':'; ` + redirect, true},
			g235bRow{name + "-trap-echo", `trap 'echo ` + name + ` >/dev/null' EXIT; ` + redirect, true},
			g235bRow{name + "-read-prompt", `read -p ` + name + ` OTHER </dev/null; ` + editor, true},
			g235bRow{name + "-nested-late-read", `bash -c '` + redirect + `; read ` + name + ` </dev/null'`, true},
			g235bRow{name + "-unset-short-glued", `env -u` + name + ` bash -c '` + redirect + `'`, false},
			g235bRow{name + "-read-before-ordinary", `read ` + name + ` </dev/null; ` + redirect, false},
			g235bRow{name + "-for-in-ordinary", `for ` + name + ` in ordinary; do ` + redirect + `; done`, false},
			g235bRow{name + "-for-after-ordinary", `for ` + name + ` in ordinary; do :; done; ` + redirect, false},
			g235bRow{name + "-unset-ordinary-after-assign", name + `=ordinary; env -u ` + name + ` bash -c '` + redirect + `'`, false},
			g235bRow{name + "-eval-echo-ordinary", name + `=ordinary; eval 'echo ` + name + ` >/dev/null'; ` + editor, false},
		)
	}
	g235bRotate(t, rows, []string{"", "strict", "permissive"}, false, func(t *testing.T, cell g235bCell, row g235bRow) {
		got := postSelfProtectionPackCell(t, home, project, cell.connector, cell.pack, cell.managed, false, row.command)
		block := strings.HasPrefix(got, `{"action":"block"`)
		t.Logf("R5 %s connector=%s managed=%t pack=%s block=%t protected=%t", row.name, cell.connector, cell.managed, cell.pack, block, row.protected)
		if row.protected && (!block || !strings.Contains(got, "tamper.detector_state_write")) {
			t.Errorf("%s %s managed=%t pack=%s: %s = %.200s, want protected block", row.name, cell.connector, cell.managed, cell.pack, row.command, got)
		}
		if !row.protected && block {
			t.Errorf("%s %s managed=%t pack=%s: %s = %.200s, want ordinary allow", row.name, cell.connector, cell.managed, cell.pack, row.command, got)
		}
	})
	fmt.Fprint(os.Stdout, "R5 done\n")
}
