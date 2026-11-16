// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"path/filepath"
	"strings"
	"testing"
)

// rel-1-0-6:GAP-0630, GAP-0601, GAP-0681 review 7 (M1): a for loop whose
// list holds the active login gives its name that login in the iteration
// that has it, whether or not an earlier statement bound USER or LOGNAME,
// and whether the body edits the state in place or redirects a printf with
// an unreadable format to it. A loop whose list holds only another login,
// a name an earlier statement bound to another login, or a statement after
// the loop (where the name keeps its last value) reads a sibling and stays
// allowed.
func TestG235bLoopAfterBindingAndPrintf(t *testing.T) {
	home, project, parent := g235bBinderFixture(t)
	active := filepath.Base(home)
	type row struct {
		name, command string
		protected     bool
	}
	var rows []row
	for _, name := range []string{"USER", "LOGNAME"} {
		other := map[string]string{"USER": "LOGNAME", "LOGNAME": "USER"}[name]
		v := "$" + name
		editor := `sed -i d ` + parent + v + `/aliasdir/config.yaml`
		printf := `printf "$X" > ` + parent + v + `/.defenseclaw/config.yaml`
		for _, prefix := range []struct{ name, text string }{
			{"plain", ``},
			{"bound-same", name + `=ordinary; `},
			{"bound-other", other + `=ordinary; `},
		} {
			for _, list := range []struct{ name, text string }{
				{"login", active},
				{"login-second", `ordinary ` + active},
				{"other-name", `$` + other},
			} {
				if list.name == "other-name" && prefix.name == "bound-other" {
					continue // the other name holds a sibling there
				}
				for _, body := range []struct{ name, text string }{{"editor", editor}, {"printf", printf}} {
					rows = append(rows, row{name + "-" + prefix.name + "-" + list.name + "-" + body.name,
						prefix.text + `for ` + name + ` in ` + list.text + `; do ` + body.text + `; done`, true})
				}
			}
		}
		rows = append(rows,
			row{name + "-bound-then-own-name", name + `=ordinary; for ` + name + ` in ` + v + `; do ` + editor + `; done`, false},
			row{name + "-bound-other-name-list", other + `=ordinary; for ` + name + ` in ` + `$` + other + `; do ` + editor + `; done`, false},
			row{name + "-only-sibling", `for ` + name + ` in ordinary; do ` + editor + `; done`, false},
			row{name + "-after-loop", `for ` + name + ` in ` + active + ` ordinary; do :; done; ` + editor, false},
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
}
