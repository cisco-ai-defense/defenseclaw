// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// g235bBinderFixture makes the home of the active login with its DefenseClaw
// config, a file link and a directory link to it, and the same link names
// as ordinary files under a sibling login. USER and LOGNAME name the active
// login. It returns the home, the project and the parent of the logins with
// a trailing slash.
func g235bBinderFixture(t *testing.T) (home, project, parent string) {
	t.Helper()
	home, project = dynamicWordParityProject(t)
	active := filepath.Base(home)
	t.Setenv("USER", active)
	t.Setenv("LOGNAME", active)
	state := filepath.Join(home, ".defenseclaw", "config.yaml")
	if err := os.MkdirAll(filepath.Dir(state), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(state, []byte("marker\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(state, filepath.Join(home, "statealias")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Dir(state), filepath.Join(home, "aliasdir")); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(filepath.Dir(home), "ordinary")
	if err := os.MkdirAll(filepath.Join(other, "aliasdir"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{filepath.Join(other, "statealias"), filepath.Join(filepath.Dir(home), "statealias"), filepath.Join(other, "aliasdir", "config.yaml")} {
		if err := os.WriteFile(name, []byte("ordinary\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return home, project, filepath.Dir(home) + "/"
}

// rel-1-0-6:GAP-0681 review 6 (M1): a for or select loop whose list holds
// the active login (the name itself, or the login spelled out) or a word
// the scan cannot read runs its body with that login in at least one
// iteration: an in-place edit of DefenseClaw state in the body through the
// name blocks in every profile, as it does without the loop. A loop whose
// every word is another login reads the sibling and stays allowed (default
// and permissive packs).
func TestG235bLoopKeepsActiveLoginForEditor(t *testing.T) {
	home, project, parent := g235bBinderFixture(t)
	active := filepath.Base(home)
	type row struct {
		name, command string
		protected     bool
	}
	var rows []row
	for _, name := range []string{"USER", "LOGNAME"} {
		v := "$" + name
		editor := `sed -i d ` + parent + v + `/aliasdir/config.yaml`
		redirect := `printf x > ` + parent + v + `/statealias`
		for _, loop := range []struct{ name, list string }{
			{"mixed", v + ` ordinary`},
			{"mixed-quoted", `"` + v + `" ordinary`},
			{"mixed-late", `ordinary ` + v},
			{"literal-login", active + ` ordinary`},
			{"unreadable", `$(echo ordinary)`},
		} {
			for _, keyword := range []string{"for", "select"} {
				body := editor
				if keyword == "select" {
					body += `; break`
				}
				rows = append(rows,
					row{name + "-" + keyword + "-" + loop.name + "-editor", keyword + ` ` + name + ` in ` + loop.list + `; do ` + body + `; done`, true},
					row{name + "-" + keyword + "-" + loop.name + "-editor-nested", `{ ` + keyword + ` ` + name + ` in ` + loop.list + `; do ` + body + `; done; }`, true},
				)
			}
			if loop.name != "unreadable" {
				// A linked redirect through a name the scan cannot read is
				// shell-command protected-file detection (GAP-0675).
				rows = append(rows, row{name + "-for-" + loop.name + "-redirect", `for ` + name + ` in ` + loop.list + `; do ` + redirect + `; done`, true})
			}
		}
		rows = append(rows,
			row{name + "-for-other-editor", `for ` + name + ` in ordinary other; do ` + editor + `; done`, false},
			row{name + "-for-other-redirect", `for ` + name + ` in ordinary other; do ` + redirect + `; done`, false},
			row{name + "-for-other-then-editor", `for ` + name + ` in ordinary; do :; done; ` + editor, false},
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
