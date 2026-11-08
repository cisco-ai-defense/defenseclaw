// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// rel-1-0-6:GAP-0630, GAP-0601, GAP-0681 review 3: USER and LOGNAME are
// two names the shell binds one at a time, in order. A write that names
// DefenseClaw state through the value a name has at that point is the write
// its literal spelling is: a binding of the other name, or a binding that
// comes after the write, does not hide it, and a shell body inherits the
// values the call that starts it hands over (a prefix assignment, an env
// word). A name the command rebinds before the write names the file of the
// new value and stays allowed, in the default and permissive packs (a strict
// pack may keep a protective block).
func TestG235bKnownValueOrderAndIndependentNames(t *testing.T) {
	home, project := dynamicWordParityProject(t)
	t.Setenv("USER", filepath.Base(home))
	t.Setenv("LOGNAME", filepath.Base(home))
	state := filepath.Join(home, ".defenseclaw", "config.yaml")
	if err := os.MkdirAll(filepath.Dir(state), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(state, []byte("marker\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(state, filepath.Join(home, "statealias")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Dir(state), filepath.Join(home, "aliasdir")); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(filepath.Dir(home), "ordinary")
	for _, dir := range []string{filepath.Join(other, "aliasdir"), filepath.Join(other, ".defenseclaw")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{filepath.Join(other, "statealias"), filepath.Join(other, "aliasdir", "config.yaml"),
		filepath.Join(other, ".defenseclaw", "config.yaml")} {
		if err := os.WriteFile(name, []byte("ordinary\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	const sq = "\x27"
	active := filepath.Base(home)
	parent := filepath.Dir(home) + "/"
	type row struct {
		name, command string
		protected     bool
	}
	var rows []row
	for _, name := range []string{"USER", "LOGNAME"} {
		o := "$" + name
		notName := "LOGNAME"
		if name == "LOGNAME" {
			notName = "USER"
		}
		rows = append(rows,
			// The write comes before the binding, or the other name is bound.
			row{name + "-before-rebind-editor", `sed -i d ` + parent + o + `/aliasdir/config.yaml; ` + name + `=ordinary`, true},
			row{name + "-before-rebind-direct", `sed -i d ` + parent + o + `/.defenseclaw/config.yaml; ` + name + `=ordinary`, true},
			row{name + "-before-rebind-redirect", `printf x > ` + parent + o + `/statealias; ` + name + `=ordinary`, true},
			row{name + "-before-rebind-direct-redirect", `printf x > ` + parent + o + `/.defenseclaw/config.yaml; ` + name + `=ordinary`, true},
			row{name + "-before-export", `sed -i d ` + parent + o + `/aliasdir/config.yaml; export ` + name + `=ordinary`, true},
			row{name + "-before-subshell-rebind", `(` + name + `=ordinary; :); sed -i d ` + parent + o + `/aliasdir/config.yaml`, true},
			row{"other-name-bound-" + name + "-editor", notName + `=ordinary; sed -i d ` + parent + o + `/aliasdir/config.yaml`, true},
			row{"other-name-bound-" + name + "-direct", notName + `=ordinary; sed -i d ` + parent + o + `/.defenseclaw/config.yaml`, true},
			row{"other-name-bound-" + name + "-redirect", notName + `=ordinary; printf x > ` + parent + o + `/statealias`, true},
			row{"other-name-exported-" + name + "-redirect", `export ` + notName + `=ordinary; printf x > ` + parent + o + `/statealias`, true},
			row{"restored-" + name + "-redirect", name + `=ordinary; ` + name + `=` + active + `; printf x > ` + parent + o + `/statealias`, true},
			row{"nested-restored-" + name + "-redirect", name + `=ordinary; ` + name + `=` + active + `; bash -c ` + sq + `printf x > ` + parent + o + `/statealias` + sq, true},
			row{"nested-prefix-active-" + name + "-redirect", name + `=` + active + ` bash -c ` + sq + `printf x > ` + parent + o + `/statealias` + sq, true},
			row{"nested-env-active-" + name + "-redirect", `env ` + name + `=` + active + ` bash -c ` + sq + `printf x > ` + parent + o + `/statealias` + sq, true},
			row{"nested-other-name-bound-" + name + "-redirect", notName + `=ordinary; bash -c ` + sq + `printf x > ` + parent + o + `/statealias` + sq, true},
			row{"nested-other-name-prefix-" + name + "-redirect", notName + `=ordinary bash -c ` + sq + `printf x > ` + parent + o + `/statealias` + sq, true},
			row{"nested-other-name-bound-" + name + "-editor", notName + `=ordinary; bash -c ` + sq + `sed -i d ` + parent + o + `/aliasdir/config.yaml` + sq, true},
			row{"nested-other-name-env-" + name + "-editor", `env ` + notName + `=ordinary bash -c ` + sq + `sed -i d ` + parent + o + `/aliasdir/config.yaml` + sq, true},
			// The name is rebound first: the file of the new value.
			row{name + "-rebound-editor", name + `=ordinary; sed -i d ` + parent + o + `/aliasdir/config.yaml`, false},
			row{name + "-rebound-direct", name + `=ordinary; sed -i d ` + parent + o + `/.defenseclaw/config.yaml`, false},
			row{name + "-rebound-redirect", name + `=ordinary; printf x > ` + parent + o + `/statealias`, false},
			row{name + "-exported-redirect", `export ` + name + `=ordinary; printf x > ` + parent + o + `/statealias`, false},
			row{"nested-prefix-ordinary-" + name + "-redirect", name + `=ordinary bash -c ` + sq + `printf x > ` + parent + o + `/statealias` + sq, false},
			row{"nested-env-ordinary-" + name + "-redirect", `env ` + name + `=ordinary bash -c ` + sq + `printf x > ` + parent + o + `/statealias` + sq, false},
			row{"nested-bound-ordinary-" + name + "-redirect", name + `=ordinary; bash -c ` + sq + `printf x > ` + parent + o + `/statealias` + sq, false},
			row{"nested-prefix-ordinary-" + name + "-editor", name + `=ordinary bash -c ` + sq + `sed -i d ` + parent + o + `/aliasdir/config.yaml` + sq, false},
		)
		// Review 4: a binding that comes later (a read, printf -v, a loop,
		// a declaration or an eval) leaves the write before it as it is; a
		// local value ends with its function; env -u and -i change only the
		// names they name, and a bash child then reads an unset name as empty.
		editor := `sed -i d ` + parent + o + `/aliasdir/config.yaml`
		redirect := `printf x > ` + parent + o + `/statealias`
		rows = append(rows,
			row{name + "-before-read-editor", editor + `; read ` + name + ` </dev/null`, true},
			row{name + "-before-read-redirect", redirect + `; read ` + name + ` </dev/null`, true},
			row{name + "-before-printf-v-editor", editor + `; printf -v ` + name + ` %s ordinary`, true},
			row{name + "-before-loop-editor", editor + `; for ` + name + ` in ordinary; do :; done`, true},
			row{name + "-before-declare-editor", editor + `; declare ` + name + `=ordinary`, true},
			row{name + "-before-eval-editor", editor + `; eval ` + sq + name + `=ordinary` + sq, true},
			row{name + "-in-loop-before-read-editor", `for i in 1 2; do ` + editor + `; read ` + name + ` </dev/null; done`, true},
			row{name + "-nested-before-read-redirect", `bash -c ` + sq + redirect + `; read ` + name + ` </dev/null` + sq, true},
			row{name + "-local-after-function-editor", `f() { local ` + name + `=ordinary; :; }; f; ` + editor, true},
			row{name + "-declare-after-function-editor", `f() { declare ` + name + `=ordinary; :; }; f; ` + editor, true},
			row{name + "-local-after-function-redirect", `f() { local ` + name + `=ordinary; :; }; f; ` + redirect, true},
			row{name + "-env-unset-other-editor", `env -u ` + notName + ` bash -c ` + sq + editor + sq, true},
			row{name + "-env-unset-other-redirect", `env -u ` + notName + ` bash -c ` + sq + redirect + sq, true},
			row{name + "-env-unset-long-other-redirect", `env --unset=` + notName + ` bash -c ` + sq + redirect + sq, true},
			row{name + "-env-unset-zsh-redirect", `env -u ` + name + ` zsh -c ` + sq + redirect + sq, true},
			row{name + "-env-clear-set-redirect", `env -i ` + name + `=` + active + ` bash -c ` + sq + redirect + sq, true},
			row{name + "-ordinary-before-read-editor", name + `=ordinary; ` + editor + `; read ` + name + ` </dev/null`, false},
			row{name + "-local-in-function-editor", `f() { local ` + name + `=ordinary; ` + editor + `; }; f`, false},
			row{name + "-env-unset-ordinary", `env -u ` + name + ` bash -c ` + sq + redirect + sq, false},
			row{name + "-env-unset-long-ordinary", `env --unset=` + name + ` bash -c ` + sq + redirect + sq, false},
			row{name + "-env-clear-ordinary", `env -i bash -c ` + sq + redirect + sq, false},
			row{name + "-env-clear-editor-ordinary", `env -i bash -c ` + sq + editor + sq, false},
		)
	}
	for _, connector := range []string{"claudecode", "codex"} {
		for _, pack := range []string{"", "strict", "permissive"} {
			for _, managed := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/pack=%s/managed=%t", connector, pack, managed), func(t *testing.T) {
					for _, row := range rows {
						if !row.protected && pack == "strict" {
							continue
						}
						got := postSelfProtectionPackCell(t, home, project, connector, pack, managed, false, row.command)
						if row.protected {
							if !strings.HasPrefix(got, `{"action":"block"`) || !strings.Contains(got, "tamper.detector_state_write") {
								t.Errorf("%s: %s = %.200s, want block tamper.detector_state_write", row.name, row.command, got)
							}
						} else if !strings.HasPrefix(got, `{"action":"allow"`) {
							t.Errorf("%s: %s = %.200s, want allow", row.name, row.command, got)
						}
					}
				})
			}
		}
	}
}
