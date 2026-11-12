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

// A for loop whose body writes a path that holds the loop variable is judged
// by that path: the variable stands for any one name, so a path that any name
// can make DefenseClaw state is protected whatever the list holds and
// whatever runs before the loop (a sourced file binds anything, eval too). A
// literal ordinary target stays allowed (rel-1-0-6:GAP-0880, review 19 M1).
func TestLoopVariableInWriterTargetIsAnyNameWhateverRunsBefore(t *testing.T) {
	home, project, parent := g235bBinderFixture(t)
	if err := os.WriteFile(filepath.Join(project, "a.txt"), []byte("b\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	state := `.defenseclaw/config.yaml`
	editor := `sed -i s/a/b/ ` + parent + `$u/` + state
	copier := `cp a.txt ` + parent + `$u/` + state
	redirect := `printf x > ` + parent + `$u/` + state
	teeing := `printf x | tee ` + parent + `$u/` + state + ` >/dev/null`
	rows := []struct {
		name, command string
		protected     bool
	}{
		{"dot-user-editor", `. /dev/null; for u in $USER; do ` + editor + `; done`, true},
		{"dot-user-copy", `. /dev/null; for u in $USER; do ` + copier + `; done`, true},
		{"source-user-editor", `source /dev/null; for u in $USER; do ` + editor + `; done`, true},
		{"source-user-copy", `source /dev/null; for u in $USER; do ` + copier + `; done`, true},
		{"dot-user-redirect", `. /dev/null; for u in $USER; do ` + redirect + `; done`, true},
		{"dot-user-tee", `. /dev/null; for u in $USER; do ` + teeing + `; done`, true},
		{"dot-logname-editor", `. /dev/null; for u in "$LOGNAME"; do ` + editor + `; done`, true},
		{"dot-command-list-copy", `. /dev/null; for u in $(ls ..); do ` + copier + `; done`, true},
		{"dot-literal-list-sibling-editor", `. /dev/null; for u in alpha beta; do ` + editor + `; done`, false},
		{"command-list-copy", `for u in $(ls ..); do ` + copier + `; done`, true},
		{"ordinary-dot-editor", `. /dev/null; for u in $USER; do sed -i s/a/b/ ` + parent + `$u/notes.yaml; done`, false},
		{"ordinary-dot-copy", `. /dev/null; for u in $USER; do cp a.txt ` + parent + `$u/.config/app.yaml; done`, false},
		{"ordinary-project-copy", `. /dev/null; for u in $(ls); do cp a.txt out/$u/.defenseclaw/config.yaml; done`, false},
		{"ordinary-literal-editor", `. /dev/null; for u in ordinary; do sed -i s/a/b/ ./$u.txt; done`, false},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			for _, connector := range []string{"claudecode", "codex"} {
				for _, managed := range []bool{false, true} {
					for _, pack := range []string{"", "permissive", "strict"} {
						if !row.protected && pack == "strict" {
							continue
						}
						got := postSelfProtectionPackCell(t, home, project, connector, pack, managed, false, row.command)
						block := strings.HasPrefix(got, `{"action":"block"`)
						if row.protected && (!block || !strings.Contains(got, "tamper.detector_state_write")) {
							t.Errorf("%s managed=%t pack=%q: %s = %.200s, want protected block", connector, managed, pack, row.command, got)
						}
						if !row.protected && block {
							t.Errorf("%s managed=%t pack=%q: %s = %.200s, want ordinary allow", connector, managed, pack, row.command, got)
						}
					}
				}
			}
		})
	}
}
