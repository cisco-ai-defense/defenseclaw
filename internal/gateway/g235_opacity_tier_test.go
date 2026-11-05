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

// The hook records the user's link answer before the blind managed gateway
// loses access to the home. A known protected value keeps its block in every
// profile; opacity alone blocks an ordinary write only in strict.
func TestG235OpacityTierCells(t *testing.T) {
	home, project := dynamicWordParityProject(t)
	runtimeDir := filepath.Join(filepath.Dir(home), "runtime")
	if err := os.MkdirAll(runtimeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DEFENSECLAW_HOME", runtimeDir)
	if err := os.MkdirAll(filepath.Join(project, "ordinary"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"clean", "linked"} {
		dir := filepath.Join(home, name)
		if err := os.MkdirAll(filepath.Join(dir, "build"), 0o700); err != nil {
			t.Fatal(err)
		}
		for _, file := range []string{"a.txt", "README.md"} {
			if err := os.WriteFile(filepath.Join(dir, file), []byte("plain\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := os.Symlink(filepath.Join(home, ".ssh", "authorized_keys"), filepath.Join(home, "linked", "build", "README.md")); err != nil {
		t.Fatal(err)
	}
	rows := []struct {
		name, cwd, command                   string
		protected, strictUser, strictManaged bool
	}{
		{"GAP-0235/ordinary", project, `f=out2.txt; cp a.txt $f`, false, false, false},
		{"GAP-0235/link", project, `f=disklink; cp a.txt $f`, true, true, true},
		{"GAP-0395/P07", filepath.Join(home, "clean"), `cd ~/clean && f=README.md && cp -v $f build/ && echo copied`, false, true, true},
		{"GAP-0395/P07-link", filepath.Join(home, "linked"), `cd ~/linked && f=README.md && cp -v $f build/ && echo copied`, true, true, true},
		{"GAP-0507/printf-redirect", project, `f=ordinary/n2; printf %s hello > ordinary/n3; cp a.txt $f`, false, true, true},
		{"GAP-0507/printf-redirect-link", project, `f=disklink; printf %s hello > ordinary/n3; cp a.txt $f`, true, true, true},
		{"GAP-0507/printf", project, `f=ordinary/n2; printf %s hello; cp a.txt $f`, false, false, true},
		{"GAP-0507/printf-link", project, `f=disklink; printf %s hello; cp a.txt $f`, true, true, true},
		{"GAP-0507/function", project, `g() { cp a.txt $f; }; f=ordinary/n2; g`, false, false, true},
		{"GAP-0507/function-link", project, `g() { cp a.txt $f; }; f=disklink; g`, true, true, true},
		{"GAP-0507/nested-shell", project, `f=ordinary/n2 bash -c "cp a.txt \$f"`, false, false, true},
		{"GAP-0507/nested-shell-link", project, `f=disklink bash -c "cp a.txt \$f"`, true, true, true},
	}
	for _, connector := range []string{"claudecode", "codex"} {
		for _, mode := range []struct{ managed, blind, strict bool }{
			{false, false, false}, {false, false, true},
			{true, false, false}, {true, false, true},
			{true, true, false}, {true, true, true},
		} {
			for _, row := range rows {
				name := fmt.Sprintf("%s/%s/managed=%t/blind=%t/strict=%t", row.name, connector, mode.managed, mode.blind, mode.strict)
				t.Run(name, func(t *testing.T) {
					wantBlock := row.protected || mode.strict && ((mode.managed && row.strictManaged) || (!mode.managed && row.strictUser))
					want := `{"action":"allow"`
					if wantBlock {
						want = `{"action":"block"`
					}
					got := postDynamicWordParityCell(t, home, row.cwd, connector, mode.managed, mode.blind, mode.strict, row.command, nil)
					if !strings.HasPrefix(got, want) {
						t.Errorf("verdict %.300s, want %s", got, want)
					}
				})
			}
		}
	}
}
