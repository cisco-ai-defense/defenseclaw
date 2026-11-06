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
		{"GAP-0395/P07-print-options", filepath.Join(home, "clean"), `cd ~/clean && f=README.md && printf -- %s hello && cp -v $f build/`, false, true, true},
		{"GAP-0395/P07-print-options-link", filepath.Join(home, "linked"), `cd ~/linked && f=README.md && printf -- %s hello && cp -v $f build/`, true, true, true},
		{"GAP-0507/printf-redirect", project, `f=ordinary/n2; printf %s hello > ordinary/n3; cp a.txt $f`, false, true, true},
		{"GAP-0507/printf-redirect-link", project, `f=disklink; printf %s hello > ordinary/n3; cp a.txt $f`, true, true, true},
		{"GAP-0507/printf", project, `f=ordinary/n2; printf %s hello; cp a.txt $f`, false, false, true},
		{"GAP-0507/printf-link", project, `f=disklink; printf %s hello; cp a.txt $f`, true, true, true},
		{"GAP-0507/printf-options", project, `f=ordinary/n2; printf -- %s hello; cp a.txt $f`, false, false, true},
		{"GAP-0507/printf-options-link", project, `f=disklink; printf -- %s hello; cp a.txt $f`, true, true, true},
		{"GAP-0507/unrelated-input", project, `f=ordinary/n2; read -r unrelated; cp a.txt $f`, false, false, true},
		{"GAP-0507/unrelated-input-link", project, `f=disklink; read -r unrelated; cp a.txt $f`, true, true, true},
		{"GAP-0507/unrelated-input-list", project, `f=ordinary/n2; read -r first second; cp a.txt $f`, false, false, true},
		{"GAP-0507/unrelated-input-list-link", project, `f=disklink; read -r first second; cp a.txt $f`, true, true, true},
		{"GAP-0507/function", project, `g() { cp a.txt $f; }; f=ordinary/n2; g`, false, false, true},
		{"GAP-0507/function-link", project, `g() { cp a.txt $f; }; f=disklink; g`, true, true, true},
		{"GAP-0507/function-print", project, `g() { printf %s hello; cp a.txt $f; }; f=ordinary/n2; g`, false, false, true},
		{"GAP-0507/function-print-link", project, `g() { printf %s hello; cp a.txt $f; }; f=disklink; g`, true, true, true},
		{"GAP-0507/nested-shell", project, `f=ordinary/n2 bash -c "cp a.txt \$f"`, false, false, true},
		{"GAP-0507/nested-shell-link", project, `f=disklink bash -c "cp a.txt \$f"`, true, true, true},
		{"GAP-0507/nested-print-options", project, `f=ordinary/n2 bash -c 'printf -- %s hello; cp a.txt "$f"'`, false, false, true},
		{"GAP-0507/nested-print-options-link", project, `f=disklink bash -c 'printf -- %s hello; cp a.txt "$f"'`, true, true, true},
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

// Round 3 neighbors keep ordinary copy commands and their linked twins paired.
func TestReviewG235NearVariants(t *testing.T) {
	home, project := dynamicWordParityProject(t)
	for _, folder := range []string{"clean", "linked"} {
		dir := filepath.Join(home, folder)
		if err := os.MkdirAll(filepath.Join(dir, "build"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("ordinary\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join(home, ".ssh", "authorized_keys"), filepath.Join(home, "linked", "build", "README.md")); err != nil {
		t.Fatal(err)
	}
	rows := []struct {
		name, cwd, command string
		block              bool
	}{
		{"fixedP07", filepath.Join(home, "clean"), `cd ~/clean && f=README.md && cp -v $f build/ && echo copied`, false},
		{"fixedP07Link", filepath.Join(home, "linked"), `cd ~/linked && f=README.md && cp -v $f build/ && echo copied`, true},
		{"nearP07Quoted", filepath.Join(home, "clean"), `cd ~/clean && f=README.md && cp -v "$f" build/ && echo copied`, false},
		{"nearP07QuotedLink", filepath.Join(home, "linked"), `cd ~/linked && f=README.md && cp -v "$f" build/ && echo copied`, true},
		{"nearP07PrintDash", filepath.Join(home, "clean"), `cd ~/clean && f=README.md && printf -- %s hello && cp -v $f build/`, false},
		{"nearP07PrintDashLink", filepath.Join(home, "linked"), `cd ~/linked && f=README.md && printf -- %s hello && cp -v $f build/`, true},
		{"fixed0507Print", project, `f=out2.txt; printf %s hello; cp a.txt $f`, false},
		{"fixed0507PrintLink", project, `f=disklink; printf %s hello; cp a.txt $f`, true},
		{"near0507PrintDash", project, `f=out2.txt; printf -- %s hello; cp a.txt $f`, false},
		{"near0507PrintDashLink", project, `f=disklink; printf -- %s hello; cp a.txt $f`, true},
		{"near0507ReadOther", project, `f=out2.txt; read -r unrelated; cp a.txt $f`, false},
		{"near0507ReadOtherLink", project, `f=disklink; read -r unrelated; cp a.txt $f`, true},
		{"near0507FunctionPrint", project, `g() { printf %s hello; cp a.txt $f; }; f=out2.txt; g`, false},
		{"near0507FunctionPrintLink", project, `g() { printf %s hello; cp a.txt $f; }; f=disklink; g`, true},
		{"fixed0507Function", project, `g() { cp a.txt $f; }; f=out2.txt; g`, false},
		{"fixed0507FunctionLink", project, `g() { cp a.txt $f; }; f=disklink; g`, true},
		{"near0507NestedPrintDash", project, `f=out2.txt bash -c 'printf -- %s hello; cp a.txt "$f"'`, false},
		{"near0507NestedPrintDashLink", project, `f=disklink bash -c 'printf -- %s hello; cp a.txt "$f"'`, true},
	}
	for _, connector := range []string{"claudecode", "codex"} {
		for _, managed := range []bool{false, true} {
			for _, row := range rows {
				t.Run(fmt.Sprintf("%s/%s/managed=%t", row.name, connector, managed), func(t *testing.T) {
					got := postDynamicWordParity(t, home, row.cwd, connector, managed, row.command, nil)
					verdict := "other"
					if strings.HasPrefix(got, `{"action":"allow"`) {
						verdict = "allow"
					}
					if strings.HasPrefix(got, `{"action":"block"`) {
						verdict = "block"
					}
					t.Logf("RV2MUT %s %s managed=%t verdict=%s", row.name, connector, managed, verdict)
					want := "allow"
					if row.block {
						want = "block"
					}
					if verdict != want {
						t.Errorf("verdict %s, want %s; body %.180s", verdict, want, got)
					}
				})
			}
		}
	}
}
