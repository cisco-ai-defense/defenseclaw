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

// A known copy destination still names the SSH keys link when its assignment
// follows a directory change joined with && (rel-1-0-6:GAP-0362).
func TestGAP0362CdVariableCopyDestination(t *testing.T) {
	home, project := dynamicWordParityProject(t)
	link := filepath.Join(project, "disklink")
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../.ssh/authorized_keys", link); err != nil {
		t.Fatal(err)
	}
	rows := []struct {
		name, command string
		block         bool
	}{
		{"no cd", `f=disklink; cp a.txt $f`, true},
		{"semicolon cd", `cd ~/proj; f=disklink; cp a.txt $f`, true},
		{"and cd", `cd ~/proj && f=disklink; cp a.txt $f`, true},
		{"and cd quoted", `cd ~/proj && f=disklink; cp a.txt "$f"`, true},
		{"and cd followed by echo", `cd ~/proj && f=disklink; cp a.txt $f && echo ok`, true},
		{"and cd archive copy", `cd ~/proj && f=disklink; cp -a a.txt $f`, true},
		{"and cd option", `cd -L ~/proj && f=disklink; cp a.txt $f`, true},
		{"and cd end options", `cd -- ~/proj && f=disklink; cp a.txt $f`, true},
		{"and pushd", `pushd ~/proj && f=disklink; cp a.txt $f`, true},
		{"and subshell cd", `(cd ~/proj && f=disklink; cp a.txt $f)`, true},
		{"ordinary no cd", `f=out2.txt; cp a.txt $f`, false},
		{"ordinary semicolon cd", `cd ~/proj; f=out2.txt; cp a.txt $f`, false},
		{"ordinary and cd", `cd ~/proj && f=out2.txt; cp a.txt $f`, false},
		{"ordinary and cd quoted", `cd ~/proj && f=out2.txt; cp a.txt "$f"`, false},
		{"ordinary and cd followed by echo", `cd ~/proj && f=out2.txt; cp a.txt $f && echo ok`, false},
		{"ordinary and cd archive copy", `cd ~/proj && f=out2.txt; cp -a a.txt $f`, false},
		{"ordinary and cd option", `cd -L ~/proj && f=out2.txt; cp a.txt $f`, false},
		{"ordinary and cd end options", `cd -- ~/proj && f=out2.txt; cp a.txt $f`, false},
		{"ordinary and pushd", `pushd ~/proj && f=out2.txt; cp a.txt $f`, false},
		{"ordinary and subshell cd", `(cd ~/proj && f=out2.txt; cp a.txt $f)`, false},
	}
	// GAP-0402 kept nested words after pushd, cd options and a subshell
	// unknown, so the managed benign twins below were a recorded
	// conservative false block. The straight-line walk now reads the
	// destination of each of them exactly (rel-1-0-6:GAP-0880, GAP-0885), so
	// those twins allow in every profile; the protected rows block as before.
	for _, scope := range []struct{ name, start, end string }{
		{"subshell cd", `(cd ~/proj && f=%s; `, `)`},
		{"subshell pushd", `(pushd ~/proj && f=%s; `, `)`},
		{"pushd", `pushd ~/proj && f=%s; `, ``},
		{"cd -L", `cd -L ~/proj && f=%s; `, ``},
		{"cd --", `cd -- ~/proj && f=%s; `, ``},
	} {
		for _, form := range []struct{ name, command string }{
			{"loop", `for x in 1; do cp a.txt $f; done`},
			{"if", `if true; then cp a.txt $f; fi`},
			{"group", `{ cp a.txt $f; }`},
			{"pipeline", `cp a.txt $f | cat`},
			{"time", `time cp a.txt $f`},
		} {
			for _, destination := range []struct {
				name, word string
				block      bool
			}{
				{"protected", "disklink", true},
				{"ordinary", "out2.txt", false},
			} {
				rows = append(rows, struct {
					name, command string
					block         bool
				}{scope.name + "/" + form.name + "/" + destination.name,
					fmt.Sprintf(scope.start, destination.word) + form.command + scope.end,
					destination.block})
			}
		}
	}
	for _, connector := range []string{"claudecode", "codex"} {
		for _, managed := range []bool{false, true} {
			for _, row := range rows {
				t.Run(fmt.Sprintf("%s/managed=%t/%s", connector, managed, row.name), func(t *testing.T) {
					var hide func(map[string]string)
					if managed {
						hide = func(targets map[string]string) {
							if row.block && !strings.Contains(row.name, "/") && targets[link] != filepath.Join(home, ".ssh", "authorized_keys") {
								t.Errorf("client link target = %q, want SSH keys", targets[link])
							}
							if err := os.Chmod(home, 0); err != nil {
								t.Fatal(err)
							}
							t.Cleanup(func() { _ = os.Chmod(home, 0o700) })
						}
					}
					got := postDynamicWordParity(t, home, project, connector, managed, row.command, hide)
					if managed {
						if err := os.Chmod(home, 0o700); err != nil {
							t.Fatal(err)
						}
					}
					// The GAP-0402 managed false block of the nested pushd,
					// cd-option and subshell benign twins is gone: every row
					// with row.block false allows, with row.block true it blocks.
					want := `{"action":"allow"`
					if row.block {
						want = `{"action":"block"`
					}
					if !strings.HasPrefix(got, want) || row.block && !strings.Contains(got, "persistence.ssh_authorized_keys_command") {
						t.Errorf("%q = %.300s, want %s", row.command, got, want)
					}
				})
			}
		}
	}
}

// GAP-0415: a nested copy inherits the directory of its enclosing placed
// statement. In particular, plain cd keeps its known-word binding while the
// client resolves a destination in the directory cd entered.
func TestGAP0415NestedCopyDestinationAfterPlainCd(t *testing.T) {
	home, project := dynamicWordParityProject(t)
	work := filepath.Join(project, "work")
	if err := os.Mkdir(work, 0o700); err != nil {
		t.Fatal(err)
	}
	workLink := filepath.Join(work, "disklink")
	if err := os.Symlink("../../.ssh/authorized_keys", workLink); err != nil {
		t.Fatal(err)
	}
	rows := []struct {
		name, command, link string
		block               bool
	}{
		{"loop", `cd ~ && f=proj/disklink; for x in 1; do cp proj/a.txt $f; done`, filepath.Join(project, "disklink"), true},
		{"if", `cd ~ && f=proj/disklink; if true; then cp proj/a.txt $f; fi`, filepath.Join(project, "disklink"), true},
		{"group", `cd ~ && f=proj/disklink; { cp proj/a.txt $f; }`, filepath.Join(project, "disklink"), true},
		{"pipeline", `cd ~ && f=proj/disklink; cp proj/a.txt $f | cat`, filepath.Join(project, "disklink"), true},
		{"time", `cd ~ && f=proj/disklink; time cp proj/a.txt $f`, filepath.Join(project, "disklink"), true},
		{"build loop", `cd ~/proj/build && f=../disklink; for x in 1; do cp ../a.txt $f; done`, filepath.Join(project, "disklink"), true},
		{"work loop", `cd ~/proj/work && f=../disklink; for x in 1; do cp ../a.txt $f; done`, filepath.Join(project, "disklink"), true},
		{"work link", `cd ~ && f=proj/work/disklink; for x in 1; do cp proj/a.txt $f; done`, workLink, true},
		{"suffix", `cd ~ && d=proj; for x in 1; do cp proj/a.txt $d/disklink; done`, filepath.Join(project, "disklink"), true},
		{"quoted", `cd ~ && f=proj/disklink; for x in 1; do cp proj/a.txt "$f"; done`, filepath.Join(project, "disklink"), true},
		{"ordinary loop", `cd ~ && f=proj/out2.txt; for x in 1; do cp proj/a.txt $f; done`, "", false},
		{"ordinary if", `cd ~ && f=proj/out2.txt; if true; then cp proj/a.txt $f; fi`, "", false},
		{"ordinary group", `cd ~ && f=proj/out2.txt; { cp proj/a.txt $f; }`, "", false},
		{"ordinary pipeline", `cd ~ && f=proj/out2.txt; cp proj/a.txt $f | cat`, "", false},
		{"ordinary time", `cd ~ && f=proj/out2.txt; time cp proj/a.txt $f`, "", false},
		{"ordinary build loop", `cd ~/proj/build && f=../out2.txt; for x in 1; do cp ../a.txt $f; done`, "", false},
		{"ordinary suffix", `cd ~ && d=proj; for x in 1; do cp proj/a.txt $d/out2.txt; done`, "", false},
		{"ordinary source", `cd ~/proj && f=a.txt; for x in 1; do cp $f build/; done`, "", false},
	}
	for _, connector := range []string{"claudecode", "codex"} {
		for _, managed := range []bool{false, true} {
			for _, row := range rows {
				t.Run(fmt.Sprintf("%s/managed=%t/%s", connector, managed, row.name), func(t *testing.T) {
					var hide func(map[string]string)
					if managed {
						hide = func(targets map[string]string) {
							if row.block && targets[row.link] != filepath.Join(home, ".ssh", "authorized_keys") {
								t.Errorf("client link target for %q = %q, want SSH keys", row.link, targets[row.link])
							}
							if err := os.Chmod(home, 0); err != nil {
								t.Fatal(err)
							}
							t.Cleanup(func() { _ = os.Chmod(home, 0o700) })
						}
					}
					got := postDynamicWordParity(t, home, project, connector, managed, row.command, hide)
					if managed {
						if err := os.Chmod(home, 0o700); err != nil {
							t.Fatal(err)
						}
					}
					want := `{"action":"allow"`
					if row.block {
						want = `{"action":"block"`
					}
					if !strings.HasPrefix(got, want) || row.block && !strings.Contains(got, "persistence.ssh_authorized_keys_command") {
						t.Errorf("%q = %.300s, want %s", row.command, got, want)
					}
				})
			}
		}
	}
}

// GAP-0416 pins the after-directory boundary with a target different from
// the request cwd, including a nested use beside a placed top-level call.
func TestGAP0416AfterDirectoryBoundaryWithNestedCopy(t *testing.T) {
	home, project := dynamicWordParityProject(t)
	rows := []struct{ name, command string }{
		{"pushd", `pushd ~/proj/build && f=../disklink; for x in 1; do cp ../a.txt $f; done`},
		{"cd logical", `cd -L ~ && f=proj/disklink; cp proj/a.txt $f | cat`},
		{"cd end options", `cd -- ~/proj/build && f=../disklink; time cp ../a.txt $f`},
		{"subshell", `(cd ~ && f=proj/disklink; if true; then cp proj/a.txt $f; fi)`},
		{"placed echo and nested", `pushd ~/proj/build && f=../disklink; echo hi; for x in 1; do cp ../a.txt $f; done`},
		{"placed copy and nested", `pushd ~/proj/build && f=../disklink; cp ../a.txt out3.txt; for x in 1; do cp ../a.txt $f; done`},
		{"placed echo with nested substitution", `pushd ~/proj/build && f=../disklink; echo hi; echo $(cp ../a.txt $f)`},
	}
	for _, connector := range []string{"claudecode", "codex"} {
		for _, managed := range []bool{false, true} {
			for _, row := range rows {
				t.Run(fmt.Sprintf("%s/managed=%t/%s", connector, managed, row.name), func(t *testing.T) {
					var hide func(map[string]string)
					if managed {
						hide = func(map[string]string) {
							if err := os.Chmod(home, 0); err != nil {
								t.Fatal(err)
							}
							t.Cleanup(func() { _ = os.Chmod(home, 0o700) })
						}
					}
					got := postDynamicWordParity(t, home, project, connector, managed, row.command, hide)
					if managed {
						if err := os.Chmod(home, 0o700); err != nil {
							t.Fatal(err)
						}
					}
					if !strings.HasPrefix(got, `{"action":"block"`) || !strings.Contains(got, "persistence.ssh_authorized_keys_command") {
						t.Errorf("%q = %.300s, want keys block", row.command, got)
					}
				})
			}
		}
	}
}

// The destination is resolved in the directory the cd enters, even when the
// hook event starts in a different directory.
func TestGAP0362CdVariableCopyDestinationInAnotherDirectory(t *testing.T) {
	home, project := dynamicWordParityProject(t)
	work := filepath.Join(project, "work")
	if err := os.Mkdir(work, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(work, "disklink")
	if err := os.Symlink("../../.ssh/authorized_keys", link); err != nil {
		t.Fatal(err)
	}
	for _, connector := range []string{"claudecode", "codex"} {
		for _, managed := range []bool{false, true} {
			for _, row := range []struct {
				command string
				block   bool
			}{
				{`cd ~/proj/work && f=disklink; cp ../a.txt $f`, true},
				{`cd ~/proj/work && f=out.txt; cp ../a.txt $f`, false},
			} {
				t.Run(fmt.Sprintf("%s/managed=%t/block=%t", connector, managed, row.block), func(t *testing.T) {
					var hide func(map[string]string)
					if managed {
						hide = func(targets map[string]string) {
							if row.block && targets[link] != filepath.Join(home, ".ssh", "authorized_keys") {
								t.Errorf("client link target = %q, want SSH keys", targets[link])
							}
							if err := os.Chmod(home, 0); err != nil {
								t.Fatal(err)
							}
							t.Cleanup(func() { _ = os.Chmod(home, 0o700) })
						}
					}
					got := postDynamicWordParity(t, home, project, connector, managed, row.command, hide)
					if managed {
						if err := os.Chmod(home, 0o700); err != nil {
							t.Fatal(err)
						}
					}
					want := `{"action":"allow"`
					if row.block {
						want = `{"action":"block"`
					}
					if !strings.HasPrefix(got, want) || row.block && !strings.Contains(got, "persistence.ssh_authorized_keys_command") {
						t.Errorf("%q = %.300s, want %s", row.command, got, want)
					}
				})
			}
		}
	}
}
