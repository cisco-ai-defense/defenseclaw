// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// TestSourcedScriptAfterADirectoryChangeIsJudgedWhereItRuns: a script named
// after cd a && opens the file of that name in a, so the writer that lies at
// the same spelling in the folder the hook started in (through a folder link
// and a .. there) does not block the ordinary script, and the writer in a
// blocks although an ordinary script lies at the starting spelling, per-user
// and managed, in the shell wrappers (rel-1-0-9:GAP-1038).
func TestSourcedScriptAfterADirectoryChangeIsJudgedWhereItRuns(t *testing.T) {
	writer := "echo marker >> $HOME/.ssh/authorized_keys\n"
	ordinary := "echo ordinary >> report.txt\n"
	// project/portal leads to home/other/live; project/a/portal to
	// home/chain/live. From the project, portal/../NAME is home/other/NAME;
	// from a, it is home/chain/NAME.
	setup := func(t *testing.T, f b36ManagedHookFixture) {
		t.Helper()
		for _, dir := range []string{
			filepath.Join(f.home, "chain", "live"), filepath.Join(f.home, "other", "live"), filepath.Join(f.project, "a"),
		} {
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
		}
		for file, body := range map[string]string{
			filepath.Join(f.home, "chain", "ok.sh"): ordinary,
			filepath.Join(f.home, "chain", "wk.sh"): writer,
			filepath.Join(f.home, "other", "ok.sh"): writer,
			filepath.Join(f.home, "other", "wk.sh"): ordinary,
			filepath.Join(f.project, "ok.sh"):       writer,
			filepath.Join(f.project, "wk.sh"):       ordinary,
			filepath.Join(f.project, "a", "ok.sh"):  ordinary,
			filepath.Join(f.project, "a", "wk.sh"):  writer,
		} {
			if err := os.WriteFile(file, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.Symlink(filepath.Join(f.home, "other", "live"), filepath.Join(f.project, "portal")); err != nil {
			t.Skipf("link unavailable: %v", err)
		}
		if err := os.Symlink(filepath.Join(f.home, "chain", "live"), filepath.Join(f.project, "a", "portal")); err != nil {
			t.Skipf("link unavailable: %v", err)
		}
	}
	var rows []r106Reader2Row
	for _, command := range []string{
		"cd a && source %s", "cd a && . ./%s", "cd a && bash %s", "cd a && sh %s",
		`bash -c "cd a && . ./%s"`, `sh -c "cd a && bash %s"`,
	} {
		for _, row := range []struct {
			name string
			want string
		}{
			{"portal/../ok.sh", "allow"},
			{"portal/../wk.sh", "block"},
			{"ok.sh", "allow"},
			{"wk.sh", "block"},
		} {
			line := fmt.Sprintf(command, row.name)
			rows = append(rows, r106Reader2Row{line, "project", line, row.want})
		}
	}
	r106Reader2CheckWith(t, rows, setup)
}

// TestSourcedScriptBehindMoreLinksThanTheSystemFollowsIsNotReadAsOpened: the
// system follows at most 40 links in one pathname (Linux), so a name that
// passes 41 of them before a .. opens no script: nothing runs, and the writer
// the evaluation of the whole chain would reach is not what the command
// sources. At the bound (40) it opens the writer, which blocks
// (rel-1-0-9:GAP-1038).
func TestSourcedScriptBehindMoreLinksThanTheSystemFollowsIsNotReadAsOpened(t *testing.T) {
	for _, count := range []int{39, 40} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			for _, connector := range []string{"claudecode", "codex"} {
				f := newB36ManagedHookFixture(t)
				live := filepath.Join(f.home, "chain", "live")
				if err := os.MkdirAll(live, 0o700); err != nil {
					t.Fatal(err)
				}
				for file, body := range map[string]string{
					filepath.Join(f.home, "chain", "wk.sh"): "echo marker >> $HOME/.ssh/authorized_keys\n",
					filepath.Join(f.project, "wk.sh"):       "echo ordinary >> report.txt\n",
				} {
					if err := os.WriteFile(file, []byte(body), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				for i := count; i >= 1; i-- {
					next := live
					if i < count {
						next = filepath.Join(f.project, fmt.Sprintf("hop%03d", i+1))
					}
					if err := os.Symlink(next, filepath.Join(f.project, fmt.Sprintf("hop%03d", i))); err != nil {
						t.Skipf("link unavailable: %v", err)
					}
				}
				// The portal is one more link than the hops: 40 in all open, 41 do not.
				if err := os.Symlink(filepath.Join(f.project, "hop001"), filepath.Join(f.project, "portal")); err != nil {
					t.Skipf("link unavailable: %v", err)
				}
				if _, err := os.Stat(f.project + "/portal/../wk.sh"); (err == nil) != (count == 39) ||
					count == 40 && !errors.Is(err, syscall.ELOOP) {
					t.Skipf("this system follows a different number of links in one name: %v", err)
				}
				payload := f.payload(t, "source portal/../wk.sh")
				header := f.clientHeader(t, payload)
				for _, mode := range []struct {
					name    string
					managed bool
					header  string
				}{{"per-user", false, ""}, {"per-user-with-client", false, header}, {"managed", true, header}} {
					blocked := strings.HasPrefix(r106HookVerdict(t, f, mode.managed, connector, payload, mode.header), "block")
					if want := count == 39; blocked != want {
						t.Errorf("%s %s with %d+1 links: blocked = %t, want %t", connector, mode.name, count, blocked, want)
					}
				}
			}
		})
	}
}
