// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// TestSourcedScriptInAShellWrapperAfterADirectoryChangeIsJudgedWhereItRuns: a
// directory change outside a shell -c wrapper moves the script its body names
// too. cd a && bash -c "source ok.sh" opens a/ok.sh, so the writer that lies
// at the same name in the folder the hook started in does not block the
// ordinary script, and the writer in a blocks although an ordinary script lies
// at the starting name, whatever launcher stands before the body, through a
// folder link and a .., managed, per-user and per-user without the client
// header (rel-1-0-9:GAP-1038).
func TestSourcedScriptInAShellWrapperAfterADirectoryChangeIsJudgedWhereItRuns(t *testing.T) {
	writer := "echo marker >> $HOME/.ssh/authorized_keys\n"
	ordinary := "echo ordinary >> report.txt\n"
	// project/portal leads to home/other/live; project/a/portal to
	// home/chain/live. From the project, portal/../NAME is home/other/NAME;
	// from a, it is home/chain/NAME.
	prepare := func(t *testing.T, f b36ManagedHookFixture) {
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
	var rows []r106HookRow
	for _, shape := range []string{
		`cd a && bash -c "source %s"`,
		`cd a && sh -c ". ./%s"`,
		`cd a && env X=1 bash -c "source %s"`,
		`cd a && bash --login -c "source %s"`,
		`cd a && nice bash -c "source %s"`,
		`cd a && bash -c "bash %s"`,
		`cd a && bash -c "bash -c \"source %s\""`,
		`(cd a && bash -c "source %s")`,
		`cd a && cd . && bash -c "source %s"`,
	} {
		for _, name := range []string{"ok.sh", "portal/../ok.sh", "wk.sh", "portal/../wk.sh"} {
			rows = append(rows, r106HookRow{command: fmt.Sprintf(shape, name), block: filepath.Base(name) == "wk.sh"})
		}
	}
	// The change inside the wrapper, and one back to the starting folder,
	// still place the script where it runs.
	rows = append(rows,
		r106HookRow{command: `bash -c "cd a && source ok.sh"`},
		r106HookRow{command: `bash -c "cd a && source wk.sh"`, block: true},
		r106HookRow{command: `cd a && cd .. && bash -c "source wk.sh"`},
		r106HookRow{command: `cd a && cd .. && bash -c "source ok.sh"`, block: true},
		r106HookRow{command: `cd a && cd .. && bash -c "source portal/../ok.sh"`, block: true},
		r106HookRow{command: `bash -c "source ok.sh"`, block: true},
		r106HookRow{command: `bash -c "source wk.sh"`},
	)
	judgeR106HookRows(t, rows, prepare)
}
