// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
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
	// One representative row per behaviour and its benign twin; the launcher
	// spellings (login, nice, nested, subshell) are covered by the hookpaths test.
	rows := []r106HookRow{
		{command: `cd a && bash -c "source ok.sh"`},
		{command: `cd a && bash -c "source wk.sh"`, block: true},
		{command: `cd a && bash -c "source portal/../ok.sh"`},
		{command: `cd a && bash -c "source portal/../wk.sh"`, block: true},
		{command: `cd a && sh -c ". ./wk.sh"`, block: true},
		{command: `cd a && env X=1 bash -c "source wk.sh"`, block: true},
		// A change back to the starting folder places the script there again.
		{command: `cd a && cd .. && bash -c "source wk.sh"`},
		{command: `cd a && cd .. && bash -c "source ok.sh"`, block: true},
	}
	judgeR106HookRows(t, rows, prepare)
}
