// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// A fixed-text echo (no expansion, no redirect, no pipe) joined to a
// statement by ;, && or || is verdict-neutral: the command gets the verdict
// of the statement alone (lead ruling 2026-10-31 18:34 EDT,
// rel-1-0-6:GAP-0225; the live form ended a read of a keys link with a done
// marker). Every write, copy, pipe, redirect or substitution form keeps its
// verdict, and so does an echo whose text expands or is redirected or piped.
func TestFixedTextEchoJoinedToAStatementIsVerdictNeutral(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX reading with a symlink fixture; the Windows readings have their own rows")
	}
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	sshDir := filepath.Join(home, ".ssh")
	keys := filepath.Join(sshDir, "authorized_keys")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(cwd, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keys, []byte("decoy\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(keys, filepath.Join(cwd, "keylink")); err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct{ statement, compound string }{
		{"uniq keylink > /dev/null", "uniq keylink > /dev/null; echo done"},
		{"uniq keylink > /dev/null", "uniq keylink > /dev/null; echo uniq-done"},
		{"cat keylink", "cat keylink; echo done"},
		{"cat keylink", "echo start; cat keylink"},
		{"cat keylink", "cat keylink || echo 'read failed'"},
		{"ls ~/.ssh", "ls ~/.ssh && echo done"},
		{"ls -la ~/.ssh", `ls -la ~/.ssh && echo "listed: ok"`},
		{"wc -l keylink", "wc -l keylink && echo -n done"},
	} {
		alone := posixShellDecision(row.statement, cwd, home)
		if alone != "" {
			t.Fatalf("%q alone = %q, want allow (fixture)", row.statement, alone)
		}
		if got := posixShellDecision(row.compound, cwd, home); got != alone {
			t.Errorf("%q = %q, want %q (the verdict of %q alone)", row.compound, got, alone, row.statement)
		}
	}
	for _, command := range []string{
		"echo $(cat keylink)",
		"echo x > keylink",
		"echo x >> ~/.ssh/authorized_keys; echo done",
		"cat keylink | tee out; echo done",
		"cp a.txt keylink; echo done",
		"cat keylink; echo $HOME",
		"cat keylink; echo ${HOME}",
		"cat keylink; echo *",
		"cat keylink; echo ~/.ssh/authorized_keys",
		"cat keylink; echo done > out",
		"cat keylink; echo done | sh",
		"cat keylink; echo `id`",
		"cat keylink; (echo done)",
		"cat keylink; echo done &",
	} {
		if got := posixShellDecision(command, cwd, home); got != "protected-target" {
			t.Errorf("%q = %q, want protected-target", command, got)
		}
	}
}
