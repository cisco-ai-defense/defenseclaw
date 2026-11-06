// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ~/.ssh/config, environment and rc are login policy as much as
// authorized_keys: environment and rc run at every login, config can run a
// command for every connection. A copy or other write into one of them
// raises persistence.ssh_authorized_keys_command on a per-user and a
// managed gateway (lead ruling 10-31 for rel-1-0-4:GAP-2586); a plain
// project copy onto ~/.ssh/config was allowed. Reads of ~/.ssh/config, an
// unrelated new file under ~/.ssh and ordinary project copies stay allowed.
func TestR106WriteIntoSSHControlFilesIsAKeysWrite(t *testing.T) {
	judgeR106AlertRows(t, []r106HookRow{
		{command: `cp a.txt ~/.ssh/config`, block: true},
		{command: `cp a.txt HOMEDIR/.ssh/config`, block: true},
		{command: `cd ~/.ssh && cp ~/project/a.txt config`, block: true},
		{command: `pushd src && cp ~1/a.txt ~/.ssh/config`, block: true},
		{command: `cp a.txt ~/.ssh/environment`, block: true},
		{command: `cp a.txt ~/.ssh/rc`, block: true},
		{command: `cp a.txt ~/.ssh/authorized_keys2`, block: true},
		{command: `mv a.txt ~/.ssh/config`, block: true},
		{command: `install -m600 a.txt ~/.ssh/config`, block: true},
		{command: `cat a.txt > ~/.ssh/config`, block: true},
		{command: `echo Host x >> ~/.ssh/config`, block: true},
		{command: `tee ~/.ssh/config < a.txt`, block: true},
		{command: `cp -r ordinary ~/.ssh/config`, block: true},
		{command: `ln -s ../.ssh s; cp a.txt s/config`, block: true},
		{command: `sed -i s/a/b/ ~/.ssh/config`, block: true},
		// A copy into the .ssh directory itself keeps its earlier reading.
		{command: `cp a.txt ~/.ssh/`, block: true},
		{command: `cd ~/.ssh && cp ~/project/a.txt scratch.txt`, block: true},
		{command: `cp a.txt ~/.ssh/scratch-note.txt`},
		{command: `cat ~/.ssh/config`},
		{command: `cp ~/.ssh/config ssh-config.bak`},
		{command: `grep Host ~/.ssh/config`},
		{command: `ssh -F ~/.ssh/config -G host`},
		{command: `cp a.txt b.txt`},
		{command: `cp a.txt config`},
		{command: `pushd src && cp -r ~1/ordinary ord2`},
	}, func(t *testing.T, f b36ManagedHookFixture) {
		for _, dir := range []string{filepath.Join(f.project, "src"), filepath.Join(f.project, "ordinary")} {
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
		}
		for _, name := range []string{filepath.Join(f.project, "a.txt"), filepath.Join(f.project, "src", "a.txt"),
			filepath.Join(f.project, "ordinary", "n.txt"), filepath.Join(f.home, ".ssh", "config")} {
			if err := os.WriteFile(name, []byte("x\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.Remove(filepath.Join(f.project, "keylink")); err != nil {
			t.Fatal(err)
		}
	})
}

// judgeR106AlertRows is judgeR106HookRows for rows of the shell-command
// protected-file class: a row with block set gets the default profile's
// alert with the keys rule; every other row is allowed.
func judgeR106AlertRows(t *testing.T, rows []r106HookRow, prepare func(t *testing.T, f b36ManagedHookFixture)) {
	t.Helper()
	for _, mode := range []struct {
		managed, header bool
	}{{true, true}, {false, true}, {false, false}} {
		for _, connector := range []string{"claudecode", "codex"} {
			for _, row := range rows {
				if mode.managed && row.perUserOnly {
					continue
				}
				f := newB36ManagedHookFixture(t)
				prepare(t, f)
				command := strings.NewReplacer("HOMEDIR", f.home, "EXTDIR", filepath.Join(filepath.Dir(f.homes), "ext")).Replace(row.command)
				payload := f.payload(t, command)
				header := ""
				if mode.header {
					header = f.clientHeader(t, payload)
				}
				want := "allow"
				if row.block {
					// rel-1-0-6:GAP-0675 (owner 2026-11-06): the default profile alerts on a shell-command protected-file write; strict blocks it (TestGAP0675ShellProtectedFileWarnsOutsideStrictOnEveryRoute).
					want = "alert"
				}
				if got := r106HookVerdict(t, f, mode.managed, connector, payload, header); got != want {
					t.Errorf("managed=%v header=%v %s %q: %s, want %s", mode.managed, mode.header, connector, row.command, got, want)
				}
				_ = os.Chmod(f.homes, 0o700)
			}
		}
	}
}
