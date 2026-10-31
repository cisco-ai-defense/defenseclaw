// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"testing"
)

// After pushd DIR (as after cd DIR) a recursive copy or rsync of a project
// path spelled with a directory-stack word (~1, ~-, ~+1) reads that word as
// the directory the stack holds when every way the shell can reach the call
// gives the same one, and a managed gateway reads the copy sources of a
// simple command after pushd from the client facts: such copies blocked as
// an SSH authorized_keys command (GAP-2586, cells L-mac-J3-011 and
// L-erhel-J3-013). A copy into or out of ~/.ssh, a stack word that names a
// directory carrying a link to the keys file then a write through it, and a
// stack word after a cd that may have failed still block.
func TestR106DirectoryStackCopyAfterPushdStaysAllowed(t *testing.T) {
	judgeR106HookRows(t, []r106HookRow{
		{command: `pushd src && cp -r ../ordinary ord4`},
		{command: `pushd src && cp -r ~1/src s2`},
		{command: `pushd src && cp -r ~1/ordinary ord2`},
		{command: `pushd src && rsync -a ../ordinary/ out/`},
		{command: `pushd src && rsync -a ~1/ordinary/ out/`},
		{command: `pushd src && cp -r ~-/ordinary x`},
		{command: `pushd src && rsync -a ~-/ordinary/ out/`},
		{command: `cd src && cp -r ~-/ordinary x`},
		{command: `cd src && rsync -a ~-/ordinary/ out/`},
		{command: `cd src && cp -r ../ordinary ord5`},
		{command: `pushd src && cp -r ~+1/ordinary ord7`},
		{command: `pushd src && cp -r ~1/ordinary ~/.ssh/`, block: true},
		{command: `pushd src && cp a.txt ~/.ssh/authorized_keys`, block: true},
		{command: `pushd ~/.ssh && pushd /tmp && cp a.txt ~1/authorized_keys`, block: true},
		{command: `pushd ~/linked && pushd ~/project && cp -a ~1 lb && echo k >> lb/lnk`, block: true},
		{command: `pushd ~/linked; cp -a ~1 lb && echo k >> lb/lnk`, block: true},
		{command: `cd ~/linked && cd ~/project && cp -a ~- lb && echo k >> lb/lnk`, block: true},
		{command: `cd ~/linked && cd ~/project && cd /nonexistent-zz || cp -a ~- lb && echo k >> lb/lnk`, block: true},
		{command: `cd ~/linked && cd ~/project && cd /nonexistent-zz && true; cp -a ~- lb && echo k >> lb/lnk`, block: true},
		{command: `pushd /nonexistent-zz; pushd ~/linked && pushd ~/project && cp -a ~1 lb; echo k >> lb/lnk`, block: true},
		// Copies out of ~/.ssh through the stack: a managed gateway allows
		// the plain spelling too (pre-existing), judged per-user here.
		{command: `pushd src && cp -r ~/.ssh ~1/sshcopy`, block: true, perUserOnly: true},
		{command: `pushd ~/.ssh && pushd ~/project && cp -r ~1 k`, block: true, perUserOnly: true},
		{command: `pushd ~/.ssh && pushd /tmp && cp -r ~2/ordinary ~1/`, block: true, perUserOnly: true},
	}, func(t *testing.T, f b36ManagedHookFixture) {
		for _, dir := range []string{filepath.Join(f.project, "src"), filepath.Join(f.home, "linked")} {
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
		}
		for _, name := range []string{"a.txt", "src/a.txt", "ordinary/n.txt"} {
			if err := os.WriteFile(filepath.Join(f.project, name), []byte("x\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.Symlink(f.keys, filepath.Join(f.home, "linked", "lnk")); err != nil {
			t.Fatal(err)
		}
		// The cells had no keys link in the project.
		if err := os.Remove(filepath.Join(f.project, "keylink")); err != nil {
			t.Fatal(err)
		}
	})
}
