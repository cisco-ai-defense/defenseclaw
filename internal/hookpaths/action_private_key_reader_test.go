// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// GAP-0281: every common program that prints a file's content reads a
// private key named as its operand, as cat, head and tail do; metadata
// programs, the public key and ordinary files are not key reads.
func TestActionPrivateKeyReadCoversEveryContentReader(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX home")
	}
	home := t.TempDir()
	cwd := filepath.Join(home, "proj")
	for _, dir := range []string{filepath.Join(home, ".ssh"), cwd} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"id_ed25519", "id_ed25519.pub"} {
		if err := os.WriteFile(filepath.Join(home, ".ssh", name), []byte("decoy\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, command := range []string{
		"less ~/.ssh/id_ed25519", "more ~/.ssh/id_ed25519", "grep -v x ~/.ssh/id_ed25519",
		"xxd ~/.ssh/id_ed25519", "strings ~/.ssh/id_ed25519", "cut -c1-10 ~/.ssh/id_ed25519",
		"nl ~/.ssh/id_ed25519", "tac ~/.ssh/id_ed25519", "awk 1 ~/.ssh/id_ed25519",
		"od -c ~/.ssh/id_ed25519", "hexdump -C ~/.ssh/id_ed25519", "sort ~/.ssh/id_ed25519",
		"rev ~/.ssh/id_ed25519", "diff ~/.ssh/id_ed25519 /dev/null", "egrep . ~/.ssh/id_ed25519",
		"cat ~/.ssh/id_ed25519",
	} {
		if !ActionPrivateKeyRead(command, cwd, home) {
			t.Errorf("ActionPrivateKeyRead(%q) = false, want a key read", command)
		}
	}
	for _, command := range []string{
		"less ~/.ssh/id_ed25519.pub", "grep ssh ~/.ssh/id_ed25519.pub", "xxd README.md",
		"ls -l ~/.ssh/id_ed25519", "stat ~/.ssh/id_ed25519", "ssh -i ~/.ssh/id_ed25519 host true",
		"sort notes.txt", "awk 1 notes.txt",
	} {
		if ActionPrivateKeyRead(command, cwd, home) {
			t.Errorf("ActionPrivateKeyRead(%q) = true, want no key read", command)
		}
	}
}
