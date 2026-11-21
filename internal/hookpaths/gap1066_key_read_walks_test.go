// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestGAP1066WideKeyPatternResolvesNoPlainMatch is rel-1-0-10:GAP-1066 on
// darwin and Windows. The private-key reader expands a wide pattern up to its
// cap of 4,096 entries and asks of each match whether it is a key. Off Linux
// the answer walked every match through its links (ResolveWriteTarget), about
// ten file system reads a match: $PWD/w/*/* answered in 80-90 ms (and twice
// that before GAP-1560) of the 200 ms inspect budget on a macOS runner, where
// Linux answers in one stat a match. A match that is there, is no link, and
// whose base name is no key name in any case is a key only as the same file
// as one, which its own lstat answers: it resolves no link.
//
// The answers stay: a hard link to the key and a link to it in the first
// folder are reads; a file spelled like a key in another case that is not
// the key is not, and is still resolved (its name can be a key's). On Linux
// the reader already answers each match with one stat, so the walk count is
// 0 before and after the fix there; the fail-before is a darwin or Windows
// run (macOS CI, native Windows).
func TestGAP1066WideKeyPatternResolvesNoPlainMatch(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	key := filepath.Join(home, ".ssh", "id_ed25519")
	if err := os.MkdirAll(filepath.Dir(key), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, []byte("-----BEGIN OPENSSH PRIVATE KEY-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	wide := func(name string) string {
		dir := filepath.Join(root, name)
		for folder := range 8 {
			sub := filepath.Join(dir, fmt.Sprintf("d%d", folder))
			if err := os.MkdirAll(sub, 0o700); err != nil {
				t.Fatal(err)
			}
			for file := range 600 {
				if err := os.WriteFile(filepath.Join(sub, fmt.Sprintf("f%03d", file)), nil, 0o600); err != nil {
					t.Fatal(err)
				}
			}
		}
		return dir
	}
	pattern := func(dir string) string { return filepath.Join(dir, "*", "*") }

	plain := wide("plain")
	before := writeTargetWalks.Load()
	read := actionGlobReadsPrivateKey(pattern(plain), false, root, home)
	walks := writeTargetWalks.Load() - before
	if read {
		t.Errorf("%s: a key read where no match is the key", pattern(plain))
	}
	// Each of the 4,088 matches before the cap was walked before the fix.
	if walks > 64 {
		t.Errorf("%s: %d link walks for matches that are plain files with no key name, want at most 64 (one lstat a match, GAP-1066)", pattern(plain), walks)
	}
	t.Logf("%s %s: %d link walks", runtime.GOOS, pattern(plain), walks)

	hard := wide("hard")
	if err := os.MkdirAll(filepath.Join(hard, "a"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(key, filepath.Join(hard, "a", "k")); err != nil {
		t.Fatal(err)
	}
	if !actionGlobReadsPrivateKey(pattern(hard), false, root, home) {
		t.Errorf("%s: a hard link to the key in the first folder is not a read", pattern(hard))
	}

	decoy := filepath.Join(root, "decoy")
	if err := os.MkdirAll(filepath.Join(decoy, "a"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(decoy, "a", "ID_ED25519"), []byte("not a key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	before = writeTargetWalks.Load()
	if actionGlobReadsPrivateKey(pattern(decoy), false, root, home) {
		t.Errorf("%s: a file spelled like a key in another folder is a read", pattern(decoy))
	}
	if walks := writeTargetWalks.Load() - before; (runtime.GOOS == "darwin" || runtime.GOOS == "windows") && walks == 0 {
		t.Errorf("%s: a match whose name can be a key name was not resolved", pattern(decoy))
	}

	linked := filepath.Join(root, "linked")
	if err := os.MkdirAll(filepath.Join(linked, "a"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(key, filepath.Join(linked, "a", "k")); err != nil {
		// A Windows token without the symlink privilege makes no link; the
		// hard link row above holds the identity answer there.
		t.Logf("no symlink row: %v", err)
		return
	}
	if !actionGlobReadsPrivateKey(pattern(linked), false, root, home) {
		t.Errorf("%s: a link to the key is not a read", pattern(linked))
	}
}
