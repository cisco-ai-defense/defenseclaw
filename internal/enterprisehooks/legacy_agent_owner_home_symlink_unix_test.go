// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterprisehooks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// GAP-0939: the owner token of a symlinked home took the device and inode
// of the home the symlink points at, but the creation time of the symlink
// itself. A home recreated behind the symlink with a reused inode then kept
// the token, and the account given the uid next inherited the earlier
// account's agent rows. The token now proves one object: the followed
// home, through the home's symlink or a symlinked parent alike.
func TestLegacyAgentOwnerTokenOfASymlinkedHomeIsItsTarget(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "real-alice")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	want := LegacyAgentOwnerToken("", target)
	if strings.Count(want, ":") < 3 {
		t.Skipf("the file system of %s keeps no creation time (token %q)", root, want)
	}
	// The symlinks are created later, so their own creation times differ.
	time.Sleep(20 * time.Millisecond)
	link := filepath.Join(root, "alice")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	parent := filepath.Join(t.TempDir(), "homes")
	if err := os.Symlink(root, parent); err != nil {
		t.Fatal(err)
	}
	for _, home := range []string{link, filepath.Join(parent, "alice"), filepath.Join(parent, "real-alice")} {
		if got := LegacyAgentOwnerToken("", home); got != want {
			t.Errorf("token of %s = %q; want the token of the home it names, %q", home, got, want)
		}
	}
	// A symlink to something that is not a directory proves nothing.
	file := filepath.Join(root, "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	fileLink := filepath.Join(root, "file-home")
	if err := os.Symlink(file, fileLink); err != nil {
		t.Fatal(err)
	}
	if got := LegacyAgentOwnerToken("", fileLink); got != "" {
		t.Errorf("token of a symlink to a file = %q; want none", got)
	}
}
