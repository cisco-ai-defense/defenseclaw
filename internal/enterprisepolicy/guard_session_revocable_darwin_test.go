//go:build darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"os/exec"
	"os/user"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// macOS checks an ACL deny entry before the mode bits: a deny of adding or
// removing a file locks the folder, an inherit-only one or an allow does
// not. So do the user immutable and append-only flags.
func TestPublishedSessionFolderIsLockedReadsMacOSDenyEntriesAndFlags(t *testing.T) {
	account, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		entry  string
		locked bool
	}{
		{"user:" + account.Username + " allow add_file,delete_child", false},
		{"user:" + account.Username + " deny delete_child", true},
		{"group:everyone deny add_file", true},
		{"group:everyone deny add_file,only_inherit,directory_inherit", false},
	} {
		dir := t.TempDir()
		if output, err := exec.Command("/bin/chmod", "+a", c.entry, dir).CombinedOutput(); err != nil {
			t.Fatalf("chmod +a %q: %v %s", c.entry, err, output)
		}
		if locked, err := publishedSessionFolderIsLocked(dir); err != nil || locked != c.locked {
			t.Fatalf("%q: locked %v (%v), want %v", c.entry, locked, err, c.locked)
		}
	}
	for _, flag := range []uint32{unix.UF_IMMUTABLE, unix.UF_APPEND} {
		dir := t.TempDir()
		if err := unix.Chflags(dir, int(flag)); err != nil {
			t.Fatal(err)
		}
		locked, err := publishedSessionFolderIsLocked(dir)
		_ = unix.Chflags(dir, 0)
		if err != nil || !locked {
			t.Fatalf("flag %#x: locked %v (%v)", flag, locked, err)
		}
	}
	if publishedSessionACLDeniesChange(managed.DarwinACLEntry{Allow: false, Rights: []string{"read", "search"}}) {
		t.Fatal("a deny of reading does not lock the folder")
	}
}
