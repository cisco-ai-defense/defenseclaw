//go:build linux

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package unixidentity

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestLinuxLocalAccountsAndDirectoryConfiguration(t *testing.T) {
	dir := t.TempDir()
	origPasswd, origNSS := localPasswdPath, nsswitchPath
	t.Cleanup(func() { localPasswdPath, nsswitchPath = origPasswd, origNSS })
	localPasswdPath = filepath.Join(dir, "passwd")
	nsswitchPath = filepath.Join(dir, "nsswitch.conf")
	if err := os.WriteFile(localPasswdPath, []byte("alice:x:1000:1000::/home/alice:/bin/bash\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	local, err := LocalAccounts(context.Background())
	if err != nil || local["alice"] != 1000 || len(local) != 1 {
		t.Fatalf("LocalAccounts = %v, %v", local, err)
	}
	if DirectoryConfigured() {
		t.Fatal("a missing nsswitch.conf is glibc's files-only default")
	}
	if err := os.WriteFile(nsswitchPath, []byte("passwd: sss files systemd\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !DirectoryConfigured() {
		t.Fatal("an sss passwd source is a directory")
	}
	if err := os.Chmod(nsswitchPath, 0o000); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() != 0 && !DirectoryConfigured() {
		t.Fatal("an unreadable nsswitch.conf must be treated as a directory host")
	}
}
