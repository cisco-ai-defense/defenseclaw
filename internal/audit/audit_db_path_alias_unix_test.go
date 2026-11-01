// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package audit

import (
	"os"
	"path/filepath"
	"testing"
)

// GAP-2078: a root-owned directory symlink below the top level, in a
// directory only root can write (an administrator's /home/team -> /srv/team;
// on the build hosts /var/run -> /run), is a trusted alias for the audit and
// judge body stores. A symlink an account can replace still fails.
func TestRootOwnedLowerLevelDirectoryAliasIsTrusted(t *testing.T) {
	var alias string
	for _, candidate := range []string{"/var/run", "/var/lock"} {
		if info, err := os.Lstat(candidate); err == nil && info.Mode()&os.ModeSymlink != 0 && rootOnlyDirectory(filepath.Dir(candidate)) {
			alias = candidate
			break
		}
	}
	if alias == "" {
		t.Skip("no root-owned lower-level directory symlink on this host")
	}
	info, err := os.Lstat(alias)
	if err != nil {
		t.Fatal(err)
	}
	if !trustedAuditDBSystemDirectoryAlias(alias, info) {
		t.Errorf("audit store refuses the root-owned alias %s", alias)
	}
	if !trustedJudgeBodySystemDirectoryAlias(alias, info) {
		t.Errorf("judge body store refuses the root-owned alias %s", alias)
	}
}

func TestAccountOwnedDirectoryAliasStillFails(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "real")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(link)
	if err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() != 0 {
		if trustedAuditDBSystemDirectoryAlias(link, info) || trustedJudgeBodySystemDirectoryAlias(link, info) {
			t.Fatal("an account-owned symlink counts as a trusted alias")
		}
		if err := validateAuditDBDirectory(link, info, true); err == nil {
			t.Fatal("an account-owned symlink in the audit path is accepted")
		}
	}
	// A root-owned link in a directory its account can write is replaceable.
	if rootOnlyDirectory(root) {
		t.Fatalf("%s counts as root-only", root)
	}
}
