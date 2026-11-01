// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"os"
	"path/filepath"
	"testing"
)

// GAP-2078: a device identity directory below a root-owned alias in a
// root-only directory (/var/run -> /run on the build hosts, an
// administrator's /home/team -> /srv/team) is not indirect; an
// account-owned symlink still is.
func TestDeviceIdentityPathTrustsOnlyRootAliases(t *testing.T) {
	if info, err := os.Lstat("/var/run"); err == nil && info.Mode()&os.ModeSymlink != 0 {
		if !onlyRootAliasesInPath("/var/run") {
			t.Error("the root-owned alias /var/run counts as indirect")
		}
	}
	root := t.TempDir()
	real := filepath.Join(root, "real")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() != 0 && onlyRootAliasesInPath(link) {
		t.Error("an account-owned symlink counts as a root alias")
	}
	if !onlyRootAliasesInPath(real) {
		t.Error("a path with no symlink counts as indirect")
	}
}
