// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package ideplugins

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWindowsHomeGrantsIgnoreLinkedNvimLockfile(t *testing.T) {
	home := t.TempDir()
	outside := t.TempDir()
	writeFile(t, filepath.Join(outside, "lazy-lock.json"), `{"other-user-plugin":{}}`)
	nvim := filepath.Join(home, "AppData", "Local", "nvim")
	if err := os.MkdirAll(filepath.Dir(nvim), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, nvim); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	lazy := filepath.Join(home, "AppData", "Local", "nvim-data", "lazy")
	writeFile(t, filepath.Join(lazy, "other-user-plugin"), "regular file")
	if err := os.Mkdir(filepath.Join(lazy, "installed-plugin"), 0o700); err != nil {
		t.Fatal(err)
	}
	grants := WindowsHomeGrants(home)
	for _, grant := range grants {
		if grant.Path == `AppData\Local\nvim-data\lazy\other-user-plugin` {
			t.Fatalf("lockfile selected a regular file for a grant: %+v", grant)
		}
	}
	found := false
	for _, grant := range grants {
		found = found || grant.Path == `AppData\Local\nvim-data\lazy\installed-plugin`
	}
	if !found {
		t.Fatal("installed plugin directory was not granted")
	}
}
