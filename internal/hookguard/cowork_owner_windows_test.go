// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hookguard

import (
	"os"
	"path/filepath"
	"testing"
)

// A marker this account wrote in a folder it made is trusted; a folder or a
// reparse point in its place is not a marker (cowork-1-0-8 GAP-0085).
func TestCoworkMarkerOwnerTrustedReadsTheRealOwners(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), ".defenseclaw")
	marker, _ := CoworkRemovalPaths(dataDir)
	if err := os.WriteFile(marker, []byte("removed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !coworkMarkerOwnerTrusted(marker) {
		t.Fatal("this account's marker in its own folder was not trusted")
	}
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(marker, 0o700); err != nil {
		t.Fatal(err)
	}
	if coworkMarkerOwnerTrusted(marker) {
		t.Fatal("a folder at the marker path was trusted as a marker")
	}
	if _, err := coworkPathOwner(filepath.Join(filepath.Dir(marker), "missing"), false); err == nil {
		t.Fatal("a missing marker has an owner")
	}
}
