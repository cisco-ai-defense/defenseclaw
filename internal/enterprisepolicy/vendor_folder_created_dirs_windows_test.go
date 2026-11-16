// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisepolicy

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// g582 round 9 L3: the removal of a recorded file in a vendor folder that does
// not protect it also removes the empty folders DefenseClaw created for the
// record, except where an untrusted account can change the parent of such a
// folder: there the removal is not DefenseClaw's to do, and it says so.
func TestRemovalOfAnUnprotectedVendorFolderRemovesTheFoldersDefenseClawCreated(t *testing.T) {
	root := t.TempDir()
	trusted := filepath.Join(root, "trusted")
	blocked := filepath.Join(root, "blocked")
	records := []string{
		filepath.Join(trusted, "empty"),
		filepath.Join(trusted, "holds-a-file"),
		filepath.Join(blocked, "empty"),
	}
	for _, dir := range records {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(records[1], "vendor.json"), []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	previous := validateTrustedDir
	validateTrustedDir = func(dir string) error {
		if strings.EqualFold(filepath.Clean(dir), blocked) {
			return errors.New("an untrusted account can change " + dir)
		}
		return nil
	}
	t.Cleanup(func() { validateTrustedDir = previous })

	var state State
	removeRecordedCreatedDirs(Options{}, &ownershipRecord{CreatedDirs: records}, &state, true)

	if _, err := os.Lstat(records[0]); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("an empty folder DefenseClaw created under a trusted parent stayed: %v", err)
	}
	if _, err := os.Lstat(records[1]); err != nil {
		t.Fatalf("a folder that holds a file was removed: %v", err)
	}
	if _, err := os.Lstat(records[2]); err != nil {
		t.Fatalf("a folder whose parent an untrusted account can change was removed: %v", err)
	}
	named := false
	for _, detail := range state.Details {
		if strings.Contains(detail, "left "+records[2]+" in place") {
			named = true
		}
	}
	if !named {
		t.Fatalf("details = %q; want the folder under the untrusted parent named as left", state.Details)
	}
}
