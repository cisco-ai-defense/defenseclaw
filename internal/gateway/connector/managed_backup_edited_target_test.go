// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"os"
	"path/filepath"
	"testing"
)

// A later setup merges over a file someone else changed after the earlier
// setup. It must not record those bytes as DefenseClaw own output: a restore
// would then put the pre-setup copy back over the change. A file nobody
// touched keeps the exact restore.
func TestManagedBackupLaterSetupKeepsEditedTargetOutOfExactRestore(t *testing.T) {
	for _, tc := range []struct {
		name      string
		edit      bool
		wantExact bool
	}{
		{"untouched file still restores exactly", false, true},
		{"edited file is left to the owned-entry cleanup", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			dataDir := filepath.Join(dir, "data")
			target := filepath.Join(dir, "home", "hooks.json")
			if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
				t.Fatal(err)
			}
			pristine := []byte("{\"operator\":true}\n")
			if err := os.WriteFile(target, pristine, 0o600); err != nil {
				t.Fatal(err)
			}
			setup := func(content string) {
				t.Helper()
				if err := captureManagedFileBackup(dataDir, "cursor", "hooks.json", target); err != nil {
					t.Fatal(err)
				}
				if content != "" {
					// The setup writes through the connector writer.
					if err := atomicWriteFile(target, []byte(content), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				if err := updateManagedFileBackupPostHash(dataDir, "cursor", "hooks.json", target); err != nil {
					t.Fatal(err)
				}
			}
			setup("{\"operator\":true,\"owned\":1}\n")
			if tc.edit {
				if err := os.WriteFile(target, []byte("{\n    \"operator\": true,\n    \"owned\": 1,\n    \"later\": 2\n}\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			// The later setup rewrites nothing here; it only records.
			setup("")
			restored, err := restoreManagedFileBackupIfUnchanged(dataDir, "cursor", "hooks.json", target)
			if err != nil {
				t.Fatal(err)
			}
			got, _ := os.ReadFile(target)
			if restored != tc.wantExact {
				t.Fatalf("exact restore = %v, want %v (file %q)", restored, tc.wantExact, got)
			}
			if tc.wantExact && string(got) != string(pristine) {
				t.Fatalf("restored file = %q, want %q", got, pristine)
			}
			if !tc.wantExact && string(got) == string(pristine) {
				t.Fatalf("the edited file was replaced by the pre-setup copy: %q", got)
			}
		})
	}
}
