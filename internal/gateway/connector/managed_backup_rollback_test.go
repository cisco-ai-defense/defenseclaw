// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestRestoreManagedFileBackupsForRollbackUsesConnectorWideRecords(t *testing.T) {
	for _, tc := range []struct {
		name       string
		configured bool
	}{
		{"newer connector", false},
		{"still configured connector", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			home := filepath.Join(root, "home")
			path := filepath.Join(home, ".agent", "hooks.json")
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			original := []byte("{\n  \"operator\": \"keep\"\n}\n")
			installed := []byte("{\"operator\":\"keep\",\"owned\":true}\n")
			if err := os.WriteFile(path, original, 0o600); err != nil {
				t.Fatal(err)
			}
			saved := filepath.Join(root, "saved-data")
			current := filepath.Join(root, "current-data")
			if err := captureManagedFileBackup(saved, "newer-connector", "hooks.json", path); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, installed, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := updateManagedFileBackupPostHash(saved, "newer-connector", "hooks.json", path); err != nil {
				t.Fatal(err)
			}
			configured := map[string]bool{"newer-connector": tc.configured}
			restored, kept, err := RestoreManagedFileBackupsForRollback(saved, current, home, configured, "")
			if err != nil || len(kept) != 0 {
				t.Fatalf("restore = %v, kept = %v, err = %v", restored, kept, err)
			}
			want := original
			wantRestored := 1
			if tc.configured {
				want = installed
				wantRestored = 0
			}
			got, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(got, want) || len(restored) != wantRestored {
				t.Fatalf("vendor file = %q, %v; want %q, restored = %v", got, err, want, restored)
			}
		})
	}
}
