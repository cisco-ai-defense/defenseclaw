// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"encoding/json"
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

func TestVerifyManagedFileBackupsCountsOnlyUsableRecords(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	path := filepath.Join(home, ".agent", "hooks.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	saved := filepath.Join(root, "saved-data")
	if n, err := VerifyManagedFileBackups(saved, filepath.Join(root, "data"), home); n != 0 || err != nil {
		t.Fatalf("missing folder = %d, %v; want 0, nil", n, err)
	}
	if err := captureManagedFileBackup(saved, "newer-connector", "hooks.json", path); err != nil {
		t.Fatal(err)
	}
	if n, err := VerifyManagedFileBackups(saved, filepath.Join(root, "data"), home); n != 1 || err != nil {
		t.Fatalf("one record = %d, %v; want 1, nil", n, err)
	}
	record := managedFileBackupPath(saved, "newer-connector", "hooks.json")
	if err := os.WriteFile(record, []byte("{invalid"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyManagedFileBackups(saved, filepath.Join(root, "data"), home); err == nil {
		t.Fatal("a record that does not parse was accepted")
	}
}

func TestVerifyManagedFileBackupsRejectsRecordsWithoutUsableTarget(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	current := filepath.Join(root, "data")
	path := filepath.Join(home, ".agent", "hooks.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		target string
		ok     bool
	}{
		{"absolute target under home", path, true},
		{"empty target", "", false},
		{"relative target", "relative-hooks.json", false},
		{"target outside home", filepath.Join(root, "elsewhere", "hooks.json"), false},
		{"target inside the current data folder", filepath.Join(current, "hooks.json"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			saved := filepath.Join(t.TempDir(), "saved-data")
			if err := captureManagedFileBackup(saved, "newer-connector", "hooks.json", path); err != nil {
				t.Fatal(err)
			}
			record := managedFileBackupPath(saved, "newer-connector", "hooks.json")
			raw, err := os.ReadFile(record)
			if err != nil {
				t.Fatal(err)
			}
			var rec map[string]any
			if err := json.Unmarshal(raw, &rec); err != nil {
				t.Fatal(err)
			}
			rec["path"] = tc.target
			if raw, err = json.Marshal(rec); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(record, raw, 0o600); err != nil {
				t.Fatal(err)
			}
			n, err := VerifyManagedFileBackups(saved, current, home)
			if tc.ok && (n != 1 || err != nil) {
				t.Fatalf("usable record = %d, %v; want 1, nil", n, err)
			}
			if !tc.ok && err == nil {
				t.Fatalf("record target %q was accepted as rollback proof", tc.target)
			}
		})
	}
}
