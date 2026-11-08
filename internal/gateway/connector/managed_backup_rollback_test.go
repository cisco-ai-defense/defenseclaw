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
			if err := atomicWriteFile(path, installed, 0o600); err != nil {
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
		name    string
		target  string
		wantN   int
		wantErr bool
	}{
		{"absolute target under home", path, 1, false},
		{"empty target", "", 0, true},
		{"relative target", "relative-hooks.json", 0, true},
		{"target outside home is skipped, not proof", filepath.Join(root, "elsewhere", "hooks.json"), 0, false},
		{"target inside the current data folder", filepath.Join(current, "hooks.json"), 0, true},
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
			if n != tc.wantN || (err != nil) != tc.wantErr {
				t.Fatalf("record target %q = %d, %v; want %d, error=%v", tc.target, n, err, tc.wantN, tc.wantErr)
			}
		})
	}
}

func TestVerifyManagedFileBackupsOutsideHomeRecordDoesNotVetoUsableOnes(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	current := filepath.Join(root, "data")
	saved := filepath.Join(root, "saved-data")
	inside := filepath.Join(home, ".agent", "hooks.json")
	outside := filepath.Join(root, "moved-config", "config.json")
	for _, p := range []string{inside, outside} {
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("{}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := captureManagedFileBackup(saved, "inside-connector", "hooks.json", inside); err != nil {
		t.Fatal(err)
	}
	if err := captureManagedFileBackup(saved, "moved-connector", "config.json", outside); err != nil {
		t.Fatal(err)
	}
	if n, err := VerifyManagedFileBackups(saved, current, home); n != 1 || err != nil {
		t.Fatalf("one usable and one outside-home record = %d, %v; want 1, nil", n, err)
	}
	// An outside-home record is still checked against its digest.
	record := managedFileBackupPath(saved, "moved-connector", "config.json")
	raw, err := os.ReadFile(record)
	if err != nil {
		t.Fatal(err)
	}
	var rec map[string]any
	if err := json.Unmarshal(raw, &rec); err != nil {
		t.Fatal(err)
	}
	rec["pristine_sha256"] = "00"
	if raw, err = json.Marshal(rec); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(record, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyManagedFileBackups(saved, current, home); err == nil {
		t.Fatal("an outside-home record with a bad digest was accepted")
	}
}
