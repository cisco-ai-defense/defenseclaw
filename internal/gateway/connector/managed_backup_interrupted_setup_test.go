// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// An operator edit must never become the recorded output of a later setup,
// whichever point of the earlier or the later setup it lands at: before the
// later setup starts with the earlier one stopped before it published its
// post hash, or after the later setup took its capture and before it read the
// file back.
func TestManagedBackupLaterSetupNeverAdoptsOutsideEdit(t *testing.T) {
	for _, tc := range []struct {
		name             string
		publishFirstHash bool
		editAfterCapture bool
	}{
		{"earlier setup stopped before its post hash", false, false},
		{"edit between the later capture and its read-back", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			dataDir := filepath.Join(root, "data")
			target := filepath.Join(root, "home", "hooks.json")
			if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
				t.Fatal(err)
			}
			installed := []byte("{\"operator\":true,\"owned\":1}\n")
			edited := []byte("{\"operator\":true,\"owned\":1,\"later\":2}\n")
			if err := os.WriteFile(target, []byte("{\"operator\":true}\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := captureManagedFileBackup(dataDir, "cursor", "config", target); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(target, installed, 0o600); err != nil {
				t.Fatal(err)
			}
			if tc.publishFirstHash {
				if err := updateManagedFileBackupPostHash(dataDir, "cursor", "config", target); err != nil {
					t.Fatal(err)
				}
			}
			if !tc.editAfterCapture {
				if err := os.WriteFile(target, edited, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if err := captureManagedFileBackup(dataDir, "cursor", "config", target); err != nil {
				t.Fatal(err)
			}
			if tc.editAfterCapture {
				if err := os.WriteFile(target, edited, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if err := patchCursorHooks(target, filepath.Join(root, "cursor-hook.sh"), "", false); err != nil {
				t.Fatal(err)
			}
			if err := updateManagedFileBackupPostHash(dataDir, "cursor", "config", target); err != nil {
				t.Fatal(err)
			}
			restored, err := restoreManagedFileBackupIfUnchanged(dataDir, "cursor", "config", target)
			if err != nil {
				t.Fatal(err)
			}
			got, err := os.ReadFile(target)
			if err != nil {
				t.Fatal(err)
			}
			var doc map[string]any
			if err := json.Unmarshal(got, &doc); err != nil {
				t.Fatal(err)
			}
			if restored || doc["later"] != float64(2) {
				t.Fatalf("the outside edit was adopted: exact restore=%v, file=%q", restored, got)
			}
		})
	}
}

// Cursor Setup run twice over the same file, with an operator edit after the
// first run and a record the first run left without a post hash, keeps the
// edit on rollback. The same two runs with nobody touching the file still
// restore the pre-setup bytes exactly.
func TestCursorSetupAfterIncompleteRecordKeepsOperatorEdit(t *testing.T) {
	for _, tc := range []struct {
		name      string
		edit      bool
		wantExact bool
	}{
		{"untouched file restores exactly", false, true},
		{"edited file keeps the edit", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			t.Setenv("HOME", root)
			t.Setenv("USERPROFILE", root)
			dataDir := filepath.Join(root, "data")
			target := filepath.Join(root, ".cursor", "hooks.json")
			if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
				t.Fatal(err)
			}
			pristine := []byte("{\"hooks\":{\"stop\":[{\"command\":\"echo operator\"}]}}\n")
			if err := os.WriteFile(target, pristine, 0o600); err != nil {
				t.Fatal(err)
			}
			conn := NewCursorConnector()
			opts := SetupOpts{DataDir: dataDir, APIAddr: "127.0.0.1:18970", APIToken: "test-token"}
			if err := conn.Setup(context.Background(), opts); err != nil {
				t.Fatal(err)
			}
			if tc.edit {
				// A stopped process leaves the written file with a record that
				// has no post hash yet.
				record := managedFileBackupPath(dataDir, "cursor", "config")
				b, err := loadManagedFileBackupPath(record)
				if err != nil {
					t.Fatal(err)
				}
				b.PostSHA256 = ""
				if err := writeManagedFileBackup(record, b); err != nil {
					t.Fatal(err)
				}
				installed, err := os.ReadFile(target)
				if err != nil {
					t.Fatal(err)
				}
				var doc map[string]any
				if err := json.Unmarshal(installed, &doc); err != nil {
					t.Fatal(err)
				}
				doc["operator_after_setup"] = true
				out, err := json.MarshalIndent(doc, "", "    ")
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(target, append(out, 0x0a), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if err := conn.Setup(context.Background(), opts); err != nil {
				t.Fatal(err)
			}
			restored, err := restoreManagedFileBackupIfUnchanged(dataDir, "cursor", "config", target)
			if err != nil {
				t.Fatal(err)
			}
			got, err := os.ReadFile(target)
			if err != nil {
				t.Fatal(err)
			}
			if restored != tc.wantExact {
				t.Fatalf("exact restore = %v, want %v (file %q)", restored, tc.wantExact, got)
			}
			if tc.wantExact && string(got) != string(pristine) {
				t.Fatalf("restored file = %q, want %q", got, pristine)
			}
			if !tc.wantExact {
				var doc map[string]any
				if err := json.Unmarshal(got, &doc); err != nil || doc["operator_after_setup"] != true {
					t.Fatalf("the operator edit was lost: %q (%v)", got, err)
				}
			}
		})
	}
}

// An earlier setup that stopped before publishing a post hash leaves a record
// whose target still holds the pre-setup state (a file, or no file at all). An
// operator edit that lands after the retry's capture and before its read-back
// must stay out of the exact restore: it is neither overwritten with the
// older snapshot nor deleted with the file the operator created.
func TestManagedBackupNoPostHashRetryKeepsEditAfterCapture(t *testing.T) {
	for _, tc := range []struct {
		name          string
		initialExists bool
		edit          bool
	}{
		{"existing target edited after the retry capture", true, true},
		{"previously absent target created after the retry capture", false, true},
		{"existing target untouched keeps the operator content", true, false},
		{"previously absent target untouched", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			dataDir := filepath.Join(root, "data")
			target := filepath.Join(root, ".cursor", "hooks.json")
			if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
				t.Fatal(err)
			}
			if tc.initialExists {
				if err := os.WriteFile(target, []byte("{\"operator\":true}\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			for i := 0; i < 2; i++ {
				// The first setup stops before its write and its post hash.
				if err := captureManagedFileBackup(dataDir, "cursor", "config", target); err != nil {
					t.Fatal(err)
				}
			}
			if tc.edit {
				if err := os.WriteFile(target, []byte("{\"operator\":true,\"later\":2}\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if err := patchCursorHooks(target, filepath.Join(root, "cursor-hook.sh"), "", false); err != nil {
				t.Fatal(err)
			}
			if err := updateManagedFileBackupPostHash(dataDir, "cursor", "config", target); err != nil {
				t.Fatal(err)
			}
			restored, err := restoreManagedFileBackupIfUnchanged(dataDir, "cursor", "config", target)
			if err != nil {
				t.Fatal(err)
			}
			got, readErr := os.ReadFile(target)
			if tc.edit {
				if readErr != nil {
					t.Fatalf("the operator file was removed (exact restore=%v): %v", restored, readErr)
				}
				var doc map[string]any
				if err := json.Unmarshal(got, &doc); err != nil {
					t.Fatal(err)
				}
				if restored || doc["later"] != float64(2) {
					t.Fatalf("the operator edit was adopted: exact restore=%v, file=%q", restored, got)
				}
				return
			}
			if tc.initialExists {
				var doc map[string]any
				if readErr != nil || json.Unmarshal(got, &doc) != nil || doc["operator"] != true {
					t.Fatalf("the operator content was lost: %q (%v)", got, readErr)
				}
			}
		})
	}
}
