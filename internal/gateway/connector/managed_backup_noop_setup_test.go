// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A setup that finds the target as the last setup left it, and changes
// nothing, must not rewrite the backup record: not its bytes and not its
// modification time. The edit protection stays: the same setup over an edited
// target still retires the exact restore.
func TestManagedBackupNoOpRepeatSetupLeavesRecordUntouched(t *testing.T) {
	for _, tc := range []struct {
		name   string
		edited bool
	}{
		{"unchanged target keeps the record file untouched and the exact restore", false},
		{"edited target is retired to owned-entry cleanup", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			dataDir := filepath.Join(root, "data")
			target := filepath.Join(root, ".cursor", "hooks.json")
			hook := filepath.Join(root, "cursor-hook.sh")
			pristine := "{\"operator\":true}\n"
			if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(target, []byte(pristine), 0o600); err != nil {
				t.Fatal(err)
			}
			setup := func() {
				t.Helper()
				if err := captureManagedFileBackup(dataDir, "cursor", "config", target); err != nil {
					t.Fatal(err)
				}
				if err := patchCursorHooks(target, hook, "", false); err != nil {
					t.Fatal(err)
				}
				if err := updateManagedFileBackupPostHash(dataDir, "cursor", "config", target); err != nil {
					t.Fatal(err)
				}
			}
			setup()

			record := managedFileBackupPath(dataDir, "cursor", "config")
			old := time.Now().Add(-time.Hour)
			if err := os.Chtimes(record, old, old); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(record)
			if err != nil {
				t.Fatal(err)
			}
			beforeInfo, err := os.Stat(record)
			if err != nil {
				t.Fatal(err)
			}
			if tc.edited {
				doc, err := os.ReadFile(target)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(target, append(doc, []byte(" ")...), 0o600); err != nil {
					t.Fatal(err)
				}
			}

			setup()

			after, err := os.ReadFile(record)
			if err != nil {
				t.Fatal(err)
			}
			afterInfo, err := os.Stat(record)
			if err != nil {
				t.Fatal(err)
			}
			exact, err := restoreManagedFileBackupIfUnchanged(dataDir, "cursor", "config", target)
			if err != nil {
				t.Fatal(err)
			}
			if tc.edited {
				if exact || bytes.Equal(before, after) {
					t.Fatalf("edit adopted: exact restore=%v, record unchanged=%v", exact, bytes.Equal(before, after))
				}
				return
			}
			if !bytes.Equal(before, after) || !afterInfo.ModTime().Equal(beforeInfo.ModTime()) {
				t.Fatalf("no-op setup rewrote the record: mtime %v -> %v", beforeInfo.ModTime(), afterInfo.ModTime())
			}
			got, err := os.ReadFile(target)
			if err != nil || !exact || string(got) != pristine {
				t.Fatalf("exact restore = %v, file %q (%v), want %q", exact, got, err, pristine)
			}
		})
	}
}

// A connector that publishes its own hash closes the span its capture opened,
// for a first setup and for a later one.
func TestManagedBackupExplicitValueClosesCaptureSpan(t *testing.T) {
	root := t.TempDir()
	dataDir := filepath.Join(root, "data")
	target := filepath.Join(root, "config.toml")
	if err := os.WriteFile(target, []byte("a = 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, round := range []string{"first setup", "later setup"} {
		if err := captureManagedFileBackup(dataDir, "codex", "config.toml", target); err != nil {
			t.Fatalf("%s: %v", round, err)
		}
		if err := updateManagedFileBackupPostHashValue(dataDir, "codex", "config.toml", target, sha256Hex([]byte("a = 1\n"))); err != nil {
			t.Fatalf("%s: %v", round, err)
		}
		if _, open := endManagedSetupSpan(target); open {
			t.Fatalf("%s: span still open after the explicit hash was published", round)
		}
	}
}
