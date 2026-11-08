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
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// A first setup records its output only for the bytes its own writers
// committed. An edit by someone else at any point between the capture and the
// read-back stays out of the exact restore, whether the patch merged it or the
// edit landed after the patch.
func TestManagedBackupFirstSetupNeverAdoptsOutsideEdit(t *testing.T) {
	patches := map[string]func(t *testing.T, root, target string){
		"plain writer": func(t *testing.T, root, target string) {
			t.Helper()
			if err := patchCursorHooks(target, filepath.Join(root, "cursor-hook.sh"), "", false); err != nil {
				t.Fatal(err)
			}
		},
		"locked writer": func(t *testing.T, root, target string) {
			t.Helper()
			if err := patchCursorHooksLocked(target, filepath.Join(root, "state"), filepath.Join(root, "cursor-hook.sh"), "", false); err != nil {
				t.Fatal(err)
			}
		},
	}
	for patchName, patch := range patches {
		for _, tc := range []struct {
			name     string
			editWhen string
			pristine string
		}{
			{"edit between capture and patch", "before-patch", "{\"operator\":true}\n"},
			{"edit between patch and post hash", "after-patch", "{\"operator\":true}\n"},
			{"file created after capture", "before-patch", ""},
			{"untouched file restores exactly", "", "{\"operator\":true}\n"},
			{"untouched absent file is removed", "", ""},
		} {
			t.Run(patchName+"/"+tc.name, func(t *testing.T) {
				root := t.TempDir()
				dataDir := filepath.Join(root, "data")
				target := filepath.Join(root, ".cursor", "hooks.json")
				if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
					t.Fatal(err)
				}
				if tc.pristine != "" {
					if err := os.WriteFile(target, []byte(tc.pristine), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				if err := captureManagedFileBackup(dataDir, "cursor", "config", target); err != nil {
					t.Fatal(err)
				}
				if tc.editWhen == "before-patch" {
					if err := os.WriteFile(target, []byte("{\"operator\":true,\"later\":2}\n"), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				patch(t, root, target)
				if tc.editWhen == "after-patch" {
					raw, err := os.ReadFile(target)
					if err != nil {
						t.Fatal(err)
					}
					var doc map[string]any
					if err := json.Unmarshal(raw, &doc); err != nil {
						t.Fatal(err)
					}
					doc["later"] = float64(2)
					edited, err := json.MarshalIndent(doc, "", "  ")
					if err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(target, append(edited, 0x0a), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				if err := updateManagedFileBackupPostHash(dataDir, "cursor", "config", target); err != nil {
					t.Fatal(err)
				}
				exact, err := restoreManagedFileBackupIfUnchanged(dataDir, "cursor", "config", target)
				if err != nil {
					t.Fatal(err)
				}
				got, readErr := os.ReadFile(target)
				if tc.editWhen == "" {
					if !exact {
						t.Fatalf("untouched first setup did not restore exactly (file %q)", got)
					}
					if tc.pristine == "" {
						if !os.IsNotExist(readErr) {
							t.Fatalf("file the setup created is still there: %q", got)
						}
						return
					}
					if readErr != nil || string(got) != tc.pristine {
						t.Fatalf("restored file = %q (%v), want %q", got, readErr, tc.pristine)
					}
					return
				}
				if readErr != nil {
					t.Fatal(readErr)
				}
				var doc map[string]any
				if err := json.Unmarshal(got, &doc); err != nil {
					t.Fatal(err)
				}
				if exact || doc["later"] != float64(2) {
					t.Fatalf("outside edit was lost: exact restore=%v file=%q", exact, got)
				}
			})
		}
	}
}
