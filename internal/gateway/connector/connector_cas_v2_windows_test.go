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

//go:build windows

package connector

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAtomicTransformV2CreateUpdateRemove(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "config", "settings.json")
	stateDir := filepath.Join(root, "protected-state")

	write := func(want string) {
		t.Helper()
		if err := atomicTransformFileWithStateDir(
			path, stateDir, 0o600,
			func(_ []byte, _ bool) (atomicTransformResult, error) {
				return atomicTransformResult{Data: []byte(want)}, nil
			},
		); err != nil {
			t.Fatalf("write %q through V2: %v", want, err)
		}
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read V2 result: %v", err)
		}
		if string(got) != want {
			t.Fatalf("V2 result = %q, want %q", got, want)
		}
	}

	write(`{"version":1}`)
	write(`{"version":2}`)
	if err := atomicTransformFileWithStateDir(
		path, stateDir, 0o600,
		func(_ []byte, _ bool) (atomicTransformResult, error) {
			return atomicTransformResult{Remove: true}, nil
		},
	); err != nil {
		t.Fatalf("remove through V2: %v", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("removed V2 target still exists: %v", err)
	}

	for _, directory := range []string{stateDir, filepath.Dir(path)} {
		entries, err := os.ReadDir(directory)
		if err != nil {
			t.Fatalf("enumerate V2 artifact directory %s: %v", directory, err)
		}
		for _, entry := range entries {
			if strings.HasPrefix(strings.ToLower(entry.Name()), atomicTransformV2ReceiptPrefix) ||
				strings.HasPrefix(strings.ToLower(entry.Name()), atomicTransformV2NamePrefix) {
				t.Fatalf("V2 lifecycle left transaction artifact %s in %s", entry.Name(), directory)
			}
		}
	}
}

func TestAtomicTransformV2MigrationDiscoveryAllowsMissingTargetParent(t *testing.T) {
	for _, malformedStableReceipt := range []bool{false, true} {
		name := "empty-stable-state"
		if malformedStableReceipt {
			name = "stable-receipt-still-scanned"
		}
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, "missing-target-parent", "settings.json")
			stateDir, err := prepareAtomicTransformStateDir(filepath.Join(root, "protected-state"))
			if err != nil {
				t.Fatal(err)
			}
			if malformedStableReceipt {
				_, intentPath, pathErr := atomicTransformIntentPathInStateDir(path, stateDir)
				if pathErr != nil {
					t.Fatal(pathErr)
				}
				if err := os.WriteFile(intentPath, []byte("{malformed"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			_, exists, err := loadAtomicTransformV1ForV2Migration(path, stateDir, "")
			if malformedStableReceipt {
				if err == nil {
					t.Fatalf("missing target parent bypassed malformed stable V1 receipt: exists=%t", exists)
				}
				return
			}
			if err != nil || exists {
				t.Fatalf("missing target parent migration discovery = exists:%t err:%v; want empty", exists, err)
			}
		})
	}
}

func TestAtomicTransformV2PrePublicationTombDeletionFailsClosed(t *testing.T) {
	for _, test := range []struct {
		name       string
		result     atomicTransformResult
		want       string
		wantExists bool
	}{
		{name: "replace", result: atomicTransformResult{Data: []byte(`{"version":2}`)}, want: `{"version":2}`, wantExists: true},
		{name: "remove", result: atomicTransformResult{Remove: true}, wantExists: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, "config", "settings.json")
			stateDir := filepath.Join(root, "protected-state")
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(`{"version":1}`), 0o600); err != nil {
				t.Fatal(err)
			}
			crash := errors.New("simulated exit after raw replacement and operator tomb deletion")
			hookCalls := 0
			restore := setAtomicTransformPhaseHookForTest(path, func(
				phase atomicTransformPhase, state atomicTransformPhaseState,
			) error {
				if phase != atomicTransformPhasePublished {
					return nil
				}
				hookCalls++
				if err := os.Remove(state.Tombstone); err != nil {
					return err
				}
				return crash
			})
			t.Cleanup(restore)

			err := atomicTransformFileWithStateDir(
				path, stateDir, 0o600,
				func(_ []byte, _ bool) (atomicTransformResult, error) { return test.result, nil },
			)
			if !errors.Is(err, crash) {
				t.Fatalf("V2 transform error = %v, want simulated exit", err)
			}
			if hookCalls != 1 {
				t.Fatalf("published hook calls = %d, want 1", hookCalls)
			}
			data, readErr := os.ReadFile(path)
			if test.wantExists {
				if readErr != nil || string(data) != test.want {
					t.Fatalf("pre-P live result = %q, %v; want %q", data, readErr, test.want)
				}
			} else if !errors.Is(readErr, os.ErrNotExist) {
				t.Fatalf("pre-P removal left live target: %v", readErr)
			}
			loaded, loadErr := loadAtomicTransformV2(path, stateDir)
			if loadErr != nil || !loaded.exists || loaded.terminal.exists {
				t.Fatalf("pre-P conflict receipt state: exists=%t terminal=%t err=%v", loaded.exists, loaded.terminal.exists, loadErr)
			}
			transactionID := loaded.receipt.TransactionID
			for attempt := 0; attempt < 2; attempt++ {
				if recoverErr := recoverAtomicTransformV2(path, stateDir); recoverErr == nil {
					t.Fatalf("recovery %d accepted deletion of the Old publication witness", attempt+1)
				}
				after, afterErr := loadAtomicTransformV2(path, stateDir)
				if afterErr != nil || !after.exists || after.terminal.exists || after.receipt.TransactionID != transactionID {
					t.Fatalf("recovery %d changed retained receipt: exists=%t terminal=%t transaction=%q/%q err=%v",
						attempt+1, after.exists, after.terminal.exists, after.receipt.TransactionID, transactionID, afterErr)
				}
				afterData, afterReadErr := os.ReadFile(path)
				if test.wantExists {
					if afterReadErr != nil || string(afterData) != test.want {
						t.Fatalf("recovery %d changed pre-P live result = %q, %v; want %q", attempt+1, afterData, afterReadErr, test.want)
					}
				} else if !errors.Is(afterReadErr, os.ErrNotExist) {
					t.Fatalf("recovery %d recreated pre-P removal: %v", attempt+1, afterReadErr)
				}
			}
		})
	}
}

func TestAtomicTransformV2TerminalRejectsConcurrentLegacyNamespaceWithoutLiveMutation(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "config", "settings.json")
	stateDir, err := prepareAtomicTransformStateDir(filepath.Join(root, "protected-state"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"version":1}`), 0o600); err != nil {
		t.Fatal(err)
	}

	crash := errors.New("simulated exit after V2 terminal receipt")
	var terminalSnapshot atomicFileSnapshot
	var legacyIntentPath string
	restore := setAtomicTransformPhaseHookForTest(path, func(
		phase atomicTransformPhase, _ atomicTransformPhaseState,
	) error {
		if phase != atomicTransformPhaseTerminalWitnessed || legacyIntentPath != "" {
			return nil
		}
		terminalSnapshot, err = readAtomicFileSnapshot(path)
		if err != nil {
			return err
		}
		stagePath, stageState, stageErr := stageAtomicTransformFile(
			terminalSnapshot.writePath, []byte(`{"legacy":true}`), 0o600,
		)
		if stageErr != nil {
			return stageErr
		}
		intent, intentPath, intentErr := prepareAtomicTransformIntent(
			path, stateDir, terminalSnapshot, stagePath, stageState, false,
		)
		if intentErr != nil {
			return intentErr
		}
		if _, persistErr := persistAtomicTransformIntent(intentPath, intent); persistErr != nil {
			return persistErr
		}
		legacyIntentPath = intentPath
		return crash
	})
	t.Cleanup(restore)

	err = atomicTransformFileWithStateDir(
		path, stateDir, 0o600,
		func(_ []byte, _ bool) (atomicTransformResult, error) {
			return atomicTransformResult{Data: []byte(`{"version":2}`)}, nil
		},
	)
	if err == nil || !strings.Contains(err.Error(), "both V1 and V2") {
		t.Fatalf("dual-namespace transform error = %v, want fail-closed V1/V2 conflict", err)
	}
	if legacyIntentPath == "" {
		t.Fatal("test did not publish the concurrent V1 prepared receipt")
	}
	matches, compareErr := atomicFileSnapshotStillMatches(path, terminalSnapshot)
	if compareErr != nil || !matches {
		t.Fatalf("dual-namespace detection mutated V2 terminal live state: matches=%t err=%v", matches, compareErr)
	}
	if recoverErr := recoverAtomicTransformV2(path, stateDir); recoverErr == nil ||
		!strings.Contains(recoverErr.Error(), "both V1 and V2") {
		t.Fatalf("repeat dual-namespace recovery error = %v, want fail closed", recoverErr)
	}
	matches, compareErr = atomicFileSnapshotStillMatches(path, terminalSnapshot)
	if compareErr != nil || !matches {
		t.Fatalf("repeat dual-namespace recovery mutated live state: matches=%t err=%v", matches, compareErr)
	}
}
