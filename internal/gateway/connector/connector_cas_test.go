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
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/pelletier/go-toml/v2"
)

func TestAtomicTransformMissingTargetPreservesRacingCreate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "new-settings.json")
	hookCalls := 0
	restoreHook := setAtomicTransformBeforeCommitHookForTest(path, func(attempt int) {
		hookCalls++
		if attempt != 0 {
			return
		}
		if err := os.WriteFile(path, []byte(`{"operator":{"kept":true}}`), 0o600); err != nil {
			t.Fatalf("create racing config: %v", err)
		}
	})
	t.Cleanup(restoreHook)

	err := atomicTransformFile(path, 0o600, func(current []byte, exists bool) (atomicTransformResult, error) {
		settings := map[string]interface{}{}
		if exists {
			if err := json.Unmarshal(current, &settings); err != nil {
				return atomicTransformResult{}, err
			}
		}
		settings["defenseclaw"] = map[string]interface{}{"installed": true}
		out, err := json.Marshal(settings)
		return atomicTransformResult{Data: out}, err
	})
	if err != nil {
		t.Fatalf("atomicTransformFile: %v", err)
	}
	if hookCalls < 2 {
		t.Fatalf("before-commit hook calls = %d, want retry after racing create", hookCalls)
	}
	settings := readCASJSON(t, path)
	operator, _ := settings["operator"].(map[string]interface{})
	if operator["kept"] != true {
		t.Fatalf("racing create was overwritten: %#v", settings)
	}
	managed, _ := settings["defenseclaw"].(map[string]interface{})
	if managed["installed"] != true {
		t.Fatalf("transform was not merged after retry: %#v", settings)
	}
}

func TestAtomicTransformExistingTargetPreservesRacingReplace(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	if err := os.WriteFile(path, []byte(`{"baseline":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	hookCalls := 0
	restoreHook := setAtomicTransformBeforeCommitHookForTest(path, func(attempt int) {
		hookCalls++
		if attempt != 0 {
			return
		}
		if err := atomicWriteFile(path, []byte(`{"operator":{"kept":true}}`), 0o600); err != nil {
			t.Fatalf("publish racing replacement: %v", err)
		}
	})
	t.Cleanup(restoreHook)

	err := atomicTransformFile(path, 0o600, func(current []byte, exists bool) (atomicTransformResult, error) {
		settings := map[string]interface{}{}
		if exists {
			if err := json.Unmarshal(current, &settings); err != nil {
				return atomicTransformResult{}, err
			}
		}
		settings["defenseclaw"] = map[string]interface{}{"installed": true}
		out, err := json.Marshal(settings)
		return atomicTransformResult{Data: out}, err
	})
	if err != nil {
		t.Fatalf("atomicTransformFile: %v", err)
	}
	if hookCalls < 2 {
		t.Fatalf("before-commit hook calls = %d, want retry after racing replacement", hookCalls)
	}
	settings := readCASJSON(t, path)
	operator, _ := settings["operator"].(map[string]interface{})
	if operator["kept"] != true {
		t.Fatalf("racing replacement was overwritten: %#v", settings)
	}
	managed, _ := settings["defenseclaw"].(map[string]interface{})
	if managed["installed"] != true {
		t.Fatalf("transform was not merged after retry: %#v", settings)
	}
}

func TestAtomicTransformIntentBoundaryPreservesRacingReplace(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	if err := os.WriteFile(path, []byte(`{"baseline":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	hookCalls := 0
	var firstState atomicTransformPhaseState
	restoreHook := setAtomicTransformPhaseHookForTest(path, func(
		phase atomicTransformPhase,
		state atomicTransformPhaseState,
	) error {
		if phase != atomicTransformPhaseIntentPersisted {
			return nil
		}
		hookCalls++
		if hookCalls != 1 {
			return nil
		}
		firstState = state
		return atomicWriteFile(path, []byte(`{"operator":true}`), 0o600)
	})
	t.Cleanup(restoreHook)
	err := atomicTransformFile(path, 0o600, func(current []byte, exists bool) (atomicTransformResult, error) {
		settings := map[string]interface{}{}
		if err := json.Unmarshal(current, &settings); err != nil {
			return atomicTransformResult{}, err
		}
		settings["defenseclaw"] = true
		out, err := json.Marshal(settings)
		return atomicTransformResult{Data: out}, err
	})
	if err != nil {
		t.Fatalf("atomicTransformFile: %v", err)
	}
	if hookCalls < 2 {
		t.Fatalf("intent phase calls = %d, want retry after boundary replacement", hookCalls)
	}
	settings := readCASJSON(t, path)
	if settings["operator"] != true || settings["defenseclaw"] != true {
		t.Fatalf("boundary replacement was not preserved and merged: %#v", settings)
	}
	if err := recoverAtomicTransform(path); err != nil {
		t.Fatalf("clear completed receipt: %v", err)
	}
	assertCASArtifactsAbsent(t, firstState)
}

func TestAtomicTransformRemovePreservesRacingReplacement(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	managed := []byte(`{"defenseclaw":"owned"}`)
	operator := []byte(`{"operator":{"kept":true}}`)
	if err := os.WriteFile(path, managed, 0o600); err != nil {
		t.Fatal(err)
	}
	restoreHook := setAtomicTransformBeforeCommitHookForTest(path, func(attempt int) {
		if attempt != 0 {
			return
		}
		if err := atomicWriteFile(path, operator, 0o600); err != nil {
			t.Fatalf("publish racing replacement before removal: %v", err)
		}
	})
	t.Cleanup(restoreHook)

	err := atomicTransformFile(path, 0o600, func(current []byte, exists bool) (atomicTransformResult, error) {
		if exists && string(current) == string(managed) {
			return atomicTransformResult{Remove: true}, nil
		}
		return atomicTransformResult{Data: append([]byte(nil), current...)}, nil
	})
	if err != nil {
		t.Fatalf("atomicTransformFile: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(operator) {
		t.Fatalf("racing replacement after conditional removal = %s, want %s", got, operator)
	}
}

var errAtomicTransformSimulatedCrash = errors.New("simulated atomic-transform crash")

func TestAtomicTransformReplacementCrashRecoveryMatrix(t *testing.T) {
	tests := []struct {
		phase atomicTransformPhase
		want  string
	}{
		{phase: atomicTransformPhaseIntentPersisted, want: `{"old":true}`},
		{phase: atomicTransformPhaseDetached, want: `{"old":true}`},
		{phase: atomicTransformPhasePublished, want: `{"new":true}`},
		{phase: atomicTransformPhaseCleanupStarted, want: `{"new":true}`},
		{phase: atomicTransformPhaseCompletionValidated, want: `{"new":true}`},
		{phase: atomicTransformPhaseCompleted, want: `{"new":true}`},
	}
	for _, tc := range tests {
		t.Run(string(tc.phase), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "settings.json")
			if err := os.WriteFile(path, []byte(`{"old":true}`), 0o600); err != nil {
				t.Fatal(err)
			}
			var crashState atomicTransformPhaseState
			restoreHook := setAtomicTransformPhaseHookForTest(path, func(
				phase atomicTransformPhase,
				state atomicTransformPhaseState,
			) error {
				if phase != tc.phase {
					return nil
				}
				crashState = state
				return errAtomicTransformSimulatedCrash
			})
			err := atomicTransformFile(path, 0o600, func([]byte, bool) (atomicTransformResult, error) {
				return atomicTransformResult{Data: []byte(`{"new":true}`)}, nil
			})
			restoreHook()
			if !errors.Is(err, errAtomicTransformSimulatedCrash) {
				t.Fatalf("atomicTransformFile error = %v, want simulated crash", err)
			}
			if crashState.IntentPath == "" {
				t.Fatal("phase hook did not capture recovery state")
			}
			if err := recoverAtomicTransform(path); err != nil {
				t.Fatalf("recoverAtomicTransform: %v", err)
			}
			assertCASFileBytes(t, path, tc.want)
			assertCASArtifactsAbsent(t, crashState)
		})
	}
}

func TestAtomicTransformRemovalCrashRecoveryMatrix(t *testing.T) {
	tests := []struct {
		phase      atomicTransformPhase
		wantExists bool
	}{
		{phase: atomicTransformPhaseIntentPersisted, wantExists: true},
		{phase: atomicTransformPhaseDetached, wantExists: true},
		{phase: atomicTransformPhasePublished, wantExists: true},
		{phase: atomicTransformPhaseCleanupStarted, wantExists: false},
		{phase: atomicTransformPhaseCompletionValidated, wantExists: false},
		{phase: atomicTransformPhaseCompleted, wantExists: false},
	}
	for _, tc := range tests {
		t.Run(string(tc.phase), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "settings.json")
			if err := os.WriteFile(path, []byte(`{"old":true}`), 0o600); err != nil {
				t.Fatal(err)
			}
			var crashState atomicTransformPhaseState
			restoreHook := setAtomicTransformPhaseHookForTest(path, func(
				phase atomicTransformPhase,
				state atomicTransformPhaseState,
			) error {
				if phase != tc.phase {
					return nil
				}
				crashState = state
				return errAtomicTransformSimulatedCrash
			})
			err := atomicTransformFile(path, 0o600, func([]byte, bool) (atomicTransformResult, error) {
				return atomicTransformResult{Remove: true}, nil
			})
			restoreHook()
			if !errors.Is(err, errAtomicTransformSimulatedCrash) {
				t.Fatalf("atomicTransformFile error = %v, want simulated crash", err)
			}
			if err := recoverAtomicTransform(path); err != nil {
				t.Fatalf("recoverAtomicTransform: %v", err)
			}
			if tc.wantExists {
				assertCASFileBytes(t, path, `{"old":true}`)
			} else if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("removed target still exists or cannot be inspected: %v", err)
			}
			assertCASArtifactsAbsent(t, crashState)
		})
	}
}

func TestAtomicTransformCompleteReceiptIsRetainedUntilNextRecovery(t *testing.T) {
	for _, remove := range []bool{false, true} {
		t.Run(map[bool]string{false: "replace", true: "remove"}[remove], func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "settings.json")
			if err := os.WriteFile(path, []byte(`{"old":true}`), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := atomicTransformFile(path, 0o600, func([]byte, bool) (atomicTransformResult, error) {
				if remove {
					return atomicTransformResult{Remove: true}, nil
				}
				return atomicTransformResult{Data: []byte(`{"new":true}`)}, nil
			}); err != nil {
				t.Fatalf("atomicTransformFile: %v", err)
			}
			intent, intentPath, _, exists, err := loadAtomicTransformIntent(path)
			if err != nil {
				t.Fatalf("load complete receipt: %v", err)
			}
			if !exists || intent.Phase != atomicTransformIntentComplete {
				t.Fatalf("durable complete receipt = exists:%v phase:%q", exists, intent.Phase)
			}
			if err := recoverAtomicTransform(path); err != nil {
				t.Fatalf("reconcile complete receipt: %v", err)
			}
			if _, err := os.Lstat(intentPath); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("complete receipt survived reconciliation: %v", err)
			}
			if remove {
				if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("removed target reappeared: %v", err)
				}
			} else {
				assertCASFileBytes(t, path, `{"new":true}`)
			}
		})
	}
}

func TestAtomicTransformCompleteReceiptReconcilesReappearedOldState(t *testing.T) {
	for _, remove := range []bool{false, true} {
		t.Run(map[bool]string{false: "replace_tombstone", true: "remove_target"}[remove], func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "settings.json")
			savedOld := filepath.Join(dir, "saved-old.json")
			if err := os.WriteFile(path, []byte(`{"old":true}`), 0o600); err != nil {
				t.Fatal(err)
			}
			var completedState atomicTransformPhaseState
			restoreHook := setAtomicTransformPhaseHookForTest(path, func(
				phase atomicTransformPhase,
				state atomicTransformPhaseState,
			) error {
				switch phase {
				case atomicTransformPhaseDetached:
					return os.Link(state.Tombstone, savedOld)
				case atomicTransformPhaseCompleted:
					completedState = state
					return errAtomicTransformSimulatedCrash
				default:
					return nil
				}
			})
			err := atomicTransformFile(path, 0o600, func([]byte, bool) (atomicTransformResult, error) {
				if remove {
					return atomicTransformResult{Remove: true}, nil
				}
				return atomicTransformResult{Data: []byte(`{"new":true}`)}, nil
			})
			restoreHook()
			if !errors.Is(err, errAtomicTransformSimulatedCrash) {
				t.Fatalf("atomicTransformFile error = %v, want completed-receipt crash", err)
			}
			if remove {
				if err := os.Link(savedOld, path); err != nil {
					t.Fatalf("simulate reappeared removed target: %v", err)
				}
			} else if err := os.Link(savedOld, completedState.Tombstone); err != nil {
				t.Fatalf("simulate reappeared old tombstone: %v", err)
			}
			if err := recoverAtomicTransform(path); err != nil {
				t.Fatalf("reconcile complete receipt: %v", err)
			}
			if remove {
				assertCASFileBytes(t, path, `{"old":true}`)
			} else {
				assertCASFileBytes(t, path, `{"new":true}`)
				if _, err := os.Lstat(completedState.Tombstone); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("reappeared owned tombstone survived receipt cleanup: %v", err)
				}
			}
			if _, err := os.Lstat(completedState.IntentPath); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("complete receipt survived reconciliation: %v", err)
			}
		})
	}
}

func TestAtomicTransformCompleteReceiptCleanupCanResume(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	if err := os.WriteFile(path, []byte(`{"old":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := atomicTransformFile(path, 0o600, func([]byte, bool) (atomicTransformResult, error) {
		return atomicTransformResult{Data: []byte(`{"new":true}`)}, nil
	}); err != nil {
		t.Fatal(err)
	}
	var cleanupState atomicTransformPhaseState
	restoreHook := setAtomicTransformPhaseHookForTest(path, func(
		phase atomicTransformPhase,
		state atomicTransformPhaseState,
	) error {
		if phase != atomicTransformPhaseReceiptCleanup {
			return nil
		}
		cleanupState = state
		return errAtomicTransformSimulatedCrash
	})
	err := recoverAtomicTransform(path)
	restoreHook()
	if !errors.Is(err, errAtomicTransformSimulatedCrash) {
		t.Fatalf("receipt cleanup error = %v, want simulated crash", err)
	}
	assertCASPathExists(t, cleanupState.IntentPath)
	assertCASFileBytes(t, path, `{"new":true}`)
	if err := recoverAtomicTransform(path); err != nil {
		t.Fatalf("resume receipt cleanup: %v", err)
	}
	assertCASArtifactsAbsent(t, cleanupState)
}

func TestAtomicTransformClearedCompleteReceiptLeavesStableNoMutationGap(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	if err := os.WriteFile(path, []byte(`{"old":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := atomicTransformFile(path, 0o600, func([]byte, bool) (atomicTransformResult, error) {
		return atomicTransformResult{Data: []byte(`{"first":true}`)}, nil
	}); err != nil {
		t.Fatal(err)
	}
	_, intentPath, _, exists, err := loadAtomicTransformIntent(path)
	if err != nil || !exists {
		t.Fatalf("load first complete receipt: exists=%v err=%v", exists, err)
	}
	if err := recoverAtomicTransform(path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(intentPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("complete receipt not cleared: %v", err)
	}
	assertCASFileBytes(t, path, `{"first":true}`)
	// A process stop at this point has no detached target and therefore needs
	// no receipt. The next operation starts by rechecking recovery and creates a
	// fresh prepared intent before any detach.
	if err := atomicTransformFile(path, 0o600, func([]byte, bool) (atomicTransformResult, error) {
		return atomicTransformResult{Data: []byte(`{"second":true}`)}, nil
	}); err != nil {
		t.Fatal(err)
	}
	assertCASFileBytes(t, path, `{"second":true}`)
	intent, _, _, exists, err := loadAtomicTransformIntent(path)
	if err != nil || !exists || intent.Phase != atomicTransformIntentComplete {
		t.Fatalf("fresh complete receipt: exists=%v phase=%q err=%v", exists, intent.Phase, err)
	}
}

func TestAtomicTransformRecoveryRejectsTamperedRecordedSize(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	if err := os.WriteFile(path, []byte(`{"old":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var crashState atomicTransformPhaseState
	restoreHook := setAtomicTransformPhaseHookForTest(path, func(
		phase atomicTransformPhase,
		state atomicTransformPhaseState,
	) error {
		if phase != atomicTransformPhaseDetached {
			return nil
		}
		crashState = state
		return errAtomicTransformSimulatedCrash
	})
	err := atomicTransformFile(path, 0o600, func([]byte, bool) (atomicTransformResult, error) {
		return atomicTransformResult{Data: []byte(`{"new":true}`)}, nil
	})
	restoreHook()
	if !errors.Is(err, errAtomicTransformSimulatedCrash) {
		t.Fatalf("atomicTransformFile error = %v, want simulated crash", err)
	}
	body, err := os.ReadFile(crashState.IntentPath)
	if err != nil {
		t.Fatal(err)
	}
	var intent atomicTransformIntent
	if err := json.Unmarshal(body, &intent); err != nil {
		t.Fatal(err)
	}
	intent.OldSize++
	body, err = marshalAtomicTransformIntent(intent)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(crashState.IntentPath, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := recoverAtomicTransform(path); err == nil {
		t.Fatal("recovery accepted tombstone with size different from durable intent")
	}
	assertCASFileBytes(t, crashState.Tombstone, `{"old":true}`)
	assertCASFileBytes(t, crashState.Staged, `{"new":true}`)
	assertCASPathExists(t, crashState.IntentPath)
}

func TestAtomicTransformRecoveryRetainsPrePublishConflict(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	if err := os.WriteFile(path, []byte(`{"old":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var crashState atomicTransformPhaseState
	restoreHook := setAtomicTransformPhaseHookForTest(path, func(
		phase atomicTransformPhase,
		state atomicTransformPhaseState,
	) error {
		if phase != atomicTransformPhaseDetached {
			return nil
		}
		crashState = state
		return errAtomicTransformSimulatedCrash
	})
	err := atomicTransformFile(path, 0o600, func([]byte, bool) (atomicTransformResult, error) {
		return atomicTransformResult{Data: []byte(`{"new":true}`)}, nil
	})
	restoreHook()
	if !errors.Is(err, errAtomicTransformSimulatedCrash) {
		t.Fatalf("atomicTransformFile error = %v, want simulated crash", err)
	}
	if err := os.WriteFile(path, []byte(`{"operator":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := recoverAtomicTransform(path); err == nil {
		t.Fatal("recovery accepted target + tombstone + staged pre-publication conflict")
	}
	assertCASFileBytes(t, path, `{"operator":true}`)
	assertCASFileBytes(t, crashState.Tombstone, `{"old":true}`)
	assertCASFileBytes(t, crashState.Staged, `{"new":true}`)
	assertCASPathExists(t, crashState.IntentPath)
}

func TestAtomicTransformRecoveryRetainsForeignTargetAfterPublish(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	if err := os.WriteFile(path, []byte(`{"old":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var crashState atomicTransformPhaseState
	restoreHook := setAtomicTransformPhaseHookForTest(path, func(
		phase atomicTransformPhase,
		state atomicTransformPhaseState,
	) error {
		if phase != atomicTransformPhasePublished {
			return nil
		}
		crashState = state
		return errAtomicTransformSimulatedCrash
	})
	err := atomicTransformFile(path, 0o600, func([]byte, bool) (atomicTransformResult, error) {
		return atomicTransformResult{Data: []byte(`{"new":true}`)}, nil
	})
	restoreHook()
	if !errors.Is(err, errAtomicTransformSimulatedCrash) {
		t.Fatalf("atomicTransformFile error = %v, want simulated crash", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"operator":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := recoverAtomicTransform(path); err == nil {
		t.Fatal("recovery accepted a foreign target without a durable completion witness")
	}
	assertCASFileBytes(t, path, `{"operator":true}`)
	assertCASFileBytes(t, crashState.Tombstone, `{"old":true}`)
	assertCASPathExists(t, crashState.IntentPath)
}

func TestAtomicTransformChangedStageRestoresOldAndRetainsEvidence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	if err := os.WriteFile(path, []byte(`{"old":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var phaseState atomicTransformPhaseState
	restoreHook := setAtomicTransformPhaseHookForTest(path, func(
		phase atomicTransformPhase,
		state atomicTransformPhaseState,
	) error {
		if phase != atomicTransformPhaseDetached {
			return nil
		}
		phaseState = state
		if err := os.Remove(state.Staged); err != nil {
			return err
		}
		return os.WriteFile(state.Staged, []byte(`{"foreign":true}`), 0o600)
	})
	err := atomicTransformFile(path, 0o600, func([]byte, bool) (atomicTransformResult, error) {
		return atomicTransformResult{Data: []byte(`{"new":true}`)}, nil
	})
	restoreHook()
	if err == nil {
		t.Fatal("atomicTransformFile accepted a replaced staged artifact")
	}
	assertCASFileBytes(t, path, `{"old":true}`)
	assertCASFileBytes(t, phaseState.Staged, `{"foreign":true}`)
	assertCASPathExists(t, phaseState.IntentPath)
}

func TestAtomicTransformConcurrentCreateAfterDetachIsNeverOverwritten(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	if err := os.WriteFile(path, []byte(`{"old":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var phaseState atomicTransformPhaseState
	restoreHook := setAtomicTransformPhaseHookForTest(path, func(
		phase atomicTransformPhase,
		state atomicTransformPhaseState,
	) error {
		if phase != atomicTransformPhaseDetached {
			return nil
		}
		phaseState = state
		return os.WriteFile(path, []byte(`{"operator":true}`), 0o600)
	})
	err := atomicTransformFile(path, 0o600, func([]byte, bool) (atomicTransformResult, error) {
		return atomicTransformResult{Data: []byte(`{"new":true}`)}, nil
	})
	restoreHook()
	if err == nil {
		t.Fatal("atomicTransformFile silently accepted a concurrent post-detach create")
	}
	assertCASFileBytes(t, path, `{"operator":true}`)
	assertCASFileBytes(t, phaseState.Tombstone, `{"old":true}`)
	assertCASFileBytes(t, phaseState.Staged, `{"new":true}`)
	assertCASPathExists(t, phaseState.IntentPath)
}

func TestAtomicTransformCleanupDoesNotDeleteReplacedIntentIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	if err := os.WriteFile(path, []byte(`{"old":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var phaseState atomicTransformPhaseState
	restoreHook := setAtomicTransformPhaseHookForTest(path, func(
		phase atomicTransformPhase,
		state atomicTransformPhaseState,
	) error {
		if phase != atomicTransformPhaseCleanupStarted {
			return nil
		}
		phaseState = state
		data, err := os.ReadFile(state.IntentPath)
		if err != nil {
			return err
		}
		if err := os.Remove(state.IntentPath); err != nil {
			return err
		}
		return os.WriteFile(state.IntentPath, data, 0o600)
	})
	err := atomicTransformFile(path, 0o600, func([]byte, bool) (atomicTransformResult, error) {
		return atomicTransformResult{Data: []byte(`{"new":true}`)}, nil
	})
	restoreHook()
	if err == nil {
		t.Fatal("cleanup deleted a replacement intent with different file identity")
	}
	assertCASPathExists(t, phaseState.IntentPath)
	assertCASFileBytes(t, path, `{"new":true}`)
	if err := recoverAtomicTransform(path); err != nil {
		t.Fatalf("recover equivalent replacement intent: %v", err)
	}
	assertCASArtifactsAbsent(t, phaseState)
}

func TestAtomicTransformCompletionDoesNotOverwriteReplacedIntent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	if err := os.WriteFile(path, []byte(`{"old":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var phaseState atomicTransformPhaseState
	restoreHook := setAtomicTransformPhaseHookForTest(path, func(
		phase atomicTransformPhase,
		state atomicTransformPhaseState,
	) error {
		if phase != atomicTransformPhaseCompletionValidated {
			return nil
		}
		phaseState = state
		if err := os.Remove(state.IntentPath); err != nil {
			return err
		}
		return os.WriteFile(state.IntentPath, []byte("foreign receipt\n"), 0o600)
	})
	err := atomicTransformFile(path, 0o600, func([]byte, bool) (atomicTransformResult, error) {
		return atomicTransformResult{Data: []byte(`{"new":true}`)}, nil
	})
	restoreHook()
	if err == nil {
		t.Fatal("completion overwrote or accepted a replacement prepared intent")
	}
	assertCASFileBytes(t, path, `{"new":true}`)
	assertCASFileBytes(t, phaseState.IntentPath, "foreign receipt\n")
	assertCASPathExists(t, atomicTransformCompleteReceiptPath(phaseState.IntentPath))
}

func TestAtomicTransformWindowsCaseAliasRecoversOutstandingIntent(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows ordinal path alias behavior")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "Settings.JSON")
	alias := filepath.Join(dir, "settings.json")
	if err := os.WriteFile(path, []byte(`{"old":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(alias); err != nil {
		t.Skipf("test directory is case-sensitive: %v", err)
	}
	_, originalIntentPath, err := atomicTransformIntentPath(path)
	if err != nil {
		t.Fatal(err)
	}
	_, aliasIntentPath, err := atomicTransformIntentPath(alias)
	if err != nil {
		t.Fatal(err)
	}
	if atomicTransformPathsEqual(originalIntentPath, aliasIntentPath) {
		t.Fatal("case-only logical spellings unexpectedly produced the same receipt name")
	}

	var crashState atomicTransformPhaseState
	restoreHook := setAtomicTransformPhaseHookForTest(path, func(
		phase atomicTransformPhase,
		state atomicTransformPhaseState,
	) error {
		if phase != atomicTransformPhaseDetached {
			return nil
		}
		crashState = state
		return errAtomicTransformSimulatedCrash
	})
	err = atomicTransformFile(path, 0o600, func([]byte, bool) (atomicTransformResult, error) {
		return atomicTransformResult{Data: []byte(`{"new":true}`)}, nil
	})
	restoreHook()
	if !errors.Is(err, errAtomicTransformSimulatedCrash) {
		t.Fatalf("atomicTransformFile error = %v, want simulated crash", err)
	}
	if err := recoverAtomicTransform(alias); err != nil {
		t.Fatalf("recover case-only alias: %v", err)
	}
	assertCASFileBytes(t, alias, `{"old":true}`)
	assertCASArtifactsAbsent(t, crashState)
}

func TestAtomicTransformWindowsUppercaseReceiptRecoversThroughCaseAlias(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows receipt-name casing")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "Settings.JSON")
	alias := filepath.Join(dir, "settings.json")
	if err := os.WriteFile(path, []byte(`{"old":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(alias); err != nil {
		t.Skipf("test directory is case-sensitive: %v", err)
	}
	var crashState atomicTransformPhaseState
	restoreHook := setAtomicTransformPhaseHookForTest(path, func(
		phase atomicTransformPhase,
		state atomicTransformPhaseState,
	) error {
		if phase != atomicTransformPhaseDetached {
			return nil
		}
		crashState = state
		return errAtomicTransformSimulatedCrash
	})
	err := atomicTransformFile(path, 0o600, func([]byte, bool) (atomicTransformResult, error) {
		return atomicTransformResult{Data: []byte(`{"new":true}`)}, nil
	})
	restoreHook()
	if !errors.Is(err, errAtomicTransformSimulatedCrash) {
		t.Fatalf("atomicTransformFile error = %v, want simulated crash", err)
	}
	intermediate := filepath.Join(dir, "receipt-case-rename.tmp")
	uppercase := filepath.Join(filepath.Dir(crashState.IntentPath), asciiUpper(filepath.Base(crashState.IntentPath)))
	if err := os.Rename(crashState.IntentPath, intermediate); err != nil {
		t.Fatalf("move receipt before case-only rename: %v", err)
	}
	if err := os.Rename(intermediate, uppercase); err != nil {
		t.Fatalf("rename receipt with uppercase fixed components: %v", err)
	}
	if err := recoverAtomicTransform(alias); err != nil {
		t.Fatalf("recover uppercase receipt through case alias: %v", err)
	}
	assertCASFileBytes(t, alias, `{"old":true}`)
	assertCASArtifactsAbsent(t, crashState)
}

func TestAtomicTransformWindowsDirectoryAliasRecoversOutstandingIntent(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows directory alias identity")
	}
	root := t.TempDir()
	realDir := filepath.Join(root, "real")
	aliasDir := filepath.Join(root, "alias")
	if err := os.Mkdir(realDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realDir, aliasDir); err != nil {
		output, junctionErr := exec.Command("cmd.exe", "/d", "/c", "mklink", "/J", aliasDir, realDir).CombinedOutput()
		if junctionErr != nil {
			t.Skipf("directory symlink and junction unavailable: symlink=%v junction=%v output=%s", err, junctionErr, output)
		}
		t.Cleanup(func() { _ = os.Remove(aliasDir) })
	}
	path := filepath.Join(realDir, "Settings.JSON")
	alias := filepath.Join(aliasDir, "settings.json")
	physicalAlias, err := canonicalAtomicTransformTargetPath(alias)
	if err != nil {
		t.Fatalf("canonicalize directory alias: %v", err)
	}
	if !atomicTransformPathsEqual(filepath.Dir(physicalAlias), realDir) {
		t.Fatalf("directory alias resolved to %q, want physical parent %q", physicalAlias, realDir)
	}
	if err := os.WriteFile(path, []byte(`{"old":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var crashState atomicTransformPhaseState
	restoreHook := setAtomicTransformPhaseHookForTest(path, func(
		phase atomicTransformPhase,
		state atomicTransformPhaseState,
	) error {
		if phase != atomicTransformPhaseDetached {
			return nil
		}
		crashState = state
		return errAtomicTransformSimulatedCrash
	})
	err = atomicTransformFile(path, 0o600, func([]byte, bool) (atomicTransformResult, error) {
		return atomicTransformResult{Data: []byte(`{"new":true}`)}, nil
	})
	restoreHook()
	if !errors.Is(err, errAtomicTransformSimulatedCrash) {
		t.Fatalf("atomicTransformFile error = %v, want simulated crash", err)
	}
	if err := recoverAtomicTransform(alias); err != nil {
		t.Fatalf("recover through directory alias: %v", err)
	}
	assertCASFileBytes(t, alias, `{"old":true}`)
	assertCASArtifactsAbsent(t, crashState)
}

func TestAtomicTransformWindowsCorruptCaseAliasReceiptFailsClosed(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows ordinal path alias behavior")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "Settings.JSON")
	alias := filepath.Join(dir, "settings.json")
	if err := os.WriteFile(path, []byte(`{"old":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(alias); err != nil {
		t.Skipf("test directory is case-sensitive: %v", err)
	}
	var crashState atomicTransformPhaseState
	restoreHook := setAtomicTransformPhaseHookForTest(path, func(
		phase atomicTransformPhase,
		state atomicTransformPhaseState,
	) error {
		if phase != atomicTransformPhaseIntentPersisted {
			return nil
		}
		crashState = state
		return errAtomicTransformSimulatedCrash
	})
	err := atomicTransformFile(path, 0o600, func([]byte, bool) (atomicTransformResult, error) {
		return atomicTransformResult{Data: []byte(`{"new":true}`)}, nil
	})
	restoreHook()
	if !errors.Is(err, errAtomicTransformSimulatedCrash) {
		t.Fatalf("atomicTransformFile error = %v, want simulated crash", err)
	}
	if err := os.WriteFile(crashState.IntentPath, []byte("{\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	err = atomicTransformFile(alias, 0o600, func([]byte, bool) (atomicTransformResult, error) {
		return atomicTransformResult{Data: []byte(`{"operator-overwritten":true}`)}, nil
	})
	if err == nil {
		t.Fatal("corrupt case-alias receipt was bypassed")
	}
	assertCASFileBytes(t, alias, `{"old":true}`)
	assertCASPathExists(t, crashState.IntentPath)
	assertCASPathExists(t, crashState.Staged)
}

func TestAtomicTransformWindowsDiscoverySeparatesDistinctOwners(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows receipt discovery")
	}
	dir := t.TempDir()
	first := filepath.Join(dir, "config.toml")
	second := filepath.Join(dir, "hooks.json")
	if err := os.WriteFile(first, []byte("old = true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(second, []byte(`{"old":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := atomicTransformFile(first, 0o600, func([]byte, bool) (atomicTransformResult, error) {
		return atomicTransformResult{Data: []byte("new = true\n")}, nil
	}); err != nil {
		t.Fatal(err)
	}
	_, firstIntentPath, _, firstExists, err := loadAtomicTransformIntent(first)
	if err != nil || !firstExists {
		t.Fatalf("load first complete receipt: exists=%v err=%v", firstExists, err)
	}

	var secondState atomicTransformPhaseState
	restoreHook := setAtomicTransformPhaseHookForTest(second, func(
		phase atomicTransformPhase,
		state atomicTransformPhaseState,
	) error {
		if phase != atomicTransformPhaseIntentPersisted {
			return nil
		}
		secondState = state
		return errAtomicTransformSimulatedCrash
	})
	err = atomicTransformFile(second, 0o600, func([]byte, bool) (atomicTransformResult, error) {
		return atomicTransformResult{Data: []byte(`{"new":true}`)}, nil
	})
	restoreHook()
	if !errors.Is(err, errAtomicTransformSimulatedCrash) {
		t.Fatalf("second transform error = %v, want simulated crash", err)
	}
	assertCASPathExists(t, firstIntentPath)
	assertCASPathExists(t, atomicTransformCompleteReceiptPath(firstIntentPath))
	assertCASPathExists(t, secondState.IntentPath)

	if err := recoverAtomicTransform(first); err != nil {
		t.Fatalf("recover first owner with second receipt present: %v", err)
	}
	if _, err := os.Lstat(firstIntentPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("first receipt survived cleanup: %v", err)
	}
	assertCASPathExists(t, secondState.IntentPath)
	assertCASPathExists(t, secondState.Staged)
	assertCASFileBytes(t, first, "new = true\n")

	if err := recoverAtomicTransform(second); err != nil {
		t.Fatalf("recover second owner: %v", err)
	}
	assertCASFileBytes(t, second, `{"old":true}`)
	assertCASArtifactsAbsent(t, secondState)
}

func TestAtomicTransformWindowsOrdinalPathsKeepKelvinDistinct(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows ordinal path comparison")
	}
	dir := t.TempDir()
	kPath := filepath.Join(dir, "K.json")
	kelvinPath := filepath.Join(dir, "\u212a.json")
	if atomicTransformPathsEqual(kPath, kelvinPath) {
		t.Fatal("Windows ordinal path comparison conflated K and Kelvin sign")
	}
	_, kIntent, err := atomicTransformIntentPath(kPath)
	if err != nil {
		t.Fatal(err)
	}
	_, kelvinIntent, err := atomicTransformIntentPath(kelvinPath)
	if err != nil {
		t.Fatal(err)
	}
	if atomicTransformPathsEqual(kIntent, kelvinIntent) {
		t.Fatal("K and Kelvin-sign paths share a recovery receipt")
	}
}

func asciiUpper(value string) string {
	result := []byte(value)
	for index, char := range result {
		if char >= 'a' && char <= 'z' {
			result[index] = char - ('a' - 'A')
		}
	}
	return string(result)
}

func TestAtomicTransformRetriesTransientParseFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	if err := os.WriteFile(path, []byte(`{"partial":`), 0o600); err != nil {
		t.Fatal(err)
	}
	calls := 0
	err := atomicTransformFile(path, 0o600, func(current []byte, exists bool) (atomicTransformResult, error) {
		calls++
		var settings map[string]interface{}
		if err := json.Unmarshal(current, &settings); err != nil {
			if calls == 1 {
				if writeErr := os.WriteFile(path, []byte(`{"operator":true}`), 0o600); writeErr != nil {
					return atomicTransformResult{}, writeErr
				}
			}
			return atomicTransformResult{}, err
		}
		settings["defenseclaw"] = true
		out, err := json.Marshal(settings)
		return atomicTransformResult{Data: out}, err
	})
	if err != nil {
		t.Fatalf("atomicTransformFile: %v", err)
	}
	if calls < 2 {
		t.Fatalf("transform calls = %d, want retry after transient parse failure", calls)
	}
	settings := readCASJSON(t, path)
	if settings["operator"] != true || settings["defenseclaw"] != true {
		t.Fatalf("retry lost merged values: %#v", settings)
	}
}

func TestAtomicTransformStableParseFailureIsReturned(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	if err := os.WriteFile(path, []byte(`{"partial":`), 0o600); err != nil {
		t.Fatal(err)
	}
	calls := 0
	err := atomicTransformFile(path, 0o600, func(current []byte, exists bool) (atomicTransformResult, error) {
		calls++
		var settings map[string]interface{}
		return atomicTransformResult{}, json.Unmarshal(current, &settings)
	})
	if err == nil {
		t.Fatal("stable malformed config was silently accepted")
	}
	if calls != 1 {
		t.Fatalf("transform calls = %d, want one stable-parse attempt", calls)
	}
}

func TestAtomicTransformFinalMetadataChangeIsNotOverwritten(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	if err := os.WriteFile(path, []byte(`{"old":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) })
	transformCalls := 0
	restoreHook := setAtomicTransformBeforeCommitHookForTest(path, func(attempt int) {
		if attempt == 0 {
			if err := os.Chmod(path, 0o400); err != nil {
				t.Fatalf("inject concurrent mode change: %v", err)
			}
		}
	})
	t.Cleanup(restoreHook)
	err := atomicTransformFile(path, 0o600, func(current []byte, exists bool) (atomicTransformResult, error) {
		transformCalls++
		if transformCalls == 1 {
			return atomicTransformResult{Data: []byte(`{"new":true}`)}, nil
		}
		return atomicTransformResult{Data: append([]byte(nil), current...)}, nil
	})
	if err != nil {
		t.Fatalf("atomicTransformFile: %v", err)
	}
	if transformCalls < 2 {
		t.Fatalf("transform calls = %d, want retry after metadata change", transformCalls)
	}
	assertCASFileBytes(t, path, `{"old":true}`)
}

func TestAtomicTransformSameBytesAppliesRequestedPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	data := []byte(`{"same":true}`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) })
	if err := atomicTransformFile(path, 0o600, func(current []byte, exists bool) (atomicTransformResult, error) {
		return atomicTransformResult{Data: append([]byte(nil), current...), Perm: 0o400}, nil
	}); err != nil {
		t.Fatalf("atomicTransformFile: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o222 != 0 {
		t.Fatalf("same-byte transform did not apply read-only permission: mode=%v", info.Mode())
	}
	assertCASFileBytes(t, path, string(data))
}

func TestAtomicTransformIntentRejectsUnboundArtifactNames(t *testing.T) {
	logical, intentPath, err := atomicTransformIntentPath(filepath.Join(t.TempDir(), "settings.json"))
	if err != nil {
		t.Fatal(err)
	}
	digest := atomicTransformDigest([]byte("x"))
	protection := ""
	if runtime.GOOS == "windows" {
		protection = digest
	}
	tests := []atomicTransformIntent{
		{
			Version: atomicTransformIntentVersion, Phase: atomicTransformIntentPrepared,
			LogicalPath: logical, TargetPath: logical,
			TombstoneName: ".tmp-cas-999.previous", StagedName: ".tmp-cas-123",
			OldSHA256: digest, NewSHA256: digest, OldSize: 1, NewSize: 1,
			OldMode: uint32(0o600), NewMode: uint32(0o600),
			OldProtectionSHA256: protection, NewProtectionSHA256: protection,
		},
		{
			Version: atomicTransformIntentVersion, Phase: atomicTransformIntentPrepared,
			LogicalPath: logical, TargetPath: logical,
			TombstoneName: ".tmp-cas-not-a-remove-reservation", Remove: true,
			OldSHA256: digest, OldSize: 1, OldMode: uint32(0o600), OldProtectionSHA256: protection,
		},
		{
			Version: atomicTransformIntentVersion, Phase: atomicTransformIntentPrepared,
			LogicalPath: logical, TargetPath: logical,
			TombstoneName: ".tmp-cas-123.previous", StagedName: ".tmp-cas-123",
			OldSHA256: digest, NewSHA256: digest, OldSize: -1, NewSize: 1,
			OldMode: uint32(0o600), NewMode: uint32(0o600),
			OldProtectionSHA256: protection, NewProtectionSHA256: protection,
		},
	}
	for i, intent := range tests {
		if err := validateAtomicTransformIntent(intent, logical, intentPath); err == nil {
			t.Fatalf("malformed intent %d was accepted: %#v", i, intent)
		}
	}
}

func TestAtomicTransformSymlinkRetargetRecovery(t *testing.T) {
	for _, phase := range []atomicTransformPhase{
		atomicTransformPhaseIntentPersisted,
		atomicTransformPhaseDetached,
		atomicTransformPhasePublished,
		atomicTransformPhaseCleanupStarted,
		atomicTransformPhaseCompletionValidated,
		atomicTransformPhaseCompleted,
	} {
		t.Run(string(phase), func(t *testing.T) {
			dir := t.TempDir()
			logical := filepath.Join(dir, "settings.json")
			oldTarget := filepath.Join(dir, "old-target.json")
			newTarget := filepath.Join(dir, "new-target.json")
			if err := os.WriteFile(oldTarget, []byte(`{"old":true}`), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(newTarget, []byte(`{"operator":true}`), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(oldTarget, logical); err != nil {
				t.Skipf("file symlinks unavailable: %v", err)
			}
			var crashState atomicTransformPhaseState
			restoreHook := setAtomicTransformPhaseHookForTest(logical, func(
				gotPhase atomicTransformPhase,
				state atomicTransformPhaseState,
			) error {
				if gotPhase != phase {
					return nil
				}
				crashState = state
				return errAtomicTransformSimulatedCrash
			})
			err := atomicTransformFile(logical, 0o600, func([]byte, bool) (atomicTransformResult, error) {
				return atomicTransformResult{Data: []byte(`{"new":true}`)}, nil
			})
			restoreHook()
			if !errors.Is(err, errAtomicTransformSimulatedCrash) {
				t.Fatalf("atomicTransformFile error = %v, want simulated crash", err)
			}
			if err := os.Remove(logical); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(newTarget, logical); err != nil {
				t.Fatal(err)
			}
			recoverErr := recoverAtomicTransform(logical)
			assertCASFileBytes(t, newTarget, `{"operator":true}`)
			if phase == atomicTransformPhaseIntentPersisted {
				if recoverErr != nil {
					t.Fatalf("safe pre-detach retarget recovery: %v", recoverErr)
				}
				assertCASFileBytes(t, oldTarget, `{"old":true}`)
				assertCASArtifactsAbsent(t, crashState)
				return
			}
			if phase == atomicTransformPhasePublished || phase == atomicTransformPhaseCleanupStarted ||
				phase == atomicTransformPhaseCompletionValidated ||
				phase == atomicTransformPhaseCompleted {
				if recoverErr != nil {
					t.Fatalf("committed retarget recovery: %v", recoverErr)
				}
				assertCASFileBytes(t, oldTarget, `{"new":true}`)
				assertCASArtifactsAbsent(t, crashState)
				return
			}
			if recoverErr == nil {
				t.Fatal("post-detach retarget was not retained as ambiguous")
			}
			assertCASFileBytes(t, crashState.Tombstone, `{"old":true}`)
			assertCASFileBytes(t, crashState.Staged, `{"new":true}`)
			assertCASPathExists(t, crashState.IntentPath)
		})
	}
}

func TestAtomicTransformRemovalSymlinkRetargetRecovery(t *testing.T) {
	for _, phase := range []atomicTransformPhase{
		atomicTransformPhasePublished,
		atomicTransformPhaseCleanupStarted,
		atomicTransformPhaseCompletionValidated,
		atomicTransformPhaseCompleted,
	} {
		t.Run(string(phase), func(t *testing.T) {
			dir := t.TempDir()
			logical := filepath.Join(dir, "settings.json")
			oldTarget := filepath.Join(dir, "old-target.json")
			newTarget := filepath.Join(dir, "new-target.json")
			if err := os.WriteFile(oldTarget, []byte(`{"old":true}`), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(newTarget, []byte(`{"operator":true}`), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(oldTarget, logical); err != nil {
				t.Skipf("file symlinks unavailable: %v", err)
			}
			var crashState atomicTransformPhaseState
			restoreHook := setAtomicTransformPhaseHookForTest(logical, func(
				gotPhase atomicTransformPhase,
				state atomicTransformPhaseState,
			) error {
				if gotPhase != phase {
					return nil
				}
				crashState = state
				return errAtomicTransformSimulatedCrash
			})
			err := atomicTransformFile(logical, 0o600, func([]byte, bool) (atomicTransformResult, error) {
				return atomicTransformResult{Remove: true}, nil
			})
			restoreHook()
			if !errors.Is(err, errAtomicTransformSimulatedCrash) {
				t.Fatalf("atomicTransformFile error = %v, want simulated crash", err)
			}
			if err := os.Remove(logical); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(newTarget, logical); err != nil {
				t.Fatal(err)
			}
			recoverErr := recoverAtomicTransform(logical)
			assertCASFileBytes(t, newTarget, `{"operator":true}`)
			if phase == atomicTransformPhasePublished {
				if recoverErr == nil {
					t.Fatal("pre-cleanup removal retarget was not retained as ambiguous")
				}
				assertCASFileBytes(t, crashState.Tombstone, `{"old":true}`)
				assertCASPathExists(t, crashState.IntentPath)
				return
			}
			if recoverErr != nil {
				t.Fatalf("committed removal retarget recovery: %v", recoverErr)
			}
			if _, err := os.Lstat(oldTarget); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("committed removed target reappeared: %v", err)
			}
			assertCASArtifactsAbsent(t, crashState)
		})
	}
}

func assertCASFileBytes(t *testing.T, path, want string) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if string(got) != want {
		t.Fatalf("%s = %q, want %q", path, got, want)
	}
}

func assertCASPathExists(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("expected recovery artifact %s: %v", path, err)
	}
}

func assertCASArtifactsAbsent(t *testing.T, state atomicTransformPhaseState) {
	t.Helper()
	paths := []string{state.IntentPath, state.Tombstone, state.Staged}
	if state.IntentPath != "" {
		paths = append(paths, atomicTransformCompleteReceiptPath(state.IntentPath))
	}
	for _, path := range paths {
		if path == "" {
			continue
		}
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("recovery artifact %s was not removed: %v", path, err)
		}
	}
}

func TestCodexSetupCASPreservesConcurrentEdit(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "codex", "config.toml")
	if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte("model = \"gpt-5\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	previous := CodexConfigPathOverride
	CodexConfigPathOverride = configPath
	t.Cleanup(func() { CodexConfigPathOverride = previous })

	hookCalls := 0
	restoreHook := setAtomicTransformBeforeCompareHookForTest(configPath, func(attempt int) {
		hookCalls++
		if attempt != 0 {
			return
		}
		// Truncate in place: identity is unchanged, but exact-byte comparison
		// must reject the stale transform and merge this new table on retry.
		concurrent := "model = \"gpt-5\"\n\n[concurrent_setup]\nkept = true\n"
		if err := os.WriteFile(configPath, []byte(concurrent), 0o600); err != nil {
			t.Fatalf("inject concurrent Codex setup edit: %v", err)
		}
	})
	t.Cleanup(restoreHook)

	connector := NewCodexConnector()
	opts := SetupOpts{DataDir: dir, APIAddr: "127.0.0.1:18970"}
	if err := connector.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if hookCalls < 2 {
		t.Fatalf("CAS hook calls = %d, want retry after concurrent edit", hookCalls)
	}
	config := readCASTOML(t, configPath)
	concurrent, _ := config["concurrent_setup"].(map[string]interface{})
	if concurrent["kept"] != true {
		t.Fatalf("concurrent Codex setup edit was lost: %#v", config)
	}
	hooks, _ := config["hooks"].(map[string]interface{})
	if err := verifyTrustedCodexHookMatrix(hooks, configPath, filepath.Join(dir, "hooks")); err != nil {
		t.Fatalf("Codex hooks not installed/trusted after retry: %v", err)
	}
	if _, err := os.Stat(managedFileBackupPath(dir, connector.Name(), "config.toml")); !os.IsNotExist(err) {
		t.Fatalf("exact managed backup survived concurrent setup edit: %v", err)
	}
	if err := connector.Teardown(context.Background(), opts); err != nil {
		t.Fatalf("Teardown after concurrent setup edit: %v", err)
	}
	config = readCASTOML(t, configPath)
	concurrent, _ = config["concurrent_setup"].(map[string]interface{})
	if concurrent["kept"] != true {
		t.Fatalf("teardown erased concurrent Codex setup edit: %#v", config)
	}
}

func TestCodexTeardownCASPreservesConcurrentEdit(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "codex", "config.toml")
	if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte("model = \"gpt-5\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	previous := CodexConfigPathOverride
	CodexConfigPathOverride = configPath
	t.Cleanup(func() { CodexConfigPathOverride = previous })

	connector := NewCodexConnector()
	opts := SetupOpts{DataDir: dir, APIAddr: "127.0.0.1:18970"}
	if err := connector.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	hookCalls := 0
	restoreHook := setAtomicTransformBeforeCompareHookForTest(configPath, func(attempt int) {
		hookCalls++
		if attempt != 0 {
			return
		}
		// Replace the file atomically: both identity and bytes change after
		// teardown computed its first (exact-backup) result.
		config := readCASTOML(t, configPath)
		config["concurrent_teardown"] = map[string]interface{}{"kept": true}
		out, err := toml.Marshal(config)
		if err != nil {
			t.Fatalf("marshal concurrent Codex teardown edit: %v", err)
		}
		if err := atomicWriteFile(configPath, out, 0o600); err != nil {
			t.Fatalf("inject concurrent Codex teardown edit: %v", err)
		}
	})
	t.Cleanup(restoreHook)

	if err := connector.Teardown(context.Background(), opts); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	if hookCalls < 2 {
		t.Fatalf("CAS hook calls = %d, want retry after concurrent edit", hookCalls)
	}
	config := readCASTOML(t, configPath)
	concurrent, _ := config["concurrent_teardown"].(map[string]interface{})
	if concurrent["kept"] != true {
		t.Fatalf("concurrent Codex teardown edit was lost: %#v", config)
	}
	if hooks, ok := config["hooks"].(map[string]interface{}); ok {
		if locations := codexOwnedHookCount(t, hooks, filepath.Join(dir, "hooks")); locations != 0 {
			t.Fatalf("DefenseClaw Codex hooks survived teardown: %#v", hooks)
		}
	}
}

func TestClaudeCodeSetupCASPreservesConcurrentEdit(t *testing.T) {
	dir := t.TempDir()
	settingsPath := filepath.Join(dir, "claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(settingsPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(settingsPath, []byte(`{"theme":"dark"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	previous := ClaudeCodeSettingsPathOverride
	ClaudeCodeSettingsPathOverride = settingsPath
	t.Cleanup(func() { ClaudeCodeSettingsPathOverride = previous })

	hookCalls := 0
	restoreHook := setAtomicTransformBeforeCompareHookForTest(settingsPath, func(attempt int) {
		hookCalls++
		if hookCalls != 1 || attempt != 0 {
			return
		}
		concurrent := []byte(`{"theme":"dark","concurrentSetup":{"kept":true}}`)
		if err := os.WriteFile(settingsPath, concurrent, 0o600); err != nil {
			t.Fatalf("inject concurrent Claude setup edit: %v", err)
		}
	})
	t.Cleanup(restoreHook)

	connector := NewClaudeCodeConnector()
	opts := SetupOpts{DataDir: dir, APIAddr: "127.0.0.1:18970"}
	if err := connector.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if hookCalls < 2 {
		t.Fatalf("CAS hook calls = %d, want retry after concurrent edit", hookCalls)
	}
	settings := readCASJSON(t, settingsPath)
	concurrent, _ := settings["concurrentSetup"].(map[string]interface{})
	if concurrent["kept"] != true {
		t.Fatalf("concurrent Claude setup edit was lost: %#v", settings)
	}
	if _, ok := settings["hooks"].(map[string]interface{}); !ok {
		t.Fatalf("Claude hooks missing after CAS retry: %#v", settings)
	}
	if _, ok := settings["env"].(map[string]interface{}); !ok {
		t.Fatalf("Claude OTel env missing after CAS retry: %#v", settings)
	}
	if _, err := os.Stat(managedFileBackupPath(dir, connector.Name(), "settings.json")); !os.IsNotExist(err) {
		t.Fatalf("exact managed backup survived concurrent setup edit: %v", err)
	}
	if err := connector.Teardown(context.Background(), opts); err != nil {
		t.Fatalf("Teardown after concurrent setup edit: %v", err)
	}
	settings = readCASJSON(t, settingsPath)
	concurrent, _ = settings["concurrentSetup"].(map[string]interface{})
	if concurrent["kept"] != true {
		t.Fatalf("teardown erased concurrent Claude setup edit: %#v", settings)
	}
}

func TestClaudeCodeTeardownCASPreservesConcurrentEdit(t *testing.T) {
	dir := t.TempDir()
	settingsPath := filepath.Join(dir, "claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(settingsPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(settingsPath, []byte(`{"theme":"dark"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	previous := ClaudeCodeSettingsPathOverride
	ClaudeCodeSettingsPathOverride = settingsPath
	t.Cleanup(func() { ClaudeCodeSettingsPathOverride = previous })

	connector := NewClaudeCodeConnector()
	opts := SetupOpts{DataDir: dir, APIAddr: "127.0.0.1:18970"}
	if err := connector.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	hookCalls := 0
	restoreHook := setAtomicTransformBeforeCompareHookForTest(settingsPath, func(attempt int) {
		hookCalls++
		if attempt != 0 {
			return
		}
		settings := readCASJSON(t, settingsPath)
		settings["concurrentTeardown"] = map[string]interface{}{"kept": true}
		out, err := json.MarshalIndent(settings, "", "  ")
		if err != nil {
			t.Fatalf("marshal concurrent Claude teardown edit: %v", err)
		}
		if err := atomicWriteFile(settingsPath, out, 0o600); err != nil {
			t.Fatalf("inject concurrent Claude teardown edit: %v", err)
		}
	})
	t.Cleanup(restoreHook)

	if err := connector.Teardown(context.Background(), opts); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	if hookCalls < 2 {
		t.Fatalf("CAS hook calls = %d, want retry after concurrent edit", hookCalls)
	}
	settings := readCASJSON(t, settingsPath)
	concurrent, _ := settings["concurrentTeardown"].(map[string]interface{})
	if concurrent["kept"] != true {
		t.Fatalf("concurrent Claude teardown edit was lost: %#v", settings)
	}
	if hooks, ok := settings["hooks"].(map[string]interface{}); ok && len(hooks) != 0 {
		t.Fatalf("DefenseClaw Claude hooks survived teardown: %#v", hooks)
	}
	if env, ok := settings["env"].(map[string]interface{}); ok {
		for _, key := range claudeCodeOtelEnvKeys {
			if _, exists := env[key]; exists {
				t.Fatalf("DefenseClaw Claude env %s survived teardown: %#v", key, env)
			}
		}
	}
}

func TestCodexRepeatedSetupDoesNotBlessOperatorDriftForExactRestore(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "codex", "config.toml")
	if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte("model = \"gpt-5\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	previous := CodexConfigPathOverride
	CodexConfigPathOverride = configPath
	t.Cleanup(func() { CodexConfigPathOverride = previous })

	conn := NewCodexConnector()
	opts := SetupOpts{DataDir: dir, APIAddr: "127.0.0.1:18970"}
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("first Setup: %v", err)
	}
	config := readCASTOML(t, configPath)
	config["operator_after_setup"] = map[string]interface{}{"kept": true}
	out, err := toml.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := atomicWriteFile(configPath, out, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("second Setup: %v", err)
	}
	if _, err := os.Stat(managedFileBackupPath(dir, conn.Name(), "config.toml")); !os.IsNotExist(err) {
		t.Fatalf("repeated setup retained unsafe exact backup: %v", err)
	}
	if err := conn.Teardown(context.Background(), opts); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	config = readCASTOML(t, configPath)
	operator, _ := config["operator_after_setup"].(map[string]interface{})
	if operator["kept"] != true {
		t.Fatalf("teardown erased operator drift: %#v", config)
	}
}

func TestClaudeRepeatedSetupDoesNotBlessOperatorDriftForExactRestore(t *testing.T) {
	dir := t.TempDir()
	settingsPath := filepath.Join(dir, "claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(settingsPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(settingsPath, []byte(`{"theme":"dark"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	previous := ClaudeCodeSettingsPathOverride
	ClaudeCodeSettingsPathOverride = settingsPath
	t.Cleanup(func() { ClaudeCodeSettingsPathOverride = previous })

	conn := NewClaudeCodeConnector()
	opts := SetupOpts{DataDir: dir, APIAddr: "127.0.0.1:18970"}
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("first Setup: %v", err)
	}
	settings := readCASJSON(t, settingsPath)
	settings["operatorAfterSetup"] = map[string]interface{}{"kept": true}
	out, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := atomicWriteFile(settingsPath, out, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("second Setup: %v", err)
	}
	if _, err := os.Stat(managedFileBackupPath(dir, conn.Name(), "settings.json")); !os.IsNotExist(err) {
		t.Fatalf("repeated setup retained unsafe exact backup: %v", err)
	}
	if err := conn.Teardown(context.Background(), opts); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	settings = readCASJSON(t, settingsPath)
	operator, _ := settings["operatorAfterSetup"].(map[string]interface{})
	if operator["kept"] != true {
		t.Fatalf("teardown erased operator drift: %#v", settings)
	}
}

func readCASTOML(t *testing.T, path string) map[string]interface{} {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read TOML %s: %v", path, err)
	}
	result := map[string]interface{}{}
	if err := toml.Unmarshal(data, &result); err != nil {
		t.Fatalf("parse TOML %s: %v\n%s", path, err, data)
	}
	return result
}

func readCASJSON(t *testing.T, path string) map[string]interface{} {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read JSON %s: %v", path, err)
	}
	result := map[string]interface{}{}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("parse JSON %s: %v\n%s", path, err, data)
	}
	return result
}

func codexOwnedHookCount(t *testing.T, hooks map[string]interface{}, hooksDir string) int {
	t.Helper()
	count := 0
	for eventType, groups := range hooks {
		if eventType == "state" {
			continue
		}
		locations, err := ownedCodexHookLocations(runtime.GOOS, codexHookEventKeyLabel(eventType), groups, hooksDir)
		if err != nil {
			t.Fatalf("discover owned Codex hooks for %s: %v", eventType, err)
		}
		count += len(locations)
	}
	return count
}
