// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// An editor saves a config by writing a new file and renaming it over the old
// one. When that lands while a transform has only an allocation or a staging
// receipt, the transform has not touched the config yet, so its own leftovers
// must be removable and the bytes the editor saved must stay.

func atomicTransformV2OperatorSave(t *testing.T, path string, data []byte) {
	t.Helper()
	temp := filepath.Join(filepath.Dir(path), "operator-save.tmp")
	if err := os.WriteFile(temp, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(temp, path); err != nil {
		t.Fatal(err)
	}
}

func atomicTransformV2Leftovers(t *testing.T, path, stateDir string) []string {
	t.Helper()
	var left []string
	for _, dir := range []struct{ path, prefix string }{
		{filepath.Dir(path), atomicTransformV2NamePrefix},
		{stateDir, atomicTransformV2ReceiptPrefix},
	} {
		entries, err := os.ReadDir(dir.path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), dir.prefix) {
				left = append(left, filepath.Join(dir.path, entry.Name()))
			}
		}
	}
	return left
}

func atomicTransformV2WriteOld(t *testing.T) (path, stateDir string) {
	t.Helper()
	root := t.TempDir()
	path, stateDir = filepath.Join(root, "config", "settings.json"), filepath.Join(root, "state")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := safefile.WritePrivate(path, []byte("old")); err != nil {
		t.Fatal(err)
	}
	return path, stateDir
}

func atomicTransformV2AppendDC(current []byte, _ bool) (atomicTransformResult, error) {
	return atomicTransformResult{Data: append(append([]byte(nil), current...), "+dc"...)}, nil
}

func atomicTransformV2HardExitAt(t *testing.T, path, stateDir string, phase atomicTransformPhase) {
	t.Helper()
	crash := exec.Command(os.Args[0], "-test.run=^TestAtomicTransformV2HardExitHelper$")
	crash.Env = atomicTransformV2HardExitEnv(
		"DEFENSECLAW_V2_HARD_EXIT_HELPER=1", "DEFENSECLAW_V2_HARD_EXIT_PATH="+path,
		"DEFENSECLAW_V2_HARD_EXIT_STATE="+stateDir, "DEFENSECLAW_V2_HARD_EXIT_OPERATION=update",
		"DEFENSECLAW_V2_HARD_EXIT_PHASE="+string(phase), "DEFENSECLAW_V2_HARD_EXIT_OCCURRENCE=1",
	)
	output, err := crash.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != atomicTransformV2HardExitCode {
		t.Fatalf("fixture crash: %v\n%s", err, output)
	}
}

func TestAtomicTransformV2OperatorSaveBeforeStagingLeavesNoRecoveryAndKeepsTheSave(t *testing.T) {
	for _, phase := range []atomicTransformPhase{
		atomicTransformPhaseAllocationPersisted,
		atomicTransformPhaseStagingLocated,
	} {
		t.Run(string(phase), func(t *testing.T) {
			path, stateDir := atomicTransformV2WriteOld(t)
			canonical, err := canonicalAtomicTransformTargetPath(path)
			if err != nil {
				t.Fatal(err)
			}
			stop := errors.New("stop fixture after the operator save")
			saved := false
			restore := setAtomicTransformPhaseHookForTest(canonical, func(
				got atomicTransformPhase, state atomicTransformPhaseState,
			) error {
				if got != phase || saved {
					return nil
				}
				saved = true
				atomicTransformV2OperatorSave(t, state.TargetPath, []byte("operator save"))
				return stop
			})
			defer restore()
			err = atomicTransformFileWithStateDir(path, stateDir, 0o600,
				func([]byte, bool) (atomicTransformResult, error) {
					return atomicTransformResult{Data: []byte("new")}, nil
				})
			if !saved {
				t.Fatal("operator save seam was not reached")
			}
			if !errors.Is(err, stop) {
				t.Fatalf("expected the injected stop: %v", err)
			}
			if content, readErr := os.ReadFile(path); readErr != nil || !bytes.Equal(content, []byte("operator save")) {
				t.Fatalf("operator save was changed: %q %v", content, readErr)
			}
			if left := atomicTransformV2Leftovers(t, path, stateDir); len(left) != 0 {
				t.Fatalf("recovery files remain after the transform stopped (%v): %v", err, left)
			}
			// The next change on the same config is not refused.
			if err := atomicTransformFileWithStateDir(path, stateDir, 0o600, atomicTransformV2AppendDC); err != nil {
				t.Fatalf("a later change was refused: %v", err)
			}
			if content, readErr := os.ReadFile(path); readErr != nil || !bytes.Equal(content, []byte("operator save+dc")) {
				t.Fatalf("later change did not build on the operator save: %q %v", content, readErr)
			}
		})
	}
}

func TestAtomicTransformV2OperatorSaveDuringStagingIsTransformedOnRetry(t *testing.T) {
	path, stateDir := atomicTransformV2WriteOld(t)
	canonical, err := canonicalAtomicTransformTargetPath(path)
	if err != nil {
		t.Fatal(err)
	}
	saved := false
	restore := setAtomicTransformPhaseHookForTest(canonical, func(
		phase atomicTransformPhase, state atomicTransformPhaseState,
	) error {
		if phase != atomicTransformPhasePayloadMarkerBootstrap || saved {
			return nil
		}
		saved = true
		atomicTransformV2OperatorSave(t, state.TargetPath, []byte("operator save"))
		return nil
	})
	defer restore()
	if err := atomicTransformFileWithStateDir(path, stateDir, 0o600, atomicTransformV2AppendDC); err != nil {
		t.Fatalf("a save during staging aborted the change: %v", err)
	}
	if !saved {
		t.Fatal("operator save seam was not reached")
	}
	if content, readErr := os.ReadFile(path); readErr != nil || !bytes.Equal(content, []byte("operator save+dc")) {
		t.Fatalf("operator save was lost or not built on: %q %v", content, readErr)
	}
	if left := atomicTransformV2Leftovers(t, path, stateDir); len(left) != 0 {
		t.Fatalf("recovery files remain after the change: %v", left)
	}
}

func TestAtomicTransformV2CrashedAllocationRecoversAfterAnOperatorSave(t *testing.T) {
	path, stateDir := atomicTransformV2WriteOld(t)
	atomicTransformV2HardExitAt(t, path, stateDir, atomicTransformPhaseAllocationPersisted)
	if len(atomicTransformV2Leftovers(t, path, stateDir)) == 0 {
		t.Fatal("the crash left no allocation receipt to recover")
	}
	atomicTransformV2OperatorSave(t, path, []byte("operator save"))
	if err := recoverAtomicTransformV2(path, stateDir); err != nil {
		t.Fatalf("recovery was refused after an operator save: %v", err)
	}
	if content, readErr := os.ReadFile(path); readErr != nil || !bytes.Equal(content, []byte("operator save")) {
		t.Fatalf("operator save was changed: %q %v", content, readErr)
	}
	if left := atomicTransformV2Leftovers(t, path, stateDir); len(left) != 0 {
		t.Fatalf("recovery files remain: %v", left)
	}
}

// A staged extended attribute can only be proved to be the transaction own copy
// against the prior config. With that file replaced or removed the stage is
// kept, never deleted, but the receipt is retired so the recovery finishes, the
// saved bytes stay and a later change to the config is not refused.
func TestAtomicTransformV2StagedEAIsKeptAndRecoveryFinishesWhenThePriorConfigIsGone(t *testing.T) {
	for _, mutation := range []string{"save", "remove"} {
		t.Run(mutation, func(t *testing.T) {
			path, stateDir := atomicTransformV2WriteOld(t)
			atomicTransformEARegressionSet(t, path, atomicTransformEARegressionPayload("CONNECTOR_EA_FIXTURE", "ordinary metadata"))
			atomicTransformV2HardExitAt(t, path, stateDir, atomicTransformPhaseStageMarkerBootstrap)
			if mutation == "save" {
				atomicTransformV2OperatorSave(t, path, []byte("operator save"))
			} else if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := recoverAtomicTransformV2(path, stateDir); err != nil {
				t.Fatalf("recovery could not finish with the prior config gone: %v", err)
			}
			content, readErr := os.ReadFile(path)
			if mutation == "save" && (readErr != nil || !bytes.Equal(content, []byte("operator save"))) {
				t.Fatalf("operator save was changed: %q %v", content, readErr)
			}
			if mutation == "remove" && !errors.Is(readErr, os.ErrNotExist) {
				t.Fatalf("recovery recreated the removed config: %q %v", content, readErr)
			}
			left := atomicTransformV2Leftovers(t, path, stateDir)
			if len(left) != 1 || !strings.HasPrefix(filepath.Base(left[0]), atomicTransformV2NamePrefix) {
				t.Fatalf("expected only the EA-bearing stage to be kept, no receipt: %v", left)
			}
			if err := atomicTransformFileWithStateDir(path, stateDir, 0o600, atomicTransformV2AppendDC); err != nil {
				t.Fatalf("a later change was refused: %v", err)
			}
		})
	}
}

// A save that lands after the transaction is prepared and before it begins to
// publish is the operator own: it stays as saved, the transaction is abandoned
// and the change is built on the saved bytes (GAP-0961). A deletion at the same
// point stays fail-closed, as before.
func TestAtomicTransformV2PreparedOperatorSaveBeforeCommitIsKeptAndRetried(t *testing.T) {
	for _, mutation := range []string{"edit", "recreate"} {
		t.Run(mutation, func(t *testing.T) {
			path, stateDir := atomicTransformV2WriteOld(t)
			canonical, err := canonicalAtomicTransformTargetPath(path)
			if err != nil {
				t.Fatal(err)
			}
			saved := false
			restore := setAtomicTransformPhaseHookForTest(canonical, func(
				phase atomicTransformPhase, state atomicTransformPhaseState,
			) error {
				if phase != atomicTransformPhaseIntentPersisted || saved {
					return nil
				}
				saved = true
				if mutation == "recreate" {
					if err := os.Remove(state.TargetPath); err != nil {
						return err
					}
				}
				return os.WriteFile(state.TargetPath, []byte("operator-"+mutation), 0o600)
			})
			defer restore()
			if err := atomicTransformFileWithStateDir(path, stateDir, 0o600, atomicTransformV2AppendDC); err != nil {
				t.Fatalf("a save before the commit aborted the change: %v", err)
			}
			if !saved {
				t.Fatal("operator save seam was not reached")
			}
			if content, readErr := os.ReadFile(path); readErr != nil || !bytes.Equal(content, []byte("operator-"+mutation+"+dc")) {
				t.Fatalf("operator save was lost or not built on: %q %v", content, readErr)
			}
			if left := atomicTransformV2Leftovers(t, path, stateDir); len(left) != 0 {
				t.Fatalf("recovery files remain after the change: %v", left)
			}
		})
	}
}
