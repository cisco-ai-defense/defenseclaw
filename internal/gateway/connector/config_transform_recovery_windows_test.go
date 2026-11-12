// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A rollback that an editor save interrupted can leave recovery files, and the
// installer then refuses every later rollback. The command named in that
// refusal (RecoverRetainedConfigTransforms) finishes them, keeps the file the
// editor saved, and the next rollback completes.
func TestRecoverRetainedConfigTransformsUnblocksTheNextRollback(t *testing.T) {
	captureRollbackNotes(t)
	dataDir, path := devinSetUp(t, "config.json", rollbackPristineVariants[0].bytes)
	resaveWithOperatorKey(t, path)
	atomicTransformV2HardExitAt(t, path, dataDir, atomicTransformPhaseAllocationPersisted)
	if len(atomicTransformV2Leftovers(t, path, dataDir)) == 0 {
		t.Fatal("the interrupted change left no recovery files")
	}
	editorAtomicSave(t, path)

	recovered, err := RecoverRetainedConfigTransforms(dataDir)
	if err != nil || recovered != 1 {
		t.Fatalf("RecoverRetainedConfigTransforms = %d, %v; want 1 finished change", recovered, err)
	}
	if left := atomicTransformV2Leftovers(t, path, dataDir); len(left) != 0 {
		t.Fatalf("recovery files remain after the command: %v", left)
	}
	saved, err := os.ReadFile(path)
	if err != nil || !bytes.Contains(saved, []byte("operator_saved_during_rollback")) {
		t.Fatalf("the saved file was not kept: %q %v", saved, err)
	}
	if again, err := RecoverRetainedConfigTransforms(dataDir); err != nil || again != 0 {
		t.Fatalf("a second run = %d, %v; want nothing left to finish", again, err)
	}

	n, err := convertDevinHooksFile(path, dataDir, "devin", devinRollbackPairs(), true, nil)
	if err != nil || n != 3 {
		t.Fatalf("rollback conversion after the command = %d, %v; want 3 handlers", n, err)
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Contains(got, []byte("operator_saved_during_rollback")) || devinHandlersInEarlierForm(t, path) != 3 {
		t.Fatalf("the rollback did not build on the saved file: %q %v", got, err)
	}
}

func TestRecoverRetainedConfigTransformsHasNothingToDoOnACleanFolder(t *testing.T) {
	dataDir, _ := devinSetUp(t, "config.json", rollbackPristineVariants[0].bytes)
	if recovered, err := RecoverRetainedConfigTransforms(dataDir); err != nil || recovered != 0 {
		t.Fatalf("RecoverRetainedConfigTransforms = %d, %v; want 0", recovered, err)
	}
	if recovered, err := RecoverRetainedConfigTransforms(dataDir + "-missing"); err != nil || recovered != 0 {
		t.Fatalf("a missing folder = %d, %v; want 0", recovered, err)
	}
}

// An ordinary extended attribute staged from a config the editor then replaced
// cannot be proved against that config, so the stage is kept, but the command
// still retires the receipt and the next rollback is no longer refused.
func TestRecoverRetainedConfigTransformsFinishesAStagedEAChangeAfterAnEditorSave(t *testing.T) {
	dataDir, path := devinSetUp(t, "config.json", rollbackPristineVariants[0].bytes)
	atomicTransformEARegressionSet(t, path, atomicTransformEARegressionPayload("CONNECTOR_EA_FIXTURE", "ordinary metadata"))
	atomicTransformV2HardExitAt(t, path, dataDir, atomicTransformPhaseStageMarkerBootstrap)
	editorAtomicSave(t, path)
	recovered, err := RecoverRetainedConfigTransforms(dataDir)
	if err != nil || recovered != 1 {
		t.Fatalf("RecoverRetainedConfigTransforms = %d, %v; want 1 finished change", recovered, err)
	}
	for _, left := range atomicTransformV2Leftovers(t, path, dataDir) {
		if filepath.Dir(left) == dataDir {
			t.Fatalf("a recovery receipt remains after the command: %s", left)
		}
	}
	if saved, readErr := os.ReadFile(path); readErr != nil || !bytes.Contains(saved, []byte("operator_saved_during_rollback")) {
		t.Fatalf("the saved file was changed: %q %v", saved, readErr)
	}
	if again, err := RecoverRetainedConfigTransforms(dataDir); err != nil || again != 0 {
		t.Fatalf("a second run = %d, %v; want nothing left to finish", again, err)
	}
}

// A change recovery cannot prove is kept, and the command says which config it
// belongs to instead of reporting success. Here a data stream that is not the
// transaction own sits on its staged file while the prior config is untouched.
func TestRecoverRetainedConfigTransformsKeepsAndNamesAChangeItCannotProve(t *testing.T) {
	dataDir, path := devinSetUp(t, "config.json", rollbackPristineVariants[0].bytes)
	atomicTransformEARegressionSet(t, path, atomicTransformEARegressionPayload("CONNECTOR_EA_FIXTURE", "ordinary metadata"))
	atomicTransformV2HardExitAt(t, path, dataDir, atomicTransformPhaseStageMarkerBootstrap)
	staged, err := filepath.Glob(filepath.Join(filepath.Dir(path), atomicTransformV2NamePrefix+"stage-*"))
	if err != nil || len(staged) != 1 {
		t.Fatalf("expected one staged payload: %v %v", staged, err)
	}
	if err := os.WriteFile(staged[0]+":foreign", []byte("not the transaction own"), 0o600); err != nil {
		t.Fatal(err)
	}
	recovered, err := RecoverRetainedConfigTransforms(dataDir)
	if err == nil || recovered != 0 || !strings.Contains(err.Error(), filepath.Base(path)) {
		t.Fatalf("RecoverRetainedConfigTransforms = %d, %v; want the unprovable change reported by config name", recovered, err)
	}
	if left := atomicTransformV2Leftovers(t, path, dataDir); len(left) == 0 {
		t.Fatal("recovery evidence was discarded")
	}
}
