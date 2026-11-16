// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func atomicTransformV2StateFiles(t *testing.T, path, stateDir string) []string {
	t.Helper()
	var receipts []string
	for _, left := range atomicTransformV2Leftovers(t, path, stateDir) {
		if filepath.Dir(left) == stateDir {
			receipts = append(receipts, left)
		}
	}
	return receipts
}

// The receipt of an EA-staging crash is released after the prior config is
// replaced only when the stage is still the harmless shape the transaction
// wrote. A stage that carries anything else (another stream, other bytes) is
// not proved, so the receipt stays and the recovery reports it.
func TestAtomicTransformV2StagedEAAfterAnEditorSaveKeepsReceiptWhenTheStageIsForeign(t *testing.T) {
	for _, mutation := range []string{"foreign-stream", "other-bytes"} {
		t.Run(mutation, func(t *testing.T) {
			path, stateDir := atomicTransformV2WriteOld(t)
			atomicTransformEARegressionSet(t, path, atomicTransformEARegressionPayload("CONNECTOR_EA_FIXTURE", "ordinary metadata"))
			atomicTransformV2HardExitAt(t, path, stateDir, atomicTransformPhaseStageMarkerBootstrap)
			staged, err := filepath.Glob(filepath.Join(filepath.Dir(path), atomicTransformV2NamePrefix+"stage-*"))
			if err != nil || len(staged) != 1 {
				t.Fatalf("expected one staged payload: %v %v", staged, err)
			}
			if mutation == "foreign-stream" {
				err = os.WriteFile(staged[0]+":foreign", []byte("not the transaction own"), 0o600)
			} else {
				err = os.WriteFile(staged[0], []byte("not the transaction own"), 0o600)
			}
			if err != nil {
				t.Fatal(err)
			}
			atomicTransformV2OperatorSave(t, path, []byte("operator save"))
			if err := recoverAtomicTransformV2(path, stateDir); err == nil {
				t.Fatal("recovery reported success for a stage it could not prove")
			}
			if len(atomicTransformV2StateFiles(t, path, stateDir)) == 0 {
				t.Fatal("the receipt of an unproven stage was retired")
			}
			if content, readErr := os.ReadFile(path); readErr != nil || !bytes.Equal(content, []byte("operator save")) {
				t.Fatalf("operator save was changed: %q %v", content, readErr)
			}
		})
	}
}

// A prior config that cannot be read is not a changed prior: the failure is
// returned and the receipt stays, instead of being taken as permission to
// retire it.
func TestAtomicTransformV2StagedEAKeepsReceiptWhenThePriorConfigCannotBeRead(t *testing.T) {
	path, stateDir := atomicTransformV2WriteOld(t)
	atomicTransformEARegressionSet(t, path, atomicTransformEARegressionPayload("CONNECTOR_EA_FIXTURE", "ordinary metadata"))
	atomicTransformV2HardExitAt(t, path, stateDir, atomicTransformPhaseStageMarkerBootstrap)
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	// No sharing: every other open of the prior config fails with a sharing violation.
	held, err := windows.CreateFile(name, windows.GENERIC_READ, 0, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal(err)
	}
	recoverErr := recoverAtomicTransformV2(path, stateDir)
	if err := windows.CloseHandle(held); err != nil {
		t.Fatal(err)
	}
	if recoverErr == nil {
		t.Fatal("recovery reported success while the prior config could not be read")
	}
	if len(atomicTransformV2StateFiles(t, path, stateDir)) == 0 {
		t.Fatal("the receipt was retired on a read failure")
	}
	if err := recoverAtomicTransformV2(path, stateDir); err != nil {
		t.Fatalf("recovery did not finish once the prior config was readable: %v", err)
	}
}
