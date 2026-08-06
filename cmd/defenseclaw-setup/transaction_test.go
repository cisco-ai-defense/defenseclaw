// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"testing"
)

const (
	testPreviousTransactionID = "11111111111111111111111111111111"
	testCurrentTransactionID  = "22222222222222222222222222222222"
)

func testTransactionRoots(t *testing.T) (string, string, string) {
	t.Helper()
	root := t.TempDir()
	return filepath.Join(root, "Programs", "DefenseClaw"),
		filepath.Join(root, "Profile", ".defenseclaw"),
		filepath.Join(root, "DefenseClaw", "InstallerCache", setupArtifactName)
}

func bypassDeferredUninstallCleanupForTest(t *testing.T) {
	t.Helper()
	original := deferredCleanupTransactionRootExpectation
	deferredCleanupTransactionRootExpectation = func(setupTransaction) (bool, error) {
		return false, nil
	}
	t.Cleanup(func() {
		deferredCleanupTransactionRootExpectation = original
	})
}

func testInstallState(installRoot, dataRoot, maintenancePath, transactionID, version string) installState {
	return installState{
		SchemaVersion:          1,
		Version:                version,
		SourceCommit:           "0123456789abcdef0123456789abcdef01234567",
		DistributionFlavor:     "oss",
		InstallKind:            "native-windows-exe",
		InstallScope:           "user",
		InstallRoot:            installRoot,
		CommandDir:             filepath.Join(installRoot, "bin"),
		DataRoot:               dataRoot,
		Runtime:                filepath.Join(installRoot, "runtime", "python"),
		MaintenancePath:        maintenancePath,
		PathEntryOwned:         true,
		Connector:              "none",
		Mode:                   "observe",
		UnsignedLocalArtifact:  true,
		ReleaseSigningRequired: true,
		TransactionID:          transactionID,
	}
}

func TestValidateInstallStateForRootsRequiresExactWindsurfHooksTarget(t *testing.T) {
	installRoot, dataRoot, maintenancePath := testTransactionRoots(t)
	state := testInstallState(
		installRoot,
		dataRoot,
		maintenancePath,
		testCurrentTransactionID,
		"1.0.0",
	)
	state.Connector = "windsurf"
	state.WindsurfUserHome = filepath.Join(t.TempDir(), "bound-profile")
	state.WindsurfHooksPath = filepath.Join(
		state.WindsurfUserHome,
		".codeium",
		"windsurf",
		"hooks.json",
	)
	if err := validateInstallStateForRoots(
		&state,
		installRoot,
		dataRoot,
		maintenancePath,
	); err != nil {
		t.Fatalf("exact Windsurf hook target was rejected: %v", err)
	}

	state.WindsurfHooksPath = filepath.Join(
		t.TempDir(),
		"other-profile",
		".codeium",
		"windsurf",
		"hooks.json",
	)
	if err := validateInstallStateForRoots(
		&state,
		installRoot,
		dataRoot,
		maintenancePath,
	); err == nil || !strings.Contains(err.Error(), "inconsistent Windsurf hooks path") {
		t.Fatalf("mismatched Windsurf hook target error = %v", err)
	}
}

func writeInstallTree(t *testing.T, tree string, state installState) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(tree, "installer"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := writeJSON(filepath.Join(tree, "installer", "install-state.json"), state); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(tree, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tree, "bin", "owned.txt"), []byte(state.Version), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestRollbackInstallRestoresBackupAfterOldTreeMove(t *testing.T) {
	installRoot, dataRoot, maintenancePath := testTransactionRoots(t)
	previous := testInstallState(installRoot, dataRoot, maintenancePath, testPreviousTransactionID, "1.0.0")
	transaction := testSetupTransactionForRoots("install", installRoot, dataRoot, maintenancePath, &previous)
	writeInstallTree(t, transaction.BackupPath, previous)
	writeInstallTree(t, transaction.StagingPath, testInstallState(
		installRoot,
		dataRoot,
		maintenancePath,
		transaction.ID,
		"1.1.0",
	))

	if err := rollbackInstallFiles(transaction); err != nil {
		t.Fatalf("rollbackInstallFiles: %v", err)
	}
	assertInstallVersion(t, installRoot, transaction, "1.0.0")
	assertPathAbsent(t, transaction.BackupPath)
	assertPathAbsent(t, transaction.StagingPath)
	if err := rollbackInstallFiles(transaction); err != nil {
		t.Fatalf("idempotent rollbackInstallFiles: %v", err)
	}
}

func TestRollbackInstallReplacesPublishedTransactionTree(t *testing.T) {
	installRoot, dataRoot, maintenancePath := testTransactionRoots(t)
	previous := testInstallState(installRoot, dataRoot, maintenancePath, testPreviousTransactionID, "1.0.0")
	transaction := testSetupTransactionForRoots("install", installRoot, dataRoot, maintenancePath, &previous)
	writeInstallTree(t, transaction.BackupPath, previous)
	writeInstallTree(t, installRoot, testInstallState(
		installRoot,
		dataRoot,
		maintenancePath,
		transaction.ID,
		"1.1.0",
	))

	if err := rollbackInstallFiles(transaction); err != nil {
		t.Fatalf("rollbackInstallFiles: %v", err)
	}
	assertInstallVersion(t, installRoot, transaction, "1.0.0")
	assertPathAbsent(t, transaction.BackupPath)
}

func TestRollbackInstallCleansIncompleteRecordedStagingTree(t *testing.T) {
	installRoot, dataRoot, maintenancePath := testTransactionRoots(t)
	transaction := testSetupTransactionForRoots("install", installRoot, dataRoot, maintenancePath, nil)
	if err := os.MkdirAll(filepath.Join(transaction.StagingPath, "runtime", "partial"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(transaction.StagingPath, "runtime", "partial", "file"), []byte("partial"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := rollbackInstallFiles(transaction); err != nil {
		t.Fatalf("rollbackInstallFiles: %v", err)
	}
	assertPathAbsent(t, transaction.StagingPath)
}

func TestRollbackInstallPreservesLockedOldTreeWhenStagingProvesPublicationNeverCreatedBackup(t *testing.T) {
	installRoot, dataRoot, maintenancePath := testTransactionRoots(t)
	previous := testInstallState(installRoot, dataRoot, maintenancePath, testPreviousTransactionID, "1.0.0")
	transaction := testSetupTransactionForRoots("install", installRoot, dataRoot, maintenancePath, &previous)
	writeInstallTree(t, installRoot, previous)
	writeInstallTree(t, transaction.StagingPath, testInstallState(
		installRoot,
		dataRoot,
		maintenancePath,
		transaction.ID,
		transaction.TargetVersion,
	))

	renameCalls := 0
	err := rollbackInstallFilesWithRename(transaction, func(string, string) error {
		renameCalls++
		return syscall.Errno(32)
	})
	if err != nil {
		t.Fatalf("pre-publication rollback: %v", err)
	}
	if renameCalls != 0 {
		t.Fatalf("pre-publication rollback rename calls = %d, want 0", renameCalls)
	}
	assertInstallVersion(t, installRoot, transaction, previous.Version)
	assertPathAbsent(t, transaction.StagingPath)
	assertPathAbsent(t, transaction.BackupPath)
}

func TestRollbackInstallConfirmsDurableRestoreWhenStagingIsAbsent(t *testing.T) {
	installRoot, dataRoot, maintenancePath := testTransactionRoots(t)
	previous := testInstallState(installRoot, dataRoot, maintenancePath, testPreviousTransactionID, "1.0.0")
	transaction := testSetupTransactionForRoots("install", installRoot, dataRoot, maintenancePath, &previous)
	writeInstallTree(t, installRoot, previous)

	renameCalls := 0
	err := rollbackInstallFilesWithRename(transaction, func(source, destination string) error {
		renameCalls++
		return os.Rename(source, destination)
	})
	if err != nil {
		t.Fatalf("durable restored-tree confirmation: %v", err)
	}
	if renameCalls != 2 {
		t.Fatalf("durable restored-tree rename calls = %d, want 2", renameCalls)
	}
	assertInstallVersion(t, installRoot, transaction, previous.Version)
	assertPathAbsent(t, transaction.BackupPath)
}

func TestRollbackFreshInstallRefusesStateLessPublishedTree(t *testing.T) {
	installRoot, dataRoot, maintenancePath := testTransactionRoots(t)
	transaction := testSetupTransactionForRoots("install", installRoot, dataRoot, maintenancePath, nil)
	if err := os.MkdirAll(filepath.Join(installRoot, "runtime"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(installRoot, "runtime", "locked-on-first-attempt"), []byte("partial"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := rollbackInstallFiles(transaction); err == nil {
		t.Fatal("rollbackInstallFiles deleted a state-less fixed install root")
	}
	if !pathExists(installRoot) {
		t.Fatal("state-less fixed install root was not preserved")
	}
}

func TestRollbackFreshInstallPreservesConcurrentRootWhenStagingStillExists(t *testing.T) {
	installRoot, dataRoot, maintenancePath := testTransactionRoots(t)
	transaction := testSetupTransactionForRoots("install", installRoot, dataRoot, maintenancePath, nil)
	if err := os.MkdirAll(transaction.StagingPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(installRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(installRoot, "unrelated.txt")
	if err := os.WriteFile(marker, []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := rollbackInstallFiles(transaction); err != nil {
		t.Fatal(err)
	}
	assertPathAbsent(t, transaction.StagingPath)
	if data, err := os.ReadFile(marker); err != nil || string(data) != "preserve" {
		t.Fatalf("concurrent install root was changed: %q, %v", data, err)
	}
}

func TestRollbackInstallRefusesUnrelatedPublishedTree(t *testing.T) {
	installRoot, dataRoot, maintenancePath := testTransactionRoots(t)
	previous := testInstallState(installRoot, dataRoot, maintenancePath, testPreviousTransactionID, "1.0.0")
	transaction := testSetupTransactionForRoots("install", installRoot, dataRoot, maintenancePath, &previous)
	writeInstallTree(t, transaction.BackupPath, previous)
	writeInstallTree(t, installRoot, testInstallState(
		installRoot,
		dataRoot,
		maintenancePath,
		"33333333333333333333333333333333",
		"9.9.9",
	))

	if err := rollbackInstallFiles(transaction); err == nil {
		t.Fatal("rollbackInstallFiles replaced a tree not owned by the transaction")
	}
	assertInstallVersion(t, installRoot, transaction, "9.9.9")
}

func TestRollbackUninstallRestoresRenamedTreeIdempotently(t *testing.T) {
	installRoot, dataRoot, maintenancePath := testTransactionRoots(t)
	previous := testInstallState(installRoot, dataRoot, maintenancePath, testPreviousTransactionID, "1.0.0")
	transaction := testSetupTransactionForRoots("uninstall", installRoot, dataRoot, maintenancePath, &previous)
	writeInstallTree(t, transaction.TrashPath, previous)

	if err := rollbackUninstallFiles(transaction); err != nil {
		t.Fatalf("rollbackUninstallFiles: %v", err)
	}
	assertInstallVersion(t, installRoot, transaction, "1.0.0")
	assertPathAbsent(t, transaction.TrashPath)
	if err := rollbackUninstallFiles(transaction); err != nil {
		t.Fatalf("idempotent rollbackUninstallFiles: %v", err)
	}
}

func TestReplayedTransactionPathOwnership(t *testing.T) {
	commandDir := `C:\Users\runneradmin\AppData\Local\Programs\DefenseClaw\bin`
	apps := `C:\Users\runneradmin\AppData\Local\Microsoft\WindowsApps`
	tests := []struct {
		name        string
		previous    userPathSnapshot
		current     userPathSnapshot
		wantOwned   bool
		wantReused  bool
		wantCreated bool
	}{
		{
			name:        "missing value published before crash",
			current:     userPathSnapshot{Existed: true, Value: commandDir, ValueType: 1},
			wantOwned:   true,
			wantCreated: true,
		},
		{
			name:      "existing value published before crash",
			previous:  userPathSnapshot{Existed: true, Value: apps, ValueType: 1},
			current:   userPathSnapshot{Existed: true, Value: commandDir + ";" + apps, ValueType: 1},
			wantOwned: true,
		},
		{
			name:       "leading separator replay",
			previous:   userPathSnapshot{Existed: true, Value: ";" + apps, ValueType: 2},
			current:    userPathSnapshot{Existed: true, Value: commandDir + ";" + apps, ValueType: 2},
			wantOwned:  true,
			wantReused: true,
		},
		{
			name:     "entry predated transaction",
			previous: userPathSnapshot{Existed: true, Value: commandDir + ";" + apps, ValueType: 1},
			current:  userPathSnapshot{Existed: true, Value: commandDir + ";" + apps, ValueType: 1},
		},
		{
			name:     "operator edited value after publication",
			previous: userPathSnapshot{Existed: true, Value: apps, ValueType: 1},
			current:  userPathSnapshot{Existed: true, Value: commandDir + ";" + apps + `;C:\Tools`, ValueType: 1},
		},
		{
			name:     "registry type changed after publication",
			previous: userPathSnapshot{Existed: true, Value: apps, ValueType: 2},
			current:  userPathSnapshot{Existed: true, Value: commandDir + ";" + apps, ValueType: 1},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			owned, reused, created := replayedTransactionPathOwnership(test.previous, test.current, commandDir)
			if owned != test.wantOwned || reused != test.wantReused || created != test.wantCreated {
				t.Fatalf(
					"ownership = (%t, %t, %t), want (%t, %t, %t)",
					owned,
					reused,
					created,
					test.wantOwned,
					test.wantReused,
					test.wantCreated,
				)
			}
		})
	}
}

func TestCommittedInstallCleanupPreservesNewTreeAndRemovesArtifacts(t *testing.T) {
	installRoot, dataRoot, maintenancePath := testTransactionRoots(t)
	previous := testInstallState(installRoot, dataRoot, maintenancePath, testPreviousTransactionID, "1.0.0")
	transaction := testSetupTransactionForRoots("install", installRoot, dataRoot, maintenancePath, &previous)
	writeInstallTree(t, installRoot, testInstallState(
		installRoot,
		dataRoot,
		maintenancePath,
		transaction.ID,
		"1.1.0",
	))
	writeInstallTree(t, transaction.BackupPath, previous)
	if err := os.MkdirAll(filepath.Dir(transaction.MaintenanceBackup), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(transaction.MaintenanceBackup, []byte("old setup"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := cleanupCommittedSetupTransaction(transaction); err != nil {
		t.Fatalf("cleanupCommittedSetupTransaction: %v", err)
	}
	assertInstallVersion(t, installRoot, transaction, "1.1.0")
	assertPathAbsent(t, transaction.BackupPath)
	assertPathAbsent(t, transaction.MaintenanceBackup)
	if err := cleanupCommittedSetupTransaction(transaction); err != nil {
		t.Fatalf("idempotent cleanupCommittedSetupTransaction: %v", err)
	}
}

func TestCommittedUninstallCleanupConvergesAfterRename(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows delayed maintenance-cache cleanup")
	}
	bypassDeferredUninstallCleanupForTest(t)
	installRoot, dataRoot, maintenancePath := testTransactionRoots(t)
	previous := testInstallState(installRoot, dataRoot, maintenancePath, testPreviousTransactionID, "1.0.0")
	transaction := testSetupTransactionForRoots("uninstall", installRoot, dataRoot, maintenancePath, &previous)
	transaction.DeleteUserData = true
	transaction.MaintenanceExisted = true
	writeInstallTree(t, transaction.TrashPath, previous)
	if err := os.MkdirAll(filepath.Dir(maintenancePath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(maintenancePath, []byte("setup"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dataRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataRoot, "state"), []byte("delete"), 0o644); err != nil {
		t.Fatal(err)
	}

	readNoReconciliation := func() (*connectorReconciliationState, error) { return nil, nil }
	if err := cleanupCommittedSetupTransactionWithReconciliationReader(transaction, readNoReconciliation); err != nil {
		t.Fatalf("cleanupCommittedSetupTransaction: %v", err)
	}
	assertPathAbsent(t, transaction.TrashPath)
	assertPathAbsent(t, filepath.Dir(maintenancePath))
	assertPathAbsent(t, dataRoot)
	if err := cleanupCommittedSetupTransactionWithReconciliationReader(transaction, readNoReconciliation); err != nil {
		t.Fatalf("idempotent cleanupCommittedSetupTransaction: %v", err)
	}
}

func TestCommittedUninstallCleanupPreservesDataForPendingConnectorReconciliation(t *testing.T) {
	bypassDeferredUninstallCleanupForTest(t)
	installRoot, dataRoot, maintenancePath := testTransactionRoots(t)
	transaction := testSetupTransactionForRoots("uninstall", installRoot, dataRoot, maintenancePath, nil)
	transaction.DeleteUserData = true
	if err := os.MkdirAll(dataRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(dataRoot, "state")
	if err := os.WriteFile(statePath, []byte("preserve"), 0o644); err != nil {
		t.Fatal(err)
	}
	pending := &connectorReconciliationState{
		SchemaVersion: connectorReconciliationSchemaVersion,
		Failures: []connectorReconciliationFailure{{
			Connector:     "claudecode",
			Operation:     "verify",
			ConfigHome:    filepath.Join(filepath.Dir(dataRoot), ".claude"),
			Message:       "managed connector cleanup is pending",
			TransactionID: testCurrentTransactionID,
		}},
	}
	readPendingReconciliation := func() (*connectorReconciliationState, error) { return pending, nil }

	if err := cleanupCommittedSetupTransactionWithReconciliationReader(transaction, readPendingReconciliation); err != nil {
		t.Fatalf("cleanupCommittedSetupTransaction: %v", err)
	}
	if _, err := os.Stat(statePath); err != nil {
		t.Fatalf("pending connector reconciliation data was not preserved: %v", err)
	}
}

func TestCommittedUninstallCleanupFinishesPartiallyDeletedTrash(t *testing.T) {
	bypassDeferredUninstallCleanupForTest(t)
	installRoot, dataRoot, maintenancePath := testTransactionRoots(t)
	previous := testInstallState(installRoot, dataRoot, maintenancePath, testPreviousTransactionID, "1.0.0")
	transaction := testSetupTransactionForRoots("uninstall", installRoot, dataRoot, maintenancePath, &previous)
	if err := os.MkdirAll(filepath.Join(transaction.TrashPath, "runtime"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(transaction.TrashPath, "runtime", "remaining"), []byte("partial"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := cleanupCommittedSetupTransaction(transaction); err != nil {
		t.Fatalf("cleanupCommittedSetupTransaction: %v", err)
	}
	assertPathAbsent(t, transaction.TrashPath)
}

func TestRollbackMaintenancePublicationRestoresPriorCache(t *testing.T) {
	installRoot, dataRoot, maintenancePath := testTransactionRoots(t)
	transaction := testSetupTransactionForRoots("install", installRoot, dataRoot, maintenancePath, nil)
	transaction.MaintenanceExisted = true
	if err := os.MkdirAll(filepath.Dir(maintenancePath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(transaction.MaintenanceBackup, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(maintenancePath, []byte("new"), 0o644); err != nil {
		t.Fatal(err)
	}
	previousDigest, err := fileSHA256(transaction.MaintenanceBackup)
	if err != nil {
		t.Fatal(err)
	}
	publishedDigest, err := fileSHA256(maintenancePath)
	if err != nil {
		t.Fatal(err)
	}
	transaction.PreviousMaintenanceSHA256 = previousDigest
	transaction.MaintenanceSHA256 = publishedDigest

	if err := rollbackMaintenancePublication(transaction); err != nil {
		t.Fatalf("rollbackMaintenancePublication: %v", err)
	}
	data, err := os.ReadFile(maintenancePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "old" {
		t.Fatalf("maintenance cache = %q, want old", data)
	}
	if err := rollbackMaintenancePublication(transaction); err != nil {
		t.Fatalf("idempotent rollbackMaintenancePublication: %v", err)
	}
}

func TestRollbackMaintenancePublicationPreservesConcurrentReplacement(t *testing.T) {
	installRoot, dataRoot, maintenancePath := testTransactionRoots(t)
	transaction := testSetupTransactionForRoots("install", installRoot, dataRoot, maintenancePath, nil)
	transaction.MaintenanceExisted = true
	if err := os.MkdirAll(filepath.Dir(maintenancePath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(transaction.MaintenanceBackup, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(maintenancePath, []byte("operator replacement"), 0o644); err != nil {
		t.Fatal(err)
	}
	previousDigest, err := fileSHA256(transaction.MaintenanceBackup)
	if err != nil {
		t.Fatal(err)
	}
	transaction.PreviousMaintenanceSHA256 = previousDigest

	if err := rollbackMaintenancePublication(transaction); err == nil {
		t.Fatal("rollback overwrote a concurrent maintenance replacement")
	}
	data, err := os.ReadFile(maintenancePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "operator replacement" {
		t.Fatalf("concurrent maintenance file = %q", data)
	}
}

func TestRollbackMaintenancePublicationWithoutPriorCacheRemovesOnlyOwnedDigest(t *testing.T) {
	installRoot, dataRoot, maintenancePath := testTransactionRoots(t)
	transaction := testSetupTransactionForRoots("install", installRoot, dataRoot, maintenancePath, nil)
	if err := os.MkdirAll(filepath.Dir(maintenancePath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(maintenancePath, []byte("operator file"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := rollbackMaintenancePublication(transaction); err == nil {
		t.Fatal("rollback removed a maintenance file it did not publish")
	}
	if !pathExists(maintenancePath) {
		t.Fatal("concurrent maintenance file was removed")
	}
}

func TestRollbackMaintenancePublicationPreservesSameDigestConcurrentTargetWhenStaged(t *testing.T) {
	installRoot, dataRoot, maintenancePath := testTransactionRoots(t)
	transaction := testSetupTransactionForRoots("install", installRoot, dataRoot, maintenancePath, nil)
	if err := os.MkdirAll(filepath.Dir(maintenancePath), 0o755); err != nil {
		t.Fatal(err)
	}
	data := []byte("same installer bytes")
	if err := os.WriteFile(transaction.MaintenanceNew, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(maintenancePath, data, 0o644); err != nil {
		t.Fatal(err)
	}
	digest, err := fileSHA256(maintenancePath)
	if err != nil {
		t.Fatal(err)
	}
	transaction.MaintenanceSHA256 = digest

	if err := rollbackMaintenancePublication(transaction); err != nil {
		t.Fatal(err)
	}
	if !pathExists(maintenancePath) {
		t.Fatal("same-digest concurrent maintenance target was removed")
	}
	assertPathAbsent(t, transaction.MaintenanceNew)
}

func TestRollbackUninstallPreservesMaintenanceCacheThatAppearedAfterIntent(t *testing.T) {
	installRoot, dataRoot, maintenancePath := testTransactionRoots(t)
	transaction := testSetupTransactionForRoots("uninstall", installRoot, dataRoot, maintenancePath, nil)
	if err := os.MkdirAll(filepath.Dir(maintenancePath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(maintenancePath, []byte("concurrent"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := rollbackMaintenancePublication(transaction); err != nil {
		t.Fatal(err)
	}
	if !pathExists(maintenancePath) {
		t.Fatal("uninstall rollback removed a concurrent maintenance cache")
	}
}

func TestRollbackUninstallPreservesMaintenanceCacheChangedAfterIntent(t *testing.T) {
	installRoot, dataRoot, maintenancePath := testTransactionRoots(t)
	transaction := testSetupTransactionForRoots("uninstall", installRoot, dataRoot, maintenancePath, nil)
	transaction.MaintenanceExisted = true
	transaction.PreviousMaintenanceSHA256 = strings.Repeat("a", 64)
	if err := os.MkdirAll(filepath.Dir(maintenancePath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(maintenancePath, []byte("new concurrent bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := rollbackMaintenancePublication(transaction); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(maintenancePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "new concurrent bytes" {
		t.Fatalf("uninstall rollback changed concurrent cache to %q", data)
	}
}

func TestValidateSetupTransactionRejectsUnrelatedRecordedPath(t *testing.T) {
	installRoot, dataRoot, maintenancePath := testTransactionRoots(t)
	previous := testInstallState(installRoot, dataRoot, maintenancePath, testPreviousTransactionID, "1.0.0")
	transaction := testSetupTransactionForRoots("install", installRoot, dataRoot, maintenancePath, &previous)
	expected := setupTransactionExpectations{
		InstallRoot:     installRoot,
		DataRoot:        dataRoot,
		MaintenancePath: maintenancePath,
	}
	if err := validateSetupTransaction(transaction, expected); err != nil {
		t.Fatalf("valid transaction rejected: %v", err)
	}
	activeHook := transaction
	activeHook.PreviousStableHookStatus = stableHookSnapshotActive
	if err := validateSetupTransaction(activeHook, expected); err != nil {
		t.Fatalf("active stable-hook snapshot rejected: %v", err)
	}
	activeUninstallHook := testSetupTransactionForRoots(
		"uninstall",
		installRoot,
		dataRoot,
		maintenancePath,
		&previous,
	)
	activeUninstallHook.PreviousStableHookStatus = stableHookSnapshotActive
	if err := validateSetupTransaction(activeUninstallHook, expected); err != nil {
		t.Fatalf("active uninstall stable-hook snapshot rejected: %v", err)
	}
	invalidHook := transaction
	invalidHook.PreviousStableHookStatus = "unknown"
	if err := validateSetupTransaction(invalidHook, expected); err == nil {
		t.Fatal("validateSetupTransaction accepted an invalid stable-hook snapshot")
	}
	freshActiveHook := testSetupTransactionForRoots("install", installRoot, dataRoot, maintenancePath, nil)
	freshActiveHook.PreviousStableHookStatus = stableHookSnapshotActive
	if err := validateSetupTransaction(freshActiveHook, expected); err == nil {
		t.Fatal("validateSetupTransaction accepted an active stable hook without a previous install")
	}
	activeHook.UninstallHandoffHookStatus = stableHookSnapshotActive
	if err := validateSetupTransaction(activeHook, expected); err != nil {
		t.Fatalf("install uninstall-handoff hook snapshot rejected: %v", err)
	}
	activeUninstallHook.UninstallHandoffHookStatus = stableHookSnapshotActive
	if err := validateSetupTransaction(activeUninstallHook, expected); err == nil {
		t.Fatal("validateSetupTransaction accepted uninstall-handoff state on an uninstall transaction")
	}
	transaction.BackupPath = filepath.Join(t.TempDir(), "unrelated")
	if err := validateSetupTransaction(transaction, expected); err == nil {
		t.Fatal("validateSetupTransaction accepted an unrelated backup path")
	}
}

func TestValidateSetupTransactionBindsPreservedConnectorState(t *testing.T) {
	installRoot, dataRoot, maintenancePath := testTransactionRoots(t)
	previous := testInstallState(installRoot, dataRoot, maintenancePath, testPreviousTransactionID, "1.0.0")
	transaction := testSetupTransactionForRoots("install", installRoot, dataRoot, maintenancePath, &previous)
	transaction.PreserveConnectorConfiguration = true
	transaction.PreviousConnectors = []string{"codex", "cursor", "hermes", "opencode"}
	transaction.TargetServices.Gateway = true
	transaction.PreviousCodexHome = filepath.Join(filepath.Dir(dataRoot), ".codex")
	transaction.CodexHome = transaction.PreviousCodexHome
	transaction.PreviousClaudeConfigDir = filepath.Join(filepath.Dir(dataRoot), ".claude")
	transaction.ClaudeConfigDir = transaction.PreviousClaudeConfigDir
	transaction.PreviousCopilotHome = filepath.Join(filepath.Dir(dataRoot), ".copilot")
	transaction.CopilotHome = transaction.PreviousCopilotHome
	transaction.PreviousCursorHome = filepath.Join(filepath.Dir(dataRoot), ".cursor")
	transaction.CursorHome = transaction.PreviousCursorHome
	officialAntigravityHome, err := officialAntigravityConfigHomeForTransaction(dataRoot)
	if err != nil {
		t.Fatal(err)
	}
	transaction.PreviousAntigravityConfigDir = officialAntigravityHome
	transaction.AntigravityConfigDir = transaction.PreviousAntigravityConfigDir
	transaction.PreviousOpenCodeConfigDir = filepath.Join(filepath.Dir(dataRoot), ".config", "opencode")
	transaction.OpenCodeConfigDir = transaction.PreviousOpenCodeConfigDir
	transaction.PreviousHermesHome = filepath.Join(filepath.Dir(dataRoot), "AppData", "Local", "hermes")
	transaction.HermesHome = transaction.PreviousHermesHome
	expected := setupTransactionExpectations{
		InstallRoot:     installRoot,
		DataRoot:        dataRoot,
		MaintenancePath: maintenancePath,
	}
	if err := validateSetupTransaction(transaction, expected); err != nil {
		t.Fatalf("valid connector-preserving transaction rejected: %v", err)
	}
	cursorMigration := transaction
	cursorPrevious := *transaction.PreviousState
	cursorPrevious.Connector = "cursor"
	cursorPrevious.Mode = "action"
	cursorMigration.PreviousState = &cursorPrevious
	cursorMigration.TargetConnector = "cursor"
	cursorMigration.TargetMode = "observe"
	if err := validateSetupTransaction(cursorMigration, expected); err == nil {
		t.Fatal("connector-preserving repair changed Cursor action to observe")
	}

	changedHome := transaction
	changedHome.CopilotHome = filepath.Join(filepath.Dir(dataRoot), "other-copilot")
	if err := validateSetupTransaction(changedHome, expected); err == nil {
		t.Fatal("connector-preserving transaction changed its recorded Copilot home")
	}
	changedCursorHome := transaction
	changedCursorHome.CursorHome = filepath.Join(filepath.Dir(dataRoot), "other-cursor")
	if err := validateSetupTransaction(changedCursorHome, expected); err == nil {
		t.Fatal("connector-preserving transaction changed its recorded Cursor home")
	}
	changedAntigravityHome := transaction
	changedAntigravityHome.AntigravityConfigDir = filepath.Join(filepath.Dir(dataRoot), ".gemini", "other")
	if err := validateSetupTransaction(changedAntigravityHome, expected); err == nil {
		t.Fatal("connector-preserving transaction changed its recorded Antigravity config home")
	}
	changedNonPreservingAntigravityHome := transaction
	changedNonPreservingAntigravityHome.PreserveConnectorConfiguration = false
	changedNonPreservingAntigravityHome.AntigravityConfigDir = filepath.Join(
		filepath.Dir(dataRoot),
		".gemini",
		"other",
	)
	if err := validateSetupTransaction(changedNonPreservingAntigravityHome, expected); err == nil {
		t.Fatal("non-preserving install transaction accepted a non-official Antigravity config home")
	}
	migratedAntigravityHome := transaction
	migratedPreviousState := *transaction.PreviousState
	migratedAntigravityHome.PreviousState = &migratedPreviousState
	migratedAntigravityHome.PreviousConnectors = append(
		append([]string(nil), transaction.PreviousConnectors...),
		"antigravity",
	)
	migratedAntigravityHome.PreviousAntigravityConfigDir = filepath.Join(
		filepath.Dir(dataRoot),
		"legacy-antigravity-custom",
	)
	migratedAntigravityHome.PreviousState.AntigravityConfigDir =
		migratedAntigravityHome.PreviousAntigravityConfigDir
	migratedAntigravityHome.AntigravityConfigDir = officialAntigravityHome
	if err := validateSetupTransaction(migratedAntigravityHome, expected); err != nil {
		t.Fatalf("connector-preserving Antigravity custom-home migration rejected: %v", err)
	}
	changedOpenCodeHome := transaction
	changedOpenCodeHome.OpenCodeConfigDir = filepath.Join(filepath.Dir(dataRoot), "other-opencode")
	if err := validateSetupTransaction(changedOpenCodeHome, expected); err == nil {
		t.Fatal("connector-preserving transaction changed its recorded OpenCode home")
	}
	changedHermesHome := transaction
	changedHermesHome.HermesHome = filepath.Join(filepath.Dir(dataRoot), "other-hermes")
	if err := validateSetupTransaction(changedHermesHome, expected); err == nil {
		t.Fatal("connector-preserving transaction changed its recorded Hermes home")
	}
	changedSelection := transaction
	changedSelection.TargetConnector = "codex"
	if err := validateSetupTransaction(changedSelection, expected); err == nil {
		t.Fatal("connector-preserving transaction changed its installer selection")
	}
	disabledGateway := transaction
	disabledGateway.TargetServices.Gateway = false
	if err := validateSetupTransaction(disabledGateway, expected); err == nil {
		t.Fatal("connector-preserving transaction disabled its required gateway")
	}
}

func TestValidateSetupTransactionAntigravityHomeIgnoresSpoofedDataRoot(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("native Windows Profile Known Folder contract")
	}
	installRoot, dataRoot, maintenancePath := testTransactionRoots(t)
	transaction := testSetupTransactionForRoots("install", installRoot, dataRoot, maintenancePath, nil)
	officialHome, err := defaultConnectorConfigHome(filepath.Join(".gemini", "config"))
	if err != nil {
		t.Fatal(err)
	}
	spoofedDataRoot := filepath.Join(t.TempDir(), "spoofed-profile", ".defenseclaw")
	transaction.DataRoot = spoofedDataRoot
	transaction.AntigravityConfigDir = officialHome
	expected := setupTransactionExpectations{
		InstallRoot:     installRoot,
		DataRoot:        spoofedDataRoot,
		MaintenancePath: maintenancePath,
	}
	if err := validateSetupTransaction(transaction, expected); err != nil {
		t.Fatalf("official Antigravity home changed with a spoofed DataRoot: %v", err)
	}
	transaction.AntigravityConfigDir = connectorDefaultHomeBesideDataRoot(
		spoofedDataRoot,
		"antigravity",
	)
	if err := validateSetupTransaction(transaction, expected); err == nil ||
		!strings.Contains(err.Error(), "non-official Antigravity configuration home") {
		t.Fatalf("spoofed DataRoot redirected Antigravity custody: %v", err)
	}
}

func TestSetupJournalRoundTripsAntigravityConfigHomeCustody(t *testing.T) {
	installRoot, dataRoot, maintenancePath := testTransactionRoots(t)
	previous := testInstallState(
		installRoot,
		dataRoot,
		maintenancePath,
		testPreviousTransactionID,
		"1.0.0",
	)
	home := filepath.Join(filepath.Dir(dataRoot), ".gemini", "config")
	previous.AntigravityConfigDir = home
	transaction := testSetupTransactionForRoots(
		"install",
		installRoot,
		dataRoot,
		maintenancePath,
		&previous,
	)
	transaction.PreviousConnectors = []string{"antigravity"}
	transaction.PreviousAntigravityConfigDir = home
	transaction.AntigravityConfigDir = home

	body, err := json.Marshal(setupJournal{
		SchemaVersion: setupJournalSchemaVersion,
		Phase:         setupPhaseIntent,
		Transaction:   transaction,
	})
	if err != nil {
		t.Fatal(err)
	}
	var restored setupJournal
	if err := decodeSetupJournalJSON(body, &restored); err != nil {
		t.Fatal(err)
	}
	if restored.Transaction.PreviousState == nil ||
		!samePath(restored.Transaction.PreviousState.AntigravityConfigDir, home) ||
		!samePath(restored.Transaction.PreviousAntigravityConfigDir, home) ||
		!samePath(restored.Transaction.AntigravityConfigDir, home) {
		t.Fatalf("Antigravity config-home custody was not preserved: %+v", restored.Transaction)
	}
}

func TestValidateUninstallRetainsCustomAntigravityRestorationCustody(t *testing.T) {
	installRoot, dataRoot, maintenancePath := testTransactionRoots(t)
	previous := testInstallState(
		installRoot,
		dataRoot,
		maintenancePath,
		testPreviousTransactionID,
		"1.0.0",
	)
	customHome := filepath.Join(filepath.Dir(dataRoot), "legacy-antigravity-custom")
	previous.Connector = "antigravity"
	previous.AntigravityConfigDir = customHome
	transaction := testSetupTransactionForRoots(
		"uninstall",
		installRoot,
		dataRoot,
		maintenancePath,
		&previous,
	)
	transaction.PreviousConnectors = []string{"antigravity"}
	transaction.PreviousAntigravityConfigDir = customHome
	transaction.AntigravityConfigDir = customHome

	if err := validateSetupTransaction(transaction, setupTransactionExpectations{
		InstallRoot:     installRoot,
		DataRoot:        dataRoot,
		MaintenancePath: maintenancePath,
	}); err != nil {
		t.Fatalf("custom Antigravity uninstall custody rejected: %v", err)
	}
}

func TestValidateSetupTransactionRejectsReparseRoot(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows reparse-point validation")
	}
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	installRoot := filepath.Join(root, "Programs", "DefenseClaw")
	if err := os.MkdirAll(filepath.Dir(installRoot), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, installRoot); err != nil {
		if output, junctionErr := exec.Command(
			"cmd.exe", "/D", "/C", "mklink", "/J", installRoot, target,
		).CombinedOutput(); junctionErr != nil {
			t.Fatalf("create reparse fixture after symlink error %v: %v\n%s", err, junctionErr, output)
		}
	}
	t.Cleanup(func() { _ = os.Remove(installRoot) })
	dataRoot := filepath.Join(root, "Profile", ".defenseclaw")
	maintenancePath := filepath.Join(root, "DefenseClaw", "InstallerCache", setupArtifactName)
	transaction := testSetupTransactionForRoots("install", installRoot, dataRoot, maintenancePath, nil)
	expected := setupTransactionExpectations{
		InstallRoot:     installRoot,
		DataRoot:        dataRoot,
		MaintenancePath: maintenancePath,
	}
	if err := validateSetupTransaction(transaction, expected); err == nil {
		t.Fatal("validateSetupTransaction accepted a reparse-point install root")
	}
}

func TestDurableTransactionMarkerRoundTripAndNoOverwrite(t *testing.T) {
	installRoot, dataRoot, maintenancePath := testTransactionRoots(t)
	transaction := testSetupTransactionForRoots("install", installRoot, dataRoot, maintenancePath, nil)
	marker := filepath.Join(t.TempDir(), "setup-transaction.json")
	if err := writeDurableTransaction(marker, transaction); err != nil {
		t.Fatalf("writeDurableTransaction: %v", err)
	}
	loaded, err := readSetupTransaction(marker)
	if err != nil {
		t.Fatalf("readSetupTransaction: %v", err)
	}
	if loaded == nil || loaded.ID != transaction.ID || loaded.Action != transaction.Action {
		t.Fatalf("loaded transaction = %+v, want id %s action %s", loaded, transaction.ID, transaction.Action)
	}
	if err := writeDurableTransaction(marker, transaction); err == nil {
		t.Fatal("writeDurableTransaction overwrote an existing durable marker")
	}
}

func TestRecoverSetupJournalPhaseDispatchesMonotonically(t *testing.T) {
	tests := []struct {
		schema int
		phase  string
		want   []string
	}{
		{schema: setupJournalSchemaVersion, phase: setupPhaseIntent, want: []string{"abort", "intent->complete"}},
		{schema: setupJournalSchemaVersion, phase: setupPhaseQuiescing, want: []string{"rollback", "quiescing->complete"}},
		{schema: setupJournalLegacySchemaVersion, phase: setupPhaseIntent, want: []string{"rollback", "intent->complete"}},
		{phase: setupPhasePublished, want: []string{"activate", "published->committed", "converge", "committed->converged", "cleanup", "converged->complete"}},
		{phase: setupPhaseCommitted, want: []string{"converge", "committed->converged", "cleanup", "converged->complete"}},
		{phase: setupPhaseConverged, want: []string{"cleanup", "converged->complete"}},
		{phase: setupPhaseComplete, want: nil},
	}
	for _, test := range tests {
		t.Run(fmt.Sprintf("schema-%d-%s", test.schema, test.phase), func(t *testing.T) {
			var got []string
			appendStep := func(step string) error {
				got = append(got, step)
				return nil
			}
			transaction := testSetupTransactionForRoots("install", "root", "data", "maintenance", nil)
			err := recoverSetupJournalPhase(setupJournal{
				SchemaVersion: test.schema,
				Phase:         test.phase,
				Transaction:   transaction,
			}, setupRecoveryOps{
				Abort:    func(setupTransaction) error { return appendStep("abort") },
				Rollback: func(setupTransaction) error { return appendStep("rollback") },
				Activate: func(setupTransaction) error { return appendStep("activate") },
				Converge: func(setupTransaction) error { return appendStep("converge") },
				Cleanup:  func(setupTransaction) error { return appendStep("cleanup") },
				Transition: func(_ setupTransaction, from, to string) error {
					return appendStep(from + "->" + to)
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("steps = %v, want %v", got, test.want)
			}
		})
	}
}

func TestAbortPreparedSetupLeavesLiveStateByteIdenticalAndRemovesOnlyStaging(t *testing.T) {
	installRoot, dataRoot, maintenancePath := testTransactionRoots(t)
	previous := testInstallState(installRoot, dataRoot, maintenancePath, testPreviousTransactionID, "1.0.0")
	transaction := testSetupTransactionForRoots("install", installRoot, dataRoot, maintenancePath, &previous)
	writeInstallTree(t, installRoot, previous)
	writeInstallTree(t, transaction.StagingPath, testInstallState(
		installRoot,
		dataRoot,
		maintenancePath,
		transaction.ID,
		transaction.TargetVersion,
	))
	if err := os.MkdirAll(dataRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dataRoot, "config.yaml")
	configBefore := []byte("config_version: 7\nobservability: realistic-fixture\n")
	dataPath := filepath.Join(dataRoot, "runtime-state.bin")
	dataBefore := []byte{0, 1, 2, 3, 0xff}
	if err := os.WriteFile(configPath, configBefore, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dataPath, dataBefore, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(maintenancePath), 0o700); err != nil {
		t.Fatal(err)
	}
	maintenanceBefore := []byte("previous-maintenance-fixture")
	if err := os.WriteFile(maintenancePath, maintenanceBefore, 0o600); err != nil {
		t.Fatal(err)
	}
	transaction.MaintenanceExisted = true
	maintenanceDigest, err := fileSHA256(maintenancePath)
	if err != nil {
		t.Fatal(err)
	}
	transaction.PreviousMaintenanceSHA256 = maintenanceDigest

	for attempt := 0; attempt < 2; attempt++ {
		if err := abortPreparedSetupTransaction(transaction); err != nil {
			t.Fatalf("abort attempt %d: %v", attempt+1, err)
		}
	}
	assertPathAbsent(t, transaction.StagingPath)
	assertInstallVersion(t, installRoot, transaction, previous.Version)
	for path, want := range map[string][]byte{
		configPath:      configBefore,
		dataPath:        dataBefore,
		maintenancePath: maintenanceBefore,
	} {
		got, err := os.ReadFile(path)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("live fixture %s changed: %x, %v", filepath.Base(path), got, err)
		}
	}
}

func TestAbortPreparedSetupRefusesPublicationArtifactsWithoutMutation(t *testing.T) {
	installRoot, dataRoot, maintenancePath := testTransactionRoots(t)
	transaction := testSetupTransactionForRoots("install", installRoot, dataRoot, maintenancePath, nil)
	if err := os.MkdirAll(transaction.StagingPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(transaction.BackupPath, 0o700); err != nil {
		t.Fatal(err)
	}

	if err := abortPreparedSetupTransaction(transaction); err == nil {
		t.Fatal("prepared abort accepted an application publication artifact")
	}
	if !pathExists(transaction.StagingPath) || !pathExists(transaction.BackupPath) {
		t.Fatal("refused prepared abort mutated transaction artifacts")
	}
}

func TestReadSetupJournalSupportsLegacyIntentButRejectsLegacyQuiescing(t *testing.T) {
	installRoot, dataRoot, maintenancePath := testTransactionRoots(t)
	transaction := testSetupTransactionForRoots("install", installRoot, dataRoot, maintenancePath, nil)
	path := filepath.Join(t.TempDir(), "private", "setup-transaction.json")
	journal := setupJournal{
		SchemaVersion: setupJournalLegacySchemaVersion,
		Phase:         setupPhaseIntent,
		Transaction:   transaction,
	}
	if err := writeDurableJournal(path, journal, false); err != nil {
		t.Fatal(err)
	}
	loaded, err := readSetupJournal(path)
	if err != nil || loaded == nil || loaded.SchemaVersion != setupJournalLegacySchemaVersion {
		t.Fatalf("legacy intent journal = %+v, %v", loaded, err)
	}
	journal.Phase = setupPhaseQuiescing
	if err := writeDurableJournal(path, journal, true); err != nil {
		t.Fatal(err)
	}
	if _, err := readSetupJournal(path); err == nil {
		t.Fatal("legacy journal accepted the v2 quiescing phase")
	}
}

func TestInstallJournalPublishesOnlyAfterQuiescing(t *testing.T) {
	installRoot, dataRoot, maintenancePath := testTransactionRoots(t)
	transaction := testSetupTransactionForRoots("install", installRoot, dataRoot, maintenancePath, nil)
	path := filepath.Join(t.TempDir(), "private", "setup-transaction.json")
	if err := beginSetupTransactionAt(path, transaction); err != nil {
		t.Fatal(err)
	}
	if err := transitionSetupJournalAt(path, transaction, setupPhaseIntent, setupPhaseQuiescing); err != nil {
		t.Fatalf("enter quiescing: %v", err)
	}
	if err := transitionSetupJournalAt(path, transaction, setupPhaseIntent, setupPhasePublished); err == nil {
		t.Fatal("published journal bypassed durable quiescing phase")
	}
	if err := transitionSetupJournalAt(path, transaction, setupPhaseQuiescing, setupPhasePublished); err != nil {
		t.Fatalf("publish after quiescing: %v", err)
	}
}

func TestSetupTransactionCommitSourcePhaseKeepsUninstallOnIntent(t *testing.T) {
	tests := []struct {
		action string
		want   string
	}{
		{action: "install", want: setupPhasePublished},
		{action: "uninstall", want: setupPhaseIntent},
	}
	for _, test := range tests {
		t.Run(test.action, func(t *testing.T) {
			got, err := setupTransactionCommitSourcePhase(test.action)
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Fatalf("commit source phase = %q, want %q", got, test.want)
			}
		})
	}
	if _, err := setupTransactionCommitSourcePhase("repair"); err == nil {
		t.Fatal("commit source phase accepted an unsupported action")
	}
}

func TestRecoverPublishedMigrationRefusalRollsBackBeforeCompletingJournal(t *testing.T) {
	transaction := testSetupTransactionForRoots("install", "root", "data", "maintenance", nil)
	refusal := errors.New("candidate field=$.observability.destinations[0].protocol; reason=unsupported value")
	var calls []string
	err := recoverSetupJournalPhase(setupJournal{
		SchemaVersion: setupJournalSchemaVersion,
		Phase:         setupPhasePublished,
		Transaction:   transaction,
	}, setupRecoveryOps{
		Activate: func(setupTransaction) error {
			calls = append(calls, "activate")
			return refusal
		},
		Rollback: func(setupTransaction) error {
			calls = append(calls, "rollback-files-maintenance-services")
			return nil
		},
		Converge: func(setupTransaction) error {
			t.Fatal("published refusal reached committed convergence")
			return nil
		},
		Cleanup: func(setupTransaction) error { return nil },
		Transition: func(_ setupTransaction, from, to string) error {
			calls = append(calls, from+"->"+to)
			return nil
		},
	})
	if !errors.Is(err, refusal) {
		t.Fatalf("recovery error = %v, want migration refusal", err)
	}
	want := "activate,rollback-files-maintenance-services,published->complete"
	if got := strings.Join(calls, ","); got != want {
		t.Fatalf("published refusal calls = %q, want %q", got, want)
	}
}

func TestRecoverPublishedMigrationRollbackFailureKeepsJournalPublished(t *testing.T) {
	transaction := testSetupTransactionForRoots("install", "root", "data", "maintenance", nil)
	rollbackFailure := errors.New("injected post-publication rollback failure")
	transitioned := false
	err := recoverSetupJournalPhase(setupJournal{
		SchemaVersion: setupJournalSchemaVersion,
		Phase:         setupPhasePublished,
		Transaction:   transaction,
	}, setupRecoveryOps{
		Activate: func(setupTransaction) error { return errors.New("candidate refusal") },
		Rollback: func(setupTransaction) error { return rollbackFailure },
		Transition: func(setupTransaction, string, string) error {
			transitioned = true
			return nil
		},
	})
	if !errors.Is(err, rollbackFailure) || transitioned {
		t.Fatalf("recovery error = %v, transitioned = %v", err, transitioned)
	}
}

func TestRecoverPublishedMigrationStateChangeRetainsTargetRuntime(t *testing.T) {
	transaction := testSetupTransactionForRoots("install", "root", "data", "maintenance", nil)
	var calls []string
	err := recoverSetupJournalPhase(setupJournal{
		SchemaVersion: setupJournalSchemaVersion,
		Phase:         setupPhasePublished,
		Transaction:   transaction,
	}, setupRecoveryOps{
		Activate: func(setupTransaction) error {
			calls = append(calls, "activate")
			return errors.Join(errPublishedActivationStateChanged, errors.New("synthetic post-activation fault"))
		},
		Rollback: func(setupTransaction) error {
			calls = append(calls, "rollback")
			return nil
		},
		Transition: func(_ setupTransaction, from, to string) error {
			calls = append(calls, from+"->"+to)
			return nil
		},
	})
	if !errors.Is(err, errPublishedActivationStateChanged) {
		t.Fatalf("recovery error = %v, want migration-state-change sentinel", err)
	}
	if got, want := strings.Join(calls, ","), "activate"; got != want {
		t.Fatalf("state-change recovery calls = %q, want %q", got, want)
	}
}

func TestRecoverSetupJournalPhaseRetainsCommittedOnConvergenceFailure(t *testing.T) {
	transaction := testSetupTransactionForRoots("install", "root", "data", "maintenance", nil)
	transitioned := false
	err := recoverSetupJournalPhase(setupJournal{
		SchemaVersion: setupJournalSchemaVersion,
		Phase:         setupPhaseCommitted,
		Transaction:   transaction,
	}, setupRecoveryOps{
		Rollback: func(setupTransaction) error { return nil },
		Converge: func(setupTransaction) error { return errors.New("injected convergence crash") },
		Cleanup:  func(setupTransaction) error { return nil },
		Transition: func(setupTransaction, string, string) error {
			transitioned = true
			return nil
		},
	})
	if err == nil || transitioned {
		t.Fatalf("recovery error = %v, transitioned = %v", err, transitioned)
	}
}

func TestRecoverSetupJournalPhaseRetainsConvergedUninstallWhileRestartIsRequired(t *testing.T) {
	transaction := testSetupTransactionForRoots("uninstall", "root", "data", "maintenance", nil)
	cleanupCalls := 0
	transitioned := false
	ops := setupRecoveryOps{
		Rollback: func(setupTransaction) error { return nil },
		Converge: func(setupTransaction) error { return nil },
		Cleanup: func(setupTransaction) error {
			cleanupCalls++
			return errUninstallCleanupRequiresRestart
		},
		Transition: func(setupTransaction, string, string) error {
			transitioned = true
			return nil
		},
	}
	journal := setupJournal{
		SchemaVersion: setupJournalSchemaVersion,
		Phase:         setupPhaseConverged,
		Transaction:   transaction,
	}
	for attempt := 1; attempt <= 2; attempt++ {
		err := recoverSetupJournalPhase(journal, ops)
		if !errors.Is(err, errUninstallCleanupRequiresRestart) || transitioned {
			t.Fatalf("attempt %d recovery error = %v, transitioned = %v", attempt, err, transitioned)
		}
	}
	if cleanupCalls != 2 {
		t.Fatalf("same-boot recovery cleanup calls = %d, want 2", cleanupCalls)
	}
}

func TestRecoverSetupJournalPhaseCompletesPostExitCleanup(t *testing.T) {
	transaction := testSetupTransactionForRoots("uninstall", "root", "data", "maintenance", nil)
	transitioned := false
	err := recoverSetupJournalPhase(setupJournal{
		SchemaVersion: setupJournalSchemaVersion,
		Phase:         setupPhaseConverged,
		Transaction:   transaction,
	}, setupRecoveryOps{
		Rollback: func(setupTransaction) error { return nil },
		Converge: func(setupTransaction) error { return nil },
		Cleanup:  func(setupTransaction) error { return errTransactionCleanupDeferred },
		Transition: func(_ setupTransaction, from, to string) error {
			if from != setupPhaseConverged || to != setupPhaseComplete {
				t.Fatalf("transition = %s -> %s", from, to)
			}
			transitioned = true
			return nil
		},
	})
	if err != nil || !transitioned {
		t.Fatalf("recovery error = %v, transitioned = %v", err, transitioned)
	}
}

func TestFinishCommittedSetupTransactionReturns3010WithoutTerminalizing(t *testing.T) {
	transaction := testSetupTransactionForRoots("uninstall", "root", "data", "maintenance", nil)
	var calls []string
	restartRequired, err := finishCommittedSetupTransactionWith(
		transaction,
		func(setupTransaction) error {
			calls = append(calls, "converge")
			return nil
		},
		func(setupTransaction) error {
			calls = append(calls, "mark-converged")
			return nil
		},
		func(setupTransaction) error {
			calls = append(calls, "arm-cleanup")
			return errUninstallCleanupRequiresRestart
		},
		func(setupTransaction) error {
			calls = append(calls, "mark-complete")
			return nil
		},
	)
	if err != nil || !restartRequired {
		t.Fatalf("finish result = restart %v, error %v", restartRequired, err)
	}
	if got, want := strings.Join(calls, ","), "converge,mark-converged,arm-cleanup"; got != want {
		t.Fatalf("finish calls = %q, want %q", got, want)
	}
}

func TestDurableJournalAtomicallyReplacesPhase(t *testing.T) {
	installRoot, dataRoot, maintenancePath := testTransactionRoots(t)
	transaction := testSetupTransactionForRoots("install", installRoot, dataRoot, maintenancePath, nil)
	path := filepath.Join(t.TempDir(), "private", "setup-transaction.json")
	journal := setupJournal{SchemaVersion: setupJournalSchemaVersion, Phase: setupPhaseIntent, Transaction: transaction}
	if err := writeDurableJournal(path, journal, false); err != nil {
		t.Fatalf("write intent journal: %v", err)
	}
	journal.Phase = setupPhaseCommitted
	if err := writeDurableJournal(path, journal, true); err != nil {
		t.Fatalf("replace journal phase: %v", err)
	}
	loaded, err := readSetupJournal(path)
	if err != nil {
		t.Fatalf("read replaced journal: %v", err)
	}
	if loaded == nil || loaded.Phase != setupPhaseCommitted || !reflect.DeepEqual(loaded.Transaction, transaction) {
		t.Fatalf("loaded journal = %+v", loaded)
	}
}

func TestBeginAndCommitJournalNormalizesEmptyConnectorList(t *testing.T) {
	installRoot, dataRoot, maintenancePath := testTransactionRoots(t)
	transaction := testSetupTransactionForRoots("install", installRoot, dataRoot, maintenancePath, nil)
	transaction.PreviousConnectors = make([]string, 0, 2)
	path := filepath.Join(t.TempDir(), "private", "setup-transaction.json")

	if err := beginSetupTransactionAt(path, transaction); err != nil {
		t.Fatalf("begin setup transaction: %v", err)
	}
	loaded, err := readSetupJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded == nil || loaded.Transaction.PreviousConnectors != nil {
		t.Fatalf("journal connector representation = %#v, want normalized nil", loaded)
	}
	if err := transitionSetupJournalAt(path, transaction, setupPhaseIntent, setupPhaseQuiescing); err != nil {
		t.Fatalf("quiesce after JSON round trip: %v", err)
	}
	loaded, err = readSetupJournal(path)
	if err != nil || loaded == nil || loaded.Phase != setupPhaseQuiescing {
		t.Fatalf("quiescing journal = %#v, %v", loaded, err)
	}
}

func TestBeginJournalReportsAmbiguousLateRenameFailure(t *testing.T) {
	installRoot, dataRoot, maintenancePath := testTransactionRoots(t)
	transaction := testSetupTransactionForRoots("install", installRoot, dataRoot, maintenancePath, nil)
	path := filepath.Join(t.TempDir(), "private", "setup-transaction.json")
	lateFailure := errors.New("simulated write-through failure after publication")
	write := func(path string, value any, replace bool) error {
		return writeDurableValueWithRename(path, value, replace, func(source, destination string) error {
			if err := renameDurableFile(source, destination); err != nil {
				return err
			}
			return lateFailure
		})
	}

	err := beginSetupTransactionAtWithWriter(path, transaction, write)
	if !errors.Is(err, errSetupJournalDurabilityAmbiguous) {
		t.Fatalf("begin error = %v, want ambiguous durability", err)
	}
	loaded, readErr := readSetupJournal(path)
	if readErr != nil || loaded == nil || loaded.Phase != setupPhaseIntent {
		t.Fatalf("visible journal after late failure = %#v, %v", loaded, readErr)
	}
}

func TestCommitJournalReportsAmbiguousLateRenameFailure(t *testing.T) {
	installRoot, dataRoot, maintenancePath := testTransactionRoots(t)
	transaction := testSetupTransactionForRoots("install", installRoot, dataRoot, maintenancePath, nil)
	path := filepath.Join(t.TempDir(), "private", "setup-transaction.json")
	if err := beginSetupTransactionAt(path, transaction); err != nil {
		t.Fatal(err)
	}
	lateFailure := errors.New("simulated write-through failure after publication")
	write := func(path string, value any, replace bool) error {
		return writeDurableValueWithRename(path, value, replace, func(source, destination string) error {
			if err := replaceDurableFile(source, destination); err != nil {
				return err
			}
			return lateFailure
		})
	}

	err := transitionSetupJournalAtWithWriter(
		path,
		transaction,
		setupPhaseIntent,
		setupPhaseCommitted,
		write,
	)
	if !errors.Is(err, errSetupJournalDurabilityAmbiguous) {
		t.Fatalf("commit error = %v, want ambiguous durability", err)
	}
	loaded, readErr := readSetupJournal(path)
	if readErr != nil || loaded == nil || loaded.Phase != setupPhaseCommitted {
		t.Fatalf("visible journal after late failure = %#v, %v", loaded, readErr)
	}
}

func TestTeardownSupersededConnectorsSwitchesConnector(t *testing.T) {
	transaction := setupTransaction{
		DataRoot:           `C:\Users\tester\.defenseclaw`,
		PreviousConnectors: []string{"codex"},
		TargetConnector:    "claudecode",
	}
	var calls []string
	run := func(_, _, connector, action string, _ []string) error {
		calls = append(calls, connector+":"+action)
		return nil
	}
	if err := teardownSupersededConnectors(transaction, `C:\DefenseClaw\gateway.exe`, nil, run); err != nil {
		t.Fatal(err)
	}
	want := []string{"codex:teardown", "codex:verify"}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("connector switch calls = %v, want %v", calls, want)
	}
}

func TestTeardownSupersededConnectorsOptOutRemovesEveryPreviousConnector(t *testing.T) {
	transaction := setupTransaction{
		DataRoot:           `C:\Users\tester\.defenseclaw`,
		PreviousConnectors: []string{"codex", "claudecode", "cursor", "windsurf", "opencode"},
		TargetConnector:    "none",
	}
	var calls []string
	run := func(_, _, connector, action string, _ []string) error {
		calls = append(calls, connector+":"+action)
		return nil
	}
	if err := teardownSupersededConnectors(transaction, `C:\DefenseClaw\gateway.exe`, nil, run); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"codex:teardown", "codex:verify",
		"claudecode:teardown", "claudecode:verify",
		"cursor:teardown", "cursor:verify",
		"windsurf:teardown", "windsurf:verify",
		"opencode:teardown", "opencode:verify",
	}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("connector opt-out calls = %v, want %v", calls, want)
	}
}

func TestTeardownSupersededOpenCodeUsesRecordedPreviousHome(t *testing.T) {
	transaction := setupTransaction{
		DataRoot:                  `C:\Users\tester\.defenseclaw`,
		PreviousConnectors:        []string{"opencode"},
		TargetConnector:           "opencode",
		PreviousOpenCodeConfigDir: `C:\Users\tester\opencode-a`,
		OpenCodeConfigDir:         `C:\Users\tester\opencode-b`,
		PreviousCodexHome:         `C:\Users\tester\codex`,
		PreviousClaudeConfigDir:   `C:\Users\tester\claude`,
	}
	var calls []string
	run := func(_, _, connector, action string, env []string) error {
		calls = append(calls, connector+":"+action+":"+envValue(env, "OPENCODE_CONFIG_DIR"))
		return nil
	}

	if err := teardownSupersededConnectors(
		transaction,
		`C:\DefenseClaw\gateway.exe`,
		transactionPreviousChildEnv(transaction),
		run,
	); err != nil {
		t.Fatal(err)
	}
	want := []string{
		`opencode:teardown:C:\Users\tester\opencode-a`,
		`opencode:verify:C:\Users\tester\opencode-a`,
	}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("OpenCode home migration calls = %v, want %v", calls, want)
	}
}

func TestTeardownSupersededConnectorsRetainsSelectedConnector(t *testing.T) {
	transaction := setupTransaction{
		DataRoot:           `C:\Users\tester\.defenseclaw`,
		PreviousConnectors: []string{"codex"},
		TargetConnector:    "codex",
	}
	run := func(_, _, connector, action string, _ []string) error {
		return fmt.Errorf("unexpected %s %s", connector, action)
	}
	if err := teardownSupersededConnectors(transaction, `C:\DefenseClaw\gateway.exe`, nil, run); err != nil {
		t.Fatal(err)
	}
}

func TestTeardownSupersededConnectorsMovesSelectedConnectorToNewHome(t *testing.T) {
	transaction := setupTransaction{
		DataRoot:           `C:\Users\tester\.defenseclaw`,
		PreviousConnectors: []string{"codex"},
		TargetConnector:    "codex",
		PreviousCodexHome:  `C:\Users\tester\codex-a`,
		CodexHome:          `C:\Users\tester\codex-b`,
	}
	var calls []string
	run := func(_, _, connector, action string, env []string) error {
		calls = append(calls, connector+":"+action+":"+envValue(env, "CODEX_HOME"))
		return nil
	}
	previousEnv := transactionPreviousChildEnv(transaction)
	if err := teardownSupersededConnectors(
		transaction,
		`C:\DefenseClaw\gateway.exe`,
		previousEnv,
		run,
	); err != nil {
		t.Fatal(err)
	}
	want := []string{
		`codex:teardown:C:\Users\tester\codex-a`,
		`codex:verify:C:\Users\tester\codex-a`,
	}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("connector home migration calls = %v, want %v", calls, want)
	}
}

func TestTeardownSupersededCursorMovesSelectedConnectorToNewHome(t *testing.T) {
	transaction := setupTransaction{
		DataRoot:           `C:\Users\tester\.defenseclaw`,
		PreviousConnectors: []string{"cursor"},
		TargetConnector:    "cursor",
		PreviousCursorHome: `C:\Users\tester\cursor-a`,
		CursorHome:         `C:\Users\tester\cursor-b`,
	}
	var calls []string
	run := func(_, _, connector, action string, env []string) error {
		calls = append(calls, connector+":"+action+":"+envValue(env, "DEFENSECLAW_CURSOR_CONFIG_HOME"))
		return nil
	}
	if err := teardownSupersededConnectors(
		transaction,
		`C:\DefenseClaw\gateway.exe`,
		transactionPreviousChildEnv(transaction),
		run,
	); err != nil {
		t.Fatal(err)
	}
	want := []string{
		`cursor:teardown:C:\Users\tester\cursor-a`,
		`cursor:verify:C:\Users\tester\cursor-a`,
	}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("Cursor home migration calls = %v, want %v", calls, want)
	}
}

func TestTeardownSupersededWindsurfUsesExactPreviousProfile(t *testing.T) {
	transaction := setupTransaction{
		DataRoot:                 `C:\Users\tester\.defenseclaw`,
		PreviousConnectors:       []string{"windsurf"},
		TargetConnector:          "windsurf",
		PreviousWindsurfUserHome: `C:\Users\bound-profile`,
		WindsurfUserHome:         `C:\Users\new-profile`,
	}
	var calls []string
	run := func(_, _, connector, action string, env []string) error {
		calls = append(calls, connector+":"+action+":"+envValue(env, "WINDSURF_USER_HOME"))
		return nil
	}
	if err := teardownSupersededConnectors(
		transaction,
		`C:\DefenseClaw\gateway.exe`,
		transactionPreviousChildEnv(transaction),
		run,
	); err != nil {
		t.Fatal(err)
	}
	want := []string{
		`windsurf:teardown:C:\Users\bound-profile`,
		`windsurf:verify:C:\Users\bound-profile`,
	}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("Windsurf profile migration calls = %v, want %v", calls, want)
	}
}

func TestTransactionChildEnvReplacesAmbientWindsurfBindings(t *testing.T) {
	t.Setenv("WINDSURF_USER_HOME", `C:\Users\ambient-profile`)
	t.Setenv(
		"WINDSURF_HOOK_CONFIG_PATH",
		`C:\Users\ambient-profile\.codeium\windsurf\hooks.json`,
	)
	transaction := setupTransaction{
		DataRoot:         `C:\Users\tester\.defenseclaw`,
		WindsurfUserHome: `C:\Users\bound-profile`,
	}

	env := transactionChildEnv(transaction)
	if got := envValue(env, "WINDSURF_USER_HOME"); got != transaction.WindsurfUserHome {
		t.Fatalf("Windsurf user home = %q, want %q", got, transaction.WindsurfUserHome)
	}
	wantHooks := filepath.Join(
		transaction.WindsurfUserHome,
		".codeium",
		"windsurf",
		"hooks.json",
	)
	if got := envValue(env, "WINDSURF_HOOK_CONFIG_PATH"); got != wantHooks {
		t.Fatalf("Windsurf hooks path = %q, want %q", got, wantHooks)
	}
}

func TestInferManagedConnectorHomeUsesBoundTarget(t *testing.T) {
	dataRoot := t.TempDir()
	backupPath := filepath.Join(dataRoot, "connector_backups", "codex", "config.toml.json")
	if err := os.MkdirAll(filepath.Dir(backupPath), 0o755); err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(t.TempDir(), "codex-a")
	if err := os.WriteFile(
		backupPath,
		[]byte(fmt.Sprintf(`{"path":%q}`, filepath.Join(want, "config.toml"))),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	got, err := inferManagedConnectorHome(dataRoot, "codex", "config.toml", `C:\fallback`)
	if err != nil {
		t.Fatal(err)
	}
	if !samePath(got, want) {
		t.Fatalf("inferred managed connector home = %q, want %q", got, want)
	}
}

func TestInferManagedAntigravityHomeUsesLegacyRuntimeBackupBinding(t *testing.T) {
	dataRoot := t.TempDir()
	backupPath := filepath.Join(dataRoot, "connector_backups", "antigravity", "config.json")
	if err := os.MkdirAll(filepath.Dir(backupPath), 0o700); err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(t.TempDir(), "antigravity-custom-home")
	if err := os.WriteFile(
		backupPath,
		[]byte(fmt.Sprintf(`{"path":%q}`, filepath.Join(want, "hooks.json"))),
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	previous, err := connectorsForNativeUninstall(nil, dataRoot)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(previous, "antigravity") {
		t.Fatalf("legacy Antigravity backup was not discovered: %v", previous)
	}
	got, err := resolvePreviousConnectorHome(
		"",
		previous,
		dataRoot,
		"antigravity",
		"hooks.json",
		filepath.Join(t.TempDir(), "fallback"),
	)
	if err != nil {
		t.Fatal(err)
	}
	if !samePath(got, want) {
		t.Fatalf("resolved Antigravity home = %q, want legacy binding %q", got, want)
	}
}

func TestInferManagedOpenCodeHomeUsesPluginParent(t *testing.T) {
	dataRoot := t.TempDir()
	backupPath := filepath.Join(dataRoot, "connector_backups", "opencode", "config.json")
	if err := os.MkdirAll(filepath.Dir(backupPath), 0o700); err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(t.TempDir(), "opencode-a")
	target := filepath.Join(want, "plugins", "defenseclaw.js")
	if err := os.WriteFile(
		backupPath,
		[]byte(fmt.Sprintf(`{"path":%q}`, target)),
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	got, err := inferManagedConnectorHome(dataRoot, "opencode", "config", `C:\fallback`)
	if err != nil {
		t.Fatal(err)
	}
	if !samePath(got, want) {
		t.Fatalf("inferred managed OpenCode home = %q, want %q", got, want)
	}
}

func TestInferManagedOpenCodeHomeRejectsMalformedPluginTarget(t *testing.T) {
	for _, test := range []struct {
		name   string
		target func(string) string
	}{
		{
			name: "wrong plugin filename",
			target: func(home string) string {
				return filepath.Join(home, "plugins", "operator.js")
			},
		},
		{
			name: "missing plugins directory",
			target: func(home string) string {
				return filepath.Join(home, "defenseclaw.js")
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			dataRoot := t.TempDir()
			backupPath := filepath.Join(dataRoot, "connector_backups", "opencode", "config.json")
			if err := os.MkdirAll(filepath.Dir(backupPath), 0o700); err != nil {
				t.Fatal(err)
			}
			target := test.target(filepath.Join(t.TempDir(), "opencode"))
			if err := os.WriteFile(
				backupPath,
				[]byte(fmt.Sprintf(`{"path":%q}`, target)),
				0o600,
			); err != nil {
				t.Fatal(err)
			}

			_, err := inferManagedConnectorHome(dataRoot, "opencode", "config", filepath.Join(t.TempDir(), "fallback"))
			if err == nil || !strings.Contains(err.Error(), "invalid plugin target path") {
				t.Fatalf("malformed OpenCode backup error = %v", err)
			}
		})
	}
}

func TestResolvePreviousConnectorHomeUsesBackupBindingWithoutInstallState(t *testing.T) {
	for _, test := range []struct {
		connector, logicalName, legacyBackup string
	}{
		{"codex", "config.toml", "codex_config_backup.json"},
		{"claudecode", "settings.json", "claudecode_backup.json"},
		{"copilot", "config", ""},
		{"cursor", "hooks.json", ""},
	} {
		t.Run(test.connector, func(t *testing.T) {
			dataRoot := t.TempDir()
			if test.legacyBackup != "" {
				if err := os.WriteFile(filepath.Join(dataRoot, test.legacyBackup), []byte(`{}`), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			managedBackup := filepath.Join(
				dataRoot, "connector_backups", test.connector, test.logicalName+".json",
			)
			if err := os.MkdirAll(filepath.Dir(managedBackup), 0o700); err != nil {
				t.Fatal(err)
			}
			want := filepath.Join(t.TempDir(), test.connector+"-custom-home")
			target := filepath.Join(want, test.logicalName)
			if test.connector == "copilot" {
				target = filepath.Join(want, "hooks", "defenseclaw.json")
			}
			if err := os.WriteFile(
				managedBackup,
				[]byte(fmt.Sprintf(`{"path":%q}`, target)),
				0o600,
			); err != nil {
				t.Fatal(err)
			}
			previous, err := connectorsForNativeUninstall(nil, dataRoot)
			if err != nil {
				t.Fatal(err)
			}
			got, err := resolvePreviousConnectorHome(
				"", previous, dataRoot, test.connector, test.logicalName, `C:\fallback`,
			)
			if err != nil {
				t.Fatal(err)
			}
			if !samePath(got, want) {
				t.Fatalf("resolved previous connector home = %q, want %q", got, want)
			}
		})
	}
}

func TestResolvePreviousConnectorHomePrefersManagedBindingOverInstallState(t *testing.T) {
	dataRoot := t.TempDir()
	backupPath := filepath.Join(dataRoot, "connector_backups", "codex", "config.toml.json")
	if err := os.MkdirAll(filepath.Dir(backupPath), 0o700); err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(t.TempDir(), "cli-configured-codex-home")
	if err := os.WriteFile(
		backupPath,
		[]byte(fmt.Sprintf(`{"path":%q}`, filepath.Join(want, "config.toml"))),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	staleInstallStateHome := filepath.Join(t.TempDir(), "installer-default-codex-home")
	got, err := resolvePreviousConnectorHome(
		staleInstallStateHome,
		[]string{"codex"},
		dataRoot,
		"codex",
		"config.toml",
		filepath.Join(t.TempDir(), "fallback-codex-home"),
	)
	if err != nil {
		t.Fatal(err)
	}
	if !samePath(got, want) {
		t.Fatalf("resolved previous connector home = %q, want managed binding %q", got, want)
	}
}

func TestResolvePreviousWindsurfUserHomeUsesExactManagedProfileBinding(t *testing.T) {
	dataRoot := t.TempDir()
	bindingPath := filepath.Join(dataRoot, "connector_backups", "windsurf", "config.json")
	if err := os.MkdirAll(filepath.Dir(bindingPath), 0o700); err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(t.TempDir(), "bound-windsurf-profile")
	if err := os.WriteFile(
		bindingPath,
		[]byte(fmt.Sprintf(`{"path":%q}`, filepath.Join(want, ".codeium", "windsurf", "hooks.json"))),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	got, err := resolvePreviousWindsurfUserHome(
		filepath.Join(t.TempDir(), "stale-profile"),
		[]string{"windsurf"},
		dataRoot,
		filepath.Join(t.TempDir(), "ambient-profile"),
	)
	if err != nil {
		t.Fatal(err)
	}
	if !samePath(got, want) {
		t.Fatalf("resolved Windsurf user home = %q, want managed binding %q", got, want)
	}
}

func TestResolvePreviousWindsurfUserHomeRejectsUnboundManagedProfile(t *testing.T) {
	dataRoot := t.TempDir()
	ambient := filepath.Join(t.TempDir(), "ambient-profile")
	_, err := resolvePreviousWindsurfUserHome(
		"",
		[]string{"windsurf"},
		dataRoot,
		ambient,
	)
	if err == nil || !strings.Contains(err.Error(), "no bound user profile was persisted") {
		t.Fatalf("error = %v, want refusal to guess ambient profile %q", err, ambient)
	}
}

func TestResolvePreviousWindsurfUserHomeRejectsBindingOutsideVendorConfig(t *testing.T) {
	dataRoot := t.TempDir()
	bindingPath := filepath.Join(dataRoot, "connector_backups", "windsurf", "config.json")
	if err := os.MkdirAll(filepath.Dir(bindingPath), 0o700); err != nil {
		t.Fatal(err)
	}
	foreign := filepath.Join(t.TempDir(), "foreign", "hooks.json")
	if err := os.WriteFile(
		bindingPath,
		[]byte(fmt.Sprintf(`{"path":%q}`, foreign)),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	_, err := resolvePreviousWindsurfUserHome(
		"",
		[]string{"windsurf"},
		dataRoot,
		filepath.Join(t.TempDir(), "ambient-profile"),
	)
	if err == nil || !strings.Contains(err.Error(), "outside the bound user profile") {
		t.Fatalf("error = %v, want invalid vendor config path refusal", err)
	}
}

func TestLegacyConnectorHomesFollowExactValidatedOrManagedBindings(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows setup transaction connector-home resolution")
	}
	installRoot, dataRoot, maintenancePath := testTransactionRoots(t)
	if err := os.MkdirAll(dataRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"codex_config_backup.json", "claudecode_backup.json"} {
		if err := os.WriteFile(filepath.Join(dataRoot, name), []byte(`{}`), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(
		filepath.Join(dataRoot, "active_connector.json"),
		[]byte(`{"names":["copilot"]}`),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	clientRoot := filepath.Join(filepath.Dir(dataRoot), "client-homes")
	codexHome := filepath.Join(clientRoot, "codex")
	claudeHome := filepath.Join(clientRoot, "claude")
	copilotHome := filepath.Join(clientRoot, "copilot")
	cursorHome := filepath.Join(clientRoot, "cursor")
	antigravityHome := filepath.Join(clientRoot, ".gemini", "config")
	antigravityBackup := filepath.Join(dataRoot, "connector_backups", "antigravity", "hooks.json.json")
	if err := os.MkdirAll(filepath.Dir(antigravityBackup), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		antigravityBackup,
		[]byte(fmt.Sprintf(`{"path":%q}`, filepath.Join(antigravityHome, "hooks.json"))),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	openCodeHome := filepath.Join(clientRoot, "opencode")
	for _, path := range []string{codexHome, claudeHome, copilotHome, cursorHome, antigravityHome, openCodeHome} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	cursorBackupPath := filepath.Join(dataRoot, "connector_backups", "cursor", "hooks.json.json")
	if err := os.MkdirAll(filepath.Dir(cursorBackupPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		cursorBackupPath,
		[]byte(fmt.Sprintf(`{"path":%q}`, filepath.Join(cursorHome, "hooks.json"))),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	openCodeBackup := filepath.Join(dataRoot, "connector_backups", "opencode", "config.json")
	if err := os.MkdirAll(filepath.Dir(openCodeBackup), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		openCodeBackup,
		[]byte(fmt.Sprintf(
			`{"path":%q}`,
			filepath.Join(openCodeHome, "plugins", "defenseclaw.js"),
		)),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CODEX_HOME", codexHome)
	t.Setenv("CLAUDE_CONFIG_DIR", claudeHome)
	t.Setenv("COPILOT_HOME", copilotHome)
	t.Setenv("DEFENSECLAW_CURSOR_CONFIG_HOME", cursorHome)
	t.Setenv("ANTIGRAVITY_CONFIG_DIR", antigravityHome)
	t.Setenv("OPENCODE_CONFIG_DIR", openCodeHome)

	legacyState := testInstallState(
		installRoot,
		dataRoot,
		maintenancePath,
		testPreviousTransactionID,
		"0.8.0",
	)
	transaction, err := newSetupTransaction(
		"uninstall",
		installRoot,
		dataRoot,
		maintenancePath,
		"0.8.0",
		"0.8.6",
		&legacyState,
		options{Action: "uninstall", Connector: "none", Mode: "observe"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !samePath(transaction.PreviousCodexHome, codexHome) ||
		!samePath(transaction.PreviousClaudeConfigDir, claudeHome) ||
		!samePath(transaction.PreviousCopilotHome, copilotHome) ||
		!samePath(transaction.PreviousCursorHome, cursorHome) ||
		!samePath(transaction.PreviousAntigravityConfigDir, antigravityHome) ||
		!samePath(transaction.PreviousOpenCodeConfigDir, openCodeHome) {
		t.Fatalf(
			"legacy transaction homes = (%q, %q, %q, %q, %q, %q), want (%q, %q, %q, %q, %q, %q)",
			transaction.PreviousCodexHome,
			transaction.PreviousClaudeConfigDir,
			transaction.PreviousCopilotHome,
			transaction.PreviousCursorHome,
			transaction.PreviousAntigravityConfigDir,
			transaction.PreviousOpenCodeConfigDir,
			codexHome,
			claudeHome,
			copilotHome,
			cursorHome,
			antigravityHome,
			openCodeHome,
		)
	}

	source := transaction
	source.Action = "install"
	source.ID = testCurrentTransactionID
	source.CodexHome = codexHome
	source.ClaudeConfigDir = claudeHome
	source.CopilotHome = copilotHome
	source.CursorHome = cursorHome
	source.AntigravityConfigDir = antigravityHome
	source.OpenCodeConfigDir = openCodeHome
	source.UninstallHandoffHookStatus = stableHookSnapshotInactive
	handoff, err := newUninstallHandoffTransaction(
		source,
		&legacyState,
		options{Action: "uninstall", Connector: "none", Mode: "observe"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !samePath(handoff.PreviousCodexHome, codexHome) ||
		!samePath(handoff.PreviousClaudeConfigDir, claudeHome) ||
		!samePath(handoff.PreviousCopilotHome, copilotHome) ||
		!samePath(handoff.PreviousCursorHome, cursorHome) ||
		!samePath(handoff.PreviousAntigravityConfigDir, antigravityHome) ||
		!samePath(handoff.PreviousOpenCodeConfigDir, openCodeHome) {
		t.Fatalf(
			"legacy handoff homes = (%q, %q, %q, %q, %q, %q), want (%q, %q, %q, %q, %q, %q)",
			handoff.PreviousCodexHome,
			handoff.PreviousClaudeConfigDir,
			handoff.PreviousCopilotHome,
			handoff.PreviousCursorHome,
			handoff.PreviousAntigravityConfigDir,
			handoff.PreviousOpenCodeConfigDir,
			codexHome,
			claudeHome,
			copilotHome,
			cursorHome,
			antigravityHome,
			openCodeHome,
		)
	}
	if handoff.PreviousStableHookStatus != stableHookSnapshotInactive {
		t.Fatalf("handoff stable-hook posture = %q", handoff.PreviousStableHookStatus)
	}
}

func TestHermesManagedHomeSurvivesRepairEnvironmentDriftAndHandoff(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows setup transaction connector-home resolution")
	}
	installRoot, dataRoot, maintenancePath := testTransactionRoots(t)
	managedHome := filepath.Join(filepath.Dir(dataRoot), "AppData", "Local", "Hermes Managed")
	ambientHome := filepath.Join(filepath.Dir(dataRoot), "ambient-hermes")
	backupPath := filepath.Join(dataRoot, "connector_backups", "hermes", "config.yaml.json")
	if err := os.MkdirAll(filepath.Dir(backupPath), 0o700); err != nil {
		t.Fatal(err)
	}
	binding := fmt.Sprintf(`{"path":%q}`, filepath.Join(managedHome, "config.yaml"))
	if err := os.WriteFile(backupPath, []byte(binding), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(ambientHome, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HERMES_HOME", ambientHome)

	previous := testInstallState(
		installRoot,
		dataRoot,
		maintenancePath,
		testPreviousTransactionID,
		"0.8.6",
	)
	previous.HermesHome = filepath.Join(filepath.Dir(dataRoot), "stale-hermes-state")
	transaction, err := newSetupTransaction(
		"install",
		installRoot,
		dataRoot,
		maintenancePath,
		"0.8.6",
		"0.8.7",
		&previous,
		options{
			Action:                         "repair",
			Connector:                      "none",
			Mode:                           "observe",
			PreserveConnectorConfiguration: true,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !samePath(transaction.PreviousHermesHome, managedHome) ||
		!samePath(transaction.HermesHome, managedHome) {
		t.Fatalf(
			"Hermes repair homes = (%q, %q), want managed binding %q",
			transaction.PreviousHermesHome,
			transaction.HermesHome,
			managedHome,
		)
	}
	if got := envValue(transactionChildEnv(transaction), "HERMES_HOME"); !samePath(got, managedHome) {
		t.Fatalf("Hermes repair child env = %q, want %q", got, managedHome)
	}

	transaction.UninstallHandoffHookStatus = stableHookSnapshotInactive
	handoff, err := newUninstallHandoffTransaction(
		transaction,
		&previous,
		options{Action: "uninstall", Connector: "none", Mode: "observe"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !samePath(handoff.PreviousHermesHome, managedHome) ||
		!samePath(handoff.HermesHome, managedHome) {
		t.Fatalf(
			"Hermes handoff homes = (%q, %q), want managed binding %q",
			handoff.PreviousHermesHome,
			handoff.HermesHome,
			managedHome,
		)
	}
}

func TestFreshAntigravityUsesOfficialHomeAndScrubsInventedEnvironment(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows setup transaction connector-home resolution")
	}
	installRoot, dataRoot, maintenancePath := testTransactionRoots(t)
	t.Setenv("ANTIGRAVITY_CONFIG_DIR", filepath.Join(filepath.Dir(dataRoot), "vendor-decoy"))
	t.Setenv("GEMINI_CONFIG_DIR", filepath.Join(filepath.Dir(dataRoot), "gemini-decoy"))

	transaction, err := newSetupTransaction(
		"install",
		installRoot,
		dataRoot,
		maintenancePath,
		"",
		"0.8.7",
		nil,
		options{
			Action:       "install",
			Connector:    "antigravity",
			ConnectorSet: true,
			Mode:         "observe",
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	officialHome, err := defaultConnectorConfigHome(filepath.Join(".gemini", "config"))
	if err != nil {
		t.Fatal(err)
	}
	if !samePath(transaction.AntigravityConfigDir, officialHome) {
		t.Fatalf("fresh Antigravity home = %q, want official %q", transaction.AntigravityConfigDir, officialHome)
	}
	childEnv := transactionChildEnv(transaction)
	if got := envValue(childEnv, "DEFENSECLAW_ANTIGRAVITY_CONFIG_HOME"); !samePath(got, officialHome) {
		t.Fatalf("internal Antigravity custody home = %q, want %q", got, officialHome)
	}
	for _, forbidden := range []string{"ANTIGRAVITY_CONFIG_DIR", "GEMINI_CONFIG_DIR"} {
		if got := envValue(childEnv, forbidden); got != "" {
			t.Fatalf("%s survived in child environment as %q", forbidden, got)
		}
	}
}

func TestFreshCursorIgnoresAmbientConfigHome(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows setup transaction connector-home resolution")
	}
	installRoot, dataRoot, maintenancePath := testTransactionRoots(t)
	ambient := filepath.Join(filepath.Dir(dataRoot), "ambient-cursor")
	t.Setenv("DEFENSECLAW_CURSOR_CONFIG_HOME", ambient)

	transaction, err := newSetupTransaction(
		"install",
		installRoot,
		dataRoot,
		maintenancePath,
		"",
		"0.8.7",
		nil,
		// Home binding is resolved for every fresh transaction. Use the
		// connector-none path so this unit test does not inspect or mutate a
		// developer machine's existing gateway startup registration.
		options{Action: "install", Connector: "none", ConnectorSet: true, Mode: "observe"},
	)
	if err != nil {
		t.Fatal(err)
	}
	official, err := defaultConnectorConfigHome(".cursor")
	if err != nil {
		t.Fatal(err)
	}
	if !samePath(transaction.CursorHome, official) || samePath(transaction.CursorHome, ambient) {
		t.Fatalf("fresh Cursor home=%q, want official %q and not ambient %q", transaction.CursorHome, official, ambient)
	}
	if got := envValue(transactionChildEnv(transaction), "DEFENSECLAW_CURSOR_CONFIG_HOME"); !samePath(got, official) {
		t.Fatalf("authenticated Cursor custody env=%q, want %q", got, official)
	}
}

func TestModeOnlyMaintenanceMigratesCustomAntigravityHomeToOfficialPath(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows setup transaction connector-home resolution")
	}
	installRoot, dataRoot, maintenancePath := testTransactionRoots(t)
	managedHome := filepath.Join(filepath.Dir(dataRoot), "Antigravity Managed")
	ambientHome := filepath.Join(filepath.Dir(dataRoot), "ambient-antigravity")
	backupPath := filepath.Join(dataRoot, "connector_backups", "antigravity", "hooks.json.json")
	if err := os.MkdirAll(filepath.Dir(backupPath), 0o700); err != nil {
		t.Fatal(err)
	}
	binding := fmt.Sprintf(`{"path":%q}`, filepath.Join(managedHome, "hooks.json"))
	if err := os.WriteFile(backupPath, []byte(binding), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(ambientHome, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ANTIGRAVITY_CONFIG_DIR", ambientHome)
	t.Setenv("GEMINI_CONFIG_DIR", filepath.Join(filepath.Dir(dataRoot), "ambient-gemini"))

	previous := testInstallState(
		installRoot,
		dataRoot,
		maintenancePath,
		testPreviousTransactionID,
		"0.8.6",
	)
	previous.Connector = "antigravity"
	previous.AntigravityConfigDir = filepath.Join(filepath.Dir(dataRoot), "stale-antigravity-state")
	transaction, err := newSetupTransaction(
		"install",
		installRoot,
		dataRoot,
		maintenancePath,
		"0.8.6",
		"0.8.7",
		&previous,
		options{
			Action:       "upgrade",
			Connector:    "antigravity",
			Mode:         "action",
			ModeSet:      true,
			ConnectorSet: false,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if transaction.TargetMode != "action" {
		t.Fatalf("mode-only maintenance target mode = %q, want action", transaction.TargetMode)
	}
	officialHome, err := defaultConnectorConfigHome(filepath.Join(".gemini", "config"))
	if err != nil {
		t.Fatal(err)
	}
	if !samePath(transaction.PreviousAntigravityConfigDir, managedHome) ||
		!samePath(transaction.AntigravityConfigDir, officialHome) {
		t.Fatalf(
			"Antigravity mode-only maintenance homes = (%q, %q), want previous %q and official %q",
			transaction.PreviousAntigravityConfigDir,
			transaction.AntigravityConfigDir,
			managedHome,
			officialHome,
		)
	}
	if got := envValue(transactionPreviousChildEnv(transaction), "DEFENSECLAW_ANTIGRAVITY_CONFIG_HOME"); !samePath(got, managedHome) {
		t.Fatalf("previous Antigravity custody binding = %q, want %q", got, managedHome)
	}
	childEnv := transactionChildEnv(transaction)
	if got := envValue(childEnv, "DEFENSECLAW_ANTIGRAVITY_CONFIG_HOME"); !samePath(got, officialHome) {
		t.Fatalf("current Antigravity custody binding = %q, want %q", got, officialHome)
	}
	for _, forbidden := range []string{"ANTIGRAVITY_CONFIG_DIR", "GEMINI_CONFIG_DIR"} {
		if got := envValue(childEnv, forbidden); got != "" {
			t.Fatalf("%s survived in child environment as %q", forbidden, got)
		}
	}
}

func TestOpenCodeManagedHomeSurvivesRepairEnvironmentDriftAndHandoff(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows setup transaction connector-home resolution")
	}
	installRoot, dataRoot, maintenancePath := testTransactionRoots(t)
	managedHome := filepath.Join(filepath.Dir(dataRoot), "OpenCode Managed")
	ambientHome := filepath.Join(filepath.Dir(dataRoot), "ambient-opencode")
	backupPath := filepath.Join(dataRoot, "connector_backups", "opencode", "config.json")
	if err := os.MkdirAll(filepath.Dir(backupPath), 0o700); err != nil {
		t.Fatal(err)
	}
	binding := fmt.Sprintf(
		`{"path":%q}`,
		filepath.Join(managedHome, "plugins", "defenseclaw.js"),
	)
	if err := os.WriteFile(backupPath, []byte(binding), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(ambientHome, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OPENCODE_CONFIG_DIR", ambientHome)

	previous := testInstallState(
		installRoot,
		dataRoot,
		maintenancePath,
		testPreviousTransactionID,
		"0.8.6",
	)
	previous.OpenCodeConfigDir = filepath.Join(filepath.Dir(dataRoot), "stale-opencode-state")
	transaction, err := newSetupTransaction(
		"install",
		installRoot,
		dataRoot,
		maintenancePath,
		"0.8.6",
		"0.8.7",
		&previous,
		options{
			Action:                         "repair",
			Connector:                      "none",
			Mode:                           "observe",
			PreserveConnectorConfiguration: true,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !samePath(transaction.PreviousOpenCodeConfigDir, managedHome) ||
		!samePath(transaction.OpenCodeConfigDir, managedHome) {
		t.Fatalf(
			"OpenCode repair homes = (%q, %q), want managed binding %q",
			transaction.PreviousOpenCodeConfigDir,
			transaction.OpenCodeConfigDir,
			managedHome,
		)
	}
	if got := envValue(transactionChildEnv(transaction), "OPENCODE_CONFIG_DIR"); !samePath(got, managedHome) {
		t.Fatalf("OpenCode repair child env = %q, want %q", got, managedHome)
	}

	transaction.UninstallHandoffHookStatus = stableHookSnapshotInactive
	handoff, err := newUninstallHandoffTransaction(
		transaction,
		&previous,
		options{Action: "uninstall", Connector: "none", Mode: "observe"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !samePath(handoff.PreviousOpenCodeConfigDir, managedHome) ||
		!samePath(handoff.OpenCodeConfigDir, managedHome) {
		t.Fatalf(
			"OpenCode handoff homes = (%q, %q), want managed binding %q",
			handoff.PreviousOpenCodeConfigDir,
			handoff.OpenCodeConfigDir,
			managedHome,
		)
	}
}

func envValue(env []string, name string) string {
	for _, entry := range env {
		key, value, ok := strings.Cut(entry, "=")
		if ok && strings.EqualFold(key, name) {
			return value
		}
	}
	return ""
}

func TestRecoverSetupTransactionAtPersistsCompleteTombstone(t *testing.T) {
	for _, phase := range []string{setupPhaseIntent, setupPhaseQuiescing, setupPhasePublished, setupPhaseCommitted, setupPhaseConverged} {
		t.Run(phase, func(t *testing.T) {
			installRoot, dataRoot, maintenancePath := testTransactionRoots(t)
			transaction := testSetupTransactionForRoots("install", installRoot, dataRoot, maintenancePath, nil)
			path := filepath.Join(t.TempDir(), "private", "setup-transaction.json")
			journal := setupJournal{SchemaVersion: setupJournalSchemaVersion, Phase: phase, Transaction: transaction}
			if err := writeDurableJournal(path, journal, false); err != nil {
				t.Fatal(err)
			}
			var effects int
			ops := setupRecoveryOps{
				Abort:    func(setupTransaction) error { effects++; return nil },
				Rollback: func(setupTransaction) error { effects++; return nil },
				Activate: func(setupTransaction) error { effects++; return nil },
				Converge: func(setupTransaction) error { effects++; return nil },
				Cleanup:  func(setupTransaction) error { effects++; return nil },
				Transition: func(want setupTransaction, from, to string) error {
					loaded, err := readSetupJournal(path)
					if err != nil {
						return err
					}
					if loaded == nil || loaded.Phase != from || !reflect.DeepEqual(loaded.Transaction, want) {
						return errors.New("unexpected journal transition source")
					}
					loaded.Phase = to
					return writeDurableJournal(path, *loaded, true)
				},
			}
			expected := setupTransactionExpectations{
				InstallRoot: installRoot, DataRoot: dataRoot, MaintenancePath: maintenancePath,
			}
			if err := recoverSetupTransactionAt(path, expected, ops); err != nil {
				t.Fatalf("recover: %v", err)
			}
			loaded, err := readSetupJournal(path)
			if err != nil || loaded == nil || loaded.Phase != setupPhaseComplete {
				t.Fatalf("journal after recovery = %+v, %v", loaded, err)
			}
			before := effects
			if err := recoverSetupTransactionAt(path, expected, ops); err != nil {
				t.Fatalf("repeat recovery: %v", err)
			}
			if effects != before {
				t.Fatalf("complete tombstone replayed effects: before=%d after=%d", before, effects)
			}
		})
	}
}

func TestLegacyStableHookSnapshotSurvivesRollbackRestoreRetry(t *testing.T) {
	installRoot, dataRoot, maintenancePath := testTransactionRoots(t)
	previous := testInstallState(
		installRoot,
		dataRoot,
		maintenancePath,
		testPreviousTransactionID,
		"1.0.0",
	)
	transaction := testSetupTransactionForRoots(
		"install",
		installRoot,
		dataRoot,
		maintenancePath,
		&previous,
	)
	transaction.PreviousStableHookStatus = ""
	path := filepath.Join(t.TempDir(), "private", "setup-transaction.json")
	journal := setupJournal{
		SchemaVersion: setupJournalSchemaVersion,
		Phase:         setupPhaseQuiescing,
		Transaction:   transaction,
	}
	if err := writeDurableJournal(path, journal, false); err != nil {
		t.Fatal(err)
	}

	snapshotCalls := 0
	upgraded, err := persistLegacyStableHookSnapshotAt(
		path,
		journal,
		func(gatewayPath, gotDataRoot string) (bool, error) {
			snapshotCalls++
			if gatewayPath != filepath.Join(installRoot, "bin", "defenseclaw-gateway.exe") ||
				gotDataRoot != dataRoot {
				t.Fatalf("snapshot roots = %q, %q", gatewayPath, gotDataRoot)
			}
			return true, nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if upgraded.Transaction.PreviousStableHookStatus != stableHookSnapshotActive {
		t.Fatalf("upgraded stable-hook posture = %q", upgraded.Transaction.PreviousStableHookStatus)
	}

	restoreErr := errors.New("injected stable-hook restore interruption")
	rollbackAttempts := 0
	ops := setupRecoveryOps{
		Rollback: func(got setupTransaction) error {
			rollbackAttempts++
			if got.PreviousStableHookStatus != stableHookSnapshotActive {
				t.Fatalf("rollback attempt %d posture = %q", rollbackAttempts, got.PreviousStableHookStatus)
			}
			if rollbackAttempts == 1 {
				return restoreErr
			}
			return nil
		},
		Transition: func(got setupTransaction, from, to string) error {
			return transitionSetupJournalAt(path, got, from, to)
		},
	}
	expected := setupTransactionExpectations{
		InstallRoot: installRoot, DataRoot: dataRoot, MaintenancePath: maintenancePath,
	}
	if err := recoverSetupTransactionAt(path, expected, ops); !errors.Is(err, restoreErr) {
		t.Fatalf("first recovery error = %v, want restore interruption", err)
	}
	loaded, err := readSetupJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded == nil || loaded.Phase != setupPhaseQuiescing ||
		loaded.Transaction.PreviousStableHookStatus != stableHookSnapshotActive {
		t.Fatalf("journal after interrupted restore = %+v", loaded)
	}

	if _, err := persistLegacyStableHookSnapshotAt(
		path,
		*loaded,
		func(string, string) (bool, error) {
			t.Fatal("retry re-snapshotted the now-disabled stable hook")
			return false, nil
		},
	); err != nil {
		t.Fatal(err)
	}
	if err := recoverSetupTransactionAt(path, expected, ops); err != nil {
		t.Fatalf("retry recovery: %v", err)
	}
	loaded, err = readSetupJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded == nil || loaded.Phase != setupPhaseComplete ||
		loaded.Transaction.PreviousStableHookStatus != stableHookSnapshotActive {
		t.Fatalf("journal after successful retry = %+v", loaded)
	}
	if snapshotCalls != 1 || rollbackAttempts != 2 {
		t.Fatalf("snapshot calls = %d, rollback attempts = %d", snapshotCalls, rollbackAttempts)
	}
}

func TestLegacyUninstallHookSnapshotSurvivesRollbackRestoreRetry(t *testing.T) {
	installRoot, dataRoot, maintenancePath := testTransactionRoots(t)
	previous := testInstallState(
		installRoot,
		dataRoot,
		maintenancePath,
		testPreviousTransactionID,
		"1.0.0",
	)
	transaction := testSetupTransactionForRoots(
		"uninstall",
		installRoot,
		dataRoot,
		maintenancePath,
		&previous,
	)
	transaction.PreviousStableHookStatus = ""
	path := filepath.Join(t.TempDir(), "private", "setup-transaction.json")
	journal := setupJournal{
		SchemaVersion: setupJournalSchemaVersion,
		Phase:         setupPhaseIntent,
		Transaction:   transaction,
	}
	if err := writeDurableJournal(path, journal, false); err != nil {
		t.Fatal(err)
	}

	snapshotCalls := 0
	upgraded, err := persistLegacyStableHookSnapshotAt(
		path,
		journal,
		func(string, string) (bool, error) {
			snapshotCalls++
			return true, nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if upgraded.Transaction.PreviousStableHookStatus != stableHookSnapshotActive {
		t.Fatalf("upgraded uninstall hook posture = %q", upgraded.Transaction.PreviousStableHookStatus)
	}

	restoreErr := errors.New("injected uninstall hook restore interruption")
	rollbackAttempts := 0
	ops := setupRecoveryOps{
		Rollback: func(got setupTransaction) error {
			rollbackAttempts++
			if got.PreviousStableHookStatus != stableHookSnapshotActive {
				t.Fatalf("rollback attempt %d posture = %q", rollbackAttempts, got.PreviousStableHookStatus)
			}
			if rollbackAttempts == 1 {
				return restoreErr
			}
			return nil
		},
		Transition: func(got setupTransaction, from, to string) error {
			return transitionSetupJournalAt(path, got, from, to)
		},
	}
	expected := setupTransactionExpectations{
		InstallRoot: installRoot, DataRoot: dataRoot, MaintenancePath: maintenancePath,
	}
	if err := recoverSetupTransactionAt(path, expected, ops); !errors.Is(err, restoreErr) {
		t.Fatalf("first uninstall recovery error = %v, want restore interruption", err)
	}
	loaded, err := readSetupJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded == nil || loaded.Phase != setupPhaseIntent ||
		loaded.Transaction.PreviousStableHookStatus != stableHookSnapshotActive {
		t.Fatalf("uninstall journal after interrupted restore = %+v", loaded)
	}
	if _, err := persistLegacyStableHookSnapshotAt(
		path,
		*loaded,
		func(string, string) (bool, error) {
			t.Fatal("uninstall retry re-snapshotted the now-disabled stable hook")
			return false, nil
		},
	); err != nil {
		t.Fatal(err)
	}
	if err := recoverSetupTransactionAt(path, expected, ops); err != nil {
		t.Fatalf("retry uninstall recovery: %v", err)
	}
	loaded, err = readSetupJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded == nil || loaded.Phase != setupPhaseComplete ||
		loaded.Transaction.PreviousStableHookStatus != stableHookSnapshotActive {
		t.Fatalf("uninstall journal after successful retry = %+v", loaded)
	}
	if snapshotCalls != 1 || rollbackAttempts != 2 {
		t.Fatalf("snapshot calls = %d, rollback attempts = %d", snapshotCalls, rollbackAttempts)
	}
}

func TestCleanupStalePayloadTempsKeepsUnrelatedEntries(t *testing.T) {
	root := filepath.Join(t.TempDir(), "InstallerTemp")
	stale := filepath.Join(root, ".DefenseClawSetup.stale", "payload")
	if err := os.MkdirAll(stale, 0o700); err != nil {
		t.Fatal(err)
	}
	unrelated := filepath.Join(root, "operator-note.txt")
	if err := os.WriteFile(unrelated, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cleanupStalePayloadTemps(root); err != nil {
		t.Fatal(err)
	}
	assertPathAbsent(t, filepath.Dir(stale))
	if !pathExists(unrelated) {
		t.Fatal("stale payload cleanup removed an unrelated entry")
	}
}

func TestPendingConnectorReconciliationQuiescesOwnedRuntimeBeforeJournalCompletes(t *testing.T) {
	t.Parallel()
	phase := setupPhaseCommitted
	var calls []string
	ops := installRuntimeConvergenceOps{
		disableStableHook: func(transactionID string) error {
			if transactionID != testCurrentTransactionID {
				t.Fatalf("stable hook transaction = %q", transactionID)
			}
			calls = append(calls, "hook:disable")
			return nil
		},
		configureAutoStart: func(_ string, enabled bool) (gatewayAutoStartSnapshot, bool, error) {
			calls = append(calls, fmt.Sprintf("autostart:%v", enabled))
			return gatewayAutoStartSnapshot{Existed: true, Value: "owned"}, true, nil
		},
		startServices: func(string, string, serviceState) (serviceState, error) {
			calls = append(calls, "start")
			return serviceState{}, nil
		},
		verifyServices: func(string, string, serviceState) error {
			calls = append(calls, "verify-running")
			return nil
		},
		stopServices: func(string, string) (serviceState, error) {
			calls = append(calls, "stop:gateway+watchdog")
			return serviceState{Gateway: true, Watchdog: true}, nil
		},
		verifyStopped: func(string, string) error {
			calls = append(calls, "verify-stopped")
			return nil
		},
	}
	err := recoverSetupJournalPhase(setupJournal{
		Phase:       setupPhaseCommitted,
		Transaction: setupTransaction{Action: "install"},
	}, setupRecoveryOps{
		Converge: func(setupTransaction) error {
			return convergeInstallRuntime(
				testCurrentTransactionID,
				true,
				`C:\DefenseClaw\defenseclaw-gateway.exe`,
				`C:\Users\test\.defenseclaw`,
				serviceState{Gateway: true, Watchdog: true},
				ops,
			)
		},
		Cleanup: func(setupTransaction) error { return nil },
		Transition: func(_ setupTransaction, from, to string) error {
			if phase != from {
				return fmt.Errorf("transition from %s while journal is %s", from, phase)
			}
			calls = append(calls, "journal:"+to)
			phase = to
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if phase != setupPhaseComplete {
		t.Fatalf("journal phase = %s, want %s", phase, setupPhaseComplete)
	}
	if got := strings.Join(calls, ","); got != "hook:disable,autostart:false,stop:gateway+watchdog,verify-stopped,journal:converged,journal:complete" {
		t.Fatalf("pending-reconciliation runtime calls = %q", got)
	}
}

func TestPendingConnectorReconciliationAttemptsEveryQuiesceBoundary(t *testing.T) {
	t.Parallel()
	hookErr := errors.New("disable stable hook")
	autoStartErr := errors.New("disable auto-start")
	stopErr := errors.New("stop runtime")
	verifyErr := errors.New("runtime remains active")
	var calls []string
	ops := installRuntimeConvergenceOps{
		disableStableHook: func(string) error {
			calls = append(calls, "hook:disable")
			return hookErr
		},
		configureAutoStart: func(_ string, enabled bool) (gatewayAutoStartSnapshot, bool, error) {
			if enabled {
				t.Fatal("pending reconciliation enabled auto-start")
			}
			calls = append(calls, "autostart:disable")
			return gatewayAutoStartSnapshot{}, false, autoStartErr
		},
		stopServices: func(string, string) (serviceState, error) {
			calls = append(calls, "runtime:stop")
			return serviceState{}, stopErr
		},
		verifyStopped: func(string, string) error {
			calls = append(calls, "runtime:verify-stopped")
			return verifyErr
		},
	}

	err := convergeInstallRuntime(
		testCurrentTransactionID,
		true,
		"gateway.exe",
		"data",
		serviceState{Gateway: true, Watchdog: true},
		ops,
	)
	for _, want := range []error{hookErr, autoStartErr, stopErr, verifyErr} {
		if !errors.Is(err, want) {
			t.Fatalf("quiesce error %v does not include %v", err, want)
		}
	}
	if got := strings.Join(calls, ","); got != "hook:disable,autostart:disable,runtime:stop,runtime:verify-stopped" {
		t.Fatalf("pending-reconciliation failure calls = %q", got)
	}
}

func TestConnectorReconciliationStateFailuresQuiesceRuntime(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name            string
		inMemoryPending bool
		persistErr      error
		summaryErr      error
	}{
		{name: "persist", persistErr: errors.New("persist failed")},
		{name: "summary", summaryErr: errors.New("summary failed")},
		{name: "in-memory", inMemoryPending: true},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var calls []string
			ops := installRuntimeConvergenceOps{
				disableStableHook: func(string) error {
					calls = append(calls, "hook:disable")
					return nil
				},
				configureAutoStart: func(string, bool) (gatewayAutoStartSnapshot, bool, error) {
					calls = append(calls, "autostart:disable")
					return gatewayAutoStartSnapshot{}, false, nil
				},
				stopServices: func(string, string) (serviceState, error) {
					calls = append(calls, "runtime:stop")
					return serviceState{}, nil
				},
				verifyStopped: func(string, string) error {
					calls = append(calls, "runtime:verify-stopped")
					return nil
				},
			}
			pending, err := settleInstallConnectorReconciliation(
				testCurrentTransactionID,
				"gateway.exe",
				"data",
				serviceState{Gateway: true},
				test.inMemoryPending,
				func() error { return test.persistErr },
				func() (string, error) { return "", test.summaryErr },
				ops,
			)
			if !pending {
				t.Fatal("unsafe reconciliation state was reported as ready for activation")
			}
			wantErr := test.persistErr
			if wantErr == nil {
				wantErr = test.summaryErr
			}
			if wantErr != nil && !errors.Is(err, wantErr) {
				t.Fatalf("settlement error = %v, want %v", err, wantErr)
			}
			if wantErr == nil && err != nil {
				t.Fatal(err)
			}
			if got := strings.Join(calls, ","); got != "hook:disable,autostart:disable,runtime:stop,runtime:verify-stopped" {
				t.Fatalf("fail-closed calls = %q", got)
			}
		})
	}
}

func TestConvergeInstallRuntimeActivatesOnlyAfterReconciliation(t *testing.T) {
	t.Parallel()
	var calls []string
	wanted := serviceState{Gateway: true, Watchdog: true}
	ops := installRuntimeConvergenceOps{
		disableStableHook: func(string) error {
			t.Fatal("successful reconciliation disabled the stable hook")
			return nil
		},
		configureAutoStart: func(gatewayPath string, enabled bool) (gatewayAutoStartSnapshot, bool, error) {
			if gatewayPath != "gateway.exe" || !enabled {
				t.Fatalf("configure auto-start arguments = %q, %v", gatewayPath, enabled)
			}
			calls = append(calls, "autostart")
			return gatewayAutoStartSnapshot{}, true, nil
		},
		startServices: func(gatewayPath, dataRoot string, got serviceState) (serviceState, error) {
			if gatewayPath != "gateway.exe" || dataRoot != "data" || got != wanted {
				t.Fatalf("start arguments = %q, %q, %+v", gatewayPath, dataRoot, got)
			}
			calls = append(calls, "start")
			return got, nil
		},
		verifyServices: func(gatewayPath, dataRoot string, got serviceState) error {
			if gatewayPath != "gateway.exe" || dataRoot != "data" || got != wanted {
				t.Fatalf("verify arguments = %q, %q, %+v", gatewayPath, dataRoot, got)
			}
			calls = append(calls, "verify")
			return nil
		},
		stopServices: func(string, string) (serviceState, error) {
			t.Fatal("successful reconciliation stopped services")
			return serviceState{}, nil
		},
		verifyStopped: func(string, string) error {
			t.Fatal("successful reconciliation verified stopped services")
			return nil
		},
	}
	if err := convergeInstallRuntime(testCurrentTransactionID, false, "gateway.exe", "data", wanted, ops); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(calls, ","); got != "autostart,start,verify" {
		t.Fatalf("runtime convergence calls = %q", got)
	}
}

func TestCanonicalReleaseStateInitializesBeforeValidation(t *testing.T) {
	t.Parallel()
	transaction := setupTransaction{
		InstallRoot:   "install",
		DataRoot:      "data",
		TargetVersion: "0.8.9",
	}
	var calls []string
	err := initializeCanonicalReleaseState(
		transaction,
		[]string{"MANAGED=1"},
		func(root, dataRoot string, env []string) error {
			if root != transaction.InstallRoot || dataRoot != transaction.DataRoot ||
				!slices.Equal(env, []string{"MANAGED=1"}) {
				t.Fatalf("initialize arguments = %q, %q, %v", root, dataRoot, env)
			}
			calls = append(calls, "canonical-base+migration-cursor")
			return nil
		},
		func(root, dataRoot, targetVersion string, env []string) error {
			if root != transaction.InstallRoot || dataRoot != transaction.DataRoot ||
				targetVersion != transaction.TargetVersion ||
				!slices.Equal(env, []string{"MANAGED=1"}) {
				t.Fatalf("validate arguments = %q, %q, %q, %v", root, dataRoot, targetVersion, env)
			}
			calls = append(calls, "validate-config+cursor")
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(calls, ","); got != "canonical-base+migration-cursor,validate-config+cursor" {
		t.Fatalf("canonical state ordering = %q", got)
	}
}

func TestCommittedRecoveryRetriesCanonicalReleaseStateIdempotently(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name               string
		failInitialization bool
	}{
		{name: "before-initialization", failInitialization: true},
		{name: "after-initialization"},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			phase := setupPhaseCommitted
			transaction := setupTransaction{
				Action:          "install",
				InstallRoot:     "install",
				DataRoot:        "data",
				TargetVersion:   "0.8.9",
				TargetConnector: "none",
				TargetServices:  serviceState{Gateway: true},
			}
			journal := setupJournal{
				SchemaVersion: setupJournalSchemaVersion,
				Phase:         setupPhaseCommitted,
				Transaction:   transaction,
			}
			injectedErr := errors.New("injected canonical-state failure")
			initializeCalls := 0
			validateCalls := 0
			converge := func(setupTransaction) error {
				return initializeCanonicalReleaseState(
					transaction,
					nil,
					func(string, string, []string) error {
						initializeCalls++
						if test.failInitialization && initializeCalls == 1 {
							return injectedErr
						}
						return nil
					},
					func(string, string, string, []string) error {
						validateCalls++
						if !test.failInitialization && validateCalls == 1 {
							return injectedErr
						}
						return nil
					},
				)
			}
			recoverOnce := func() error {
				return recoverSetupJournalPhase(journal, setupRecoveryOps{
					Converge: converge,
					Cleanup:  func(setupTransaction) error { return nil },
					Transition: func(_ setupTransaction, from, to string) error {
						if phase != from {
							return fmt.Errorf("transition from %s while phase is %s", from, phase)
						}
						phase = to
						journal.Phase = to
						return nil
					},
				})
			}
			if err := recoverOnce(); !errors.Is(err, injectedErr) {
				t.Fatalf("first recovery error = %v, want injected failure", err)
			}
			if phase != setupPhaseCommitted {
				t.Fatalf("failed recovery advanced journal to %q", phase)
			}
			if err := recoverOnce(); err != nil {
				t.Fatalf("second recovery: %v", err)
			}
			if phase != setupPhaseComplete || initializeCalls != 2 {
				t.Fatalf("recovery phase=%s initialize=%d validate=%d", phase, initializeCalls, validateCalls)
			}
			completedInitializeCalls, completedValidateCalls := initializeCalls, validateCalls
			if err := recoverOnce(); err != nil {
				t.Fatalf("completed recovery replay: %v", err)
			}
			if initializeCalls != completedInitializeCalls || validateCalls != completedValidateCalls {
				t.Fatalf(
					"completed rescue replayed initialization: initialize=%d validate=%d",
					initializeCalls,
					validateCalls,
				)
			}
		})
	}
}

func TestInstallMutationQuiescenceDrainsLateExactCodexHookAfterRevokingLaunches(t *testing.T) {
	t.Parallel()
	transaction := setupTransaction{ID: testCurrentTransactionID, InstallRoot: "install"}
	var calls []string
	hookActive := true
	lateHookRunning := true
	err := quiesceSetupRuntimeForMutation(
		transaction,
		"gateway.exe",
		"data",
		func(transactionID string) error {
			if transactionID != testCurrentTransactionID {
				t.Fatalf("disable transaction = %q", transactionID)
			}
			calls = append(calls, "hook:disable")
			hookActive = false
			return nil
		},
		func(installRoot, transactionID string) error {
			if hookActive {
				t.Fatal("hook child drain began before the stable launch gate was disabled")
			}
			if installRoot != "install" || transactionID != testCurrentTransactionID {
				t.Fatalf("drain identity = %q, %q", installRoot, transactionID)
			}
			calls = append(calls, "hook:drain-late-child")
			lateHookRunning = false
			return nil
		},
		func(gatewayPath, dataRoot string) (serviceState, error) {
			if hookActive || lateHookRunning {
				t.Fatal("runtime stop began before stable-hook quiescence completed")
			}
			if gatewayPath != "gateway.exe" || dataRoot != "data" {
				t.Fatalf("stop roots = %q, %q", gatewayPath, dataRoot)
			}
			calls = append(calls, "runtime:stop")
			return serviceState{Gateway: true, Watchdog: true}, nil
		},
		func(gatewayPath, dataRoot string) error {
			if hookActive {
				t.Fatal("runtime release was verified while stable-hook cold start remained authorized")
			}
			if gatewayPath != "gateway.exe" || dataRoot != "data" {
				t.Fatalf("verify roots = %q, %q", gatewayPath, dataRoot)
			}
			calls = append(calls, "runtime:verify-release")
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(calls, ","); got != "hook:disable,hook:drain-late-child,runtime:stop,runtime:verify-release" {
		t.Fatalf("quiescence calls = %q", got)
	}
}

func TestInstallMutationQuiescenceRefusesRuntimeStopWhenHookDisableFails(t *testing.T) {
	t.Parallel()
	disableErr := errors.New("stable hook state is locked")
	drainCalled := false
	stopCalled := false
	verifyCalled := false
	err := quiesceSetupRuntimeForMutation(
		setupTransaction{ID: testCurrentTransactionID},
		"gateway.exe",
		"data",
		func(string) error { return disableErr },
		func(string, string) error {
			drainCalled = true
			return nil
		},
		func(string, string) (serviceState, error) {
			stopCalled = true
			return serviceState{}, nil
		},
		func(string, string) error {
			verifyCalled = true
			return nil
		},
	)
	if !errors.Is(err, disableErr) || drainCalled || stopCalled || verifyCalled {
		t.Fatalf("quiescence result = %v, drain=%t stop=%t verify=%t", err, drainCalled, stopCalled, verifyCalled)
	}
}

func TestUninstallMutationRevokesHookBeforeRuntimeReleaseAndTreeRename(t *testing.T) {
	t.Parallel()
	transaction := setupTransaction{ID: testCurrentTransactionID, Action: "uninstall"}
	var calls []string
	hookActive := true
	err := mutateUninstallTreeWithQuiescedRuntime(
		transaction,
		"gateway.exe",
		"data",
		func(transactionID string) error {
			if transactionID != testCurrentTransactionID {
				t.Fatalf("disable transaction = %q", transactionID)
			}
			calls = append(calls, "hook:disable")
			hookActive = false
			return nil
		},
		func(installRoot, transactionID string) error {
			if installRoot != transaction.InstallRoot || transactionID != transaction.ID {
				t.Fatalf("uninstall drain identity = %q, %q", installRoot, transactionID)
			}
			calls = append(calls, "hook:drain")
			return nil
		},
		func(gatewayPath, dataRoot string) (serviceState, error) {
			if hookActive {
				t.Fatal("uninstall stopped services while stable-hook cold start remained authorized")
			}
			if gatewayPath != "gateway.exe" || dataRoot != "data" {
				t.Fatalf("stop roots = %q, %q", gatewayPath, dataRoot)
			}
			calls = append(calls, "runtime:stop")
			return serviceState{Gateway: true, Watchdog: true}, nil
		},
		func(gatewayPath, dataRoot string) error {
			if hookActive {
				t.Fatal("uninstall verified release while stable-hook cold start remained authorized")
			}
			if gatewayPath != "gateway.exe" || dataRoot != "data" {
				t.Fatalf("verify roots = %q, %q", gatewayPath, dataRoot)
			}
			calls = append(calls, "runtime:verify-release")
			return nil
		},
		func() error {
			if hookActive {
				t.Fatal("uninstall renamed the live tree while stable-hook cold start remained authorized")
			}
			calls = append(calls, "tree:rename")
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	want := "hook:disable,hook:drain,runtime:stop,runtime:verify-release,tree:rename"
	if got := strings.Join(calls, ","); got != want {
		t.Fatalf("uninstall mutation calls = %q, want %q", got, want)
	}
}

func TestRollbackRestoreIncludesOwnedRuntimeStartedAfterIntent(t *testing.T) {
	installRoot, dataRoot, maintenancePath := testTransactionRoots(t)
	previous := testInstallState(
		installRoot,
		dataRoot,
		maintenancePath,
		testPreviousTransactionID,
		"1.0.0",
	)
	transaction := testSetupTransactionForRoots(
		"install",
		installRoot,
		dataRoot,
		maintenancePath,
		&previous,
	)
	transaction.PreviousStableHookStatus = stableHookSnapshotActive
	transaction.PreviousServices = serviceState{}
	writeInstallTree(t, installRoot, previous)
	if err := os.WriteFile(
		filepath.Join(installRoot, "bin", "defenseclaw-gateway.exe"),
		[]byte("fixture"),
		0o644,
	); err != nil {
		t.Fatal(err)
	}

	liveDuringRecovery := serviceState{Gateway: true, Watchdog: true}
	var restored serviceState
	var restoreCalls []string
	err := rollbackSetupTransactionWithRuntime(
		transaction,
		func(string, string) error { return nil },
		func(gatewayPath, gotDataRoot string) (serviceState, error) {
			if gatewayPath != filepath.Join(installRoot, "bin", "defenseclaw-gateway.exe") || gotDataRoot != dataRoot {
				t.Fatalf("stop roots = %q, %q", gatewayPath, gotDataRoot)
			}
			return liveDuringRecovery, nil
		},
		func(string, string) error { return nil },
		func(setupTransaction) error {
			restoreCalls = append(restoreCalls, "hook")
			return nil
		},
		func(gatewayPath, gotDataRoot string, wanted serviceState) (serviceState, error) {
			restoreCalls = append(restoreCalls, "services")
			if gatewayPath != filepath.Join(installRoot, "bin", "defenseclaw-gateway.exe") || gotDataRoot != dataRoot {
				t.Fatalf("start roots = %q, %q", gatewayPath, gotDataRoot)
			}
			restored = wanted
			return wanted, nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if restored != liveDuringRecovery {
		t.Fatalf("rollback restored services = %+v, want %+v", restored, liveDuringRecovery)
	}
	if got := strings.Join(restoreCalls, ","); got != "hook,services" {
		t.Fatalf("rollback restore order = %q, want hook before services", got)
	}
}

func TestQuiescingRecoveryRestoresGatewayDespiteStaleClaudeReadiness(t *testing.T) {
	installRoot, dataRoot, maintenancePath := testTransactionRoots(t)
	previous := testInstallState(
		installRoot,
		dataRoot,
		maintenancePath,
		testPreviousTransactionID,
		"1.0.0",
	)
	transaction := testSetupTransactionForRoots(
		"install",
		installRoot,
		dataRoot,
		maintenancePath,
		&previous,
	)
	transaction.PreviousServices = serviceState{Gateway: true}
	transaction.PreviousStableHookStatus = stableHookSnapshotActive
	writeInstallTree(t, installRoot, previous)
	writeInstallTree(t, transaction.StagingPath, testInstallState(
		installRoot,
		dataRoot,
		maintenancePath,
		transaction.ID,
		transaction.TargetVersion,
	))

	savedClaudeVersion := "2.1.211"
	currentClaudeVersion := "2.1.220"
	connectorReady := savedClaudeVersion == currentClaudeVersion
	launched := serviceState{}
	phase := setupPhaseQuiescing
	err := recoverSetupJournalPhase(setupJournal{
		SchemaVersion: setupJournalSchemaVersion,
		Phase:         setupPhaseQuiescing,
		Transaction:   transaction,
	}, setupRecoveryOps{
		Rollback: func(got setupTransaction) error {
			return rollbackSetupTransactionWithRuntime(
				got,
				func(string, string) error { return nil },
				func(string, string) (serviceState, error) { return serviceState{}, nil },
				func(string, string) error { return nil },
				func(setupTransaction) error { return nil },
				func(_ string, _ string, wanted serviceState) (serviceState, error) {
					// Recovery owns readiness for the immediately following
					// transaction. A validated process launch is sufficient here;
					// the final target activation remains the strict readiness gate.
					if connectorReady {
						t.Fatal("fixture unexpectedly reported stale connector readiness")
					}
					launched = wanted
					return wanted, nil
				},
			)
		},
		Transition: func(_ setupTransaction, from, to string) error {
			if phase != from {
				return fmt.Errorf("journal phase = %q, want %q", phase, from)
			}
			phase = to
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if phase != setupPhaseComplete {
		t.Fatalf("journal phase = %q, want complete", phase)
	}
	if launched != (serviceState{Gateway: true}) {
		t.Fatalf("recovery launched services = %+v, want prior gateway intent", launched)
	}
	assertInstallVersion(t, installRoot, transaction, previous.Version)
	assertPathAbsent(t, transaction.StagingPath)
}

func TestUninstallRollbackRestoresHookBeforeServices(t *testing.T) {
	installRoot, dataRoot, maintenancePath := testTransactionRoots(t)
	previous := testInstallState(
		installRoot,
		dataRoot,
		maintenancePath,
		testPreviousTransactionID,
		"1.0.0",
	)
	transaction := testSetupTransactionForRoots(
		"uninstall",
		installRoot,
		dataRoot,
		maintenancePath,
		&previous,
	)
	transaction.PreviousStableHookStatus = stableHookSnapshotActive
	transaction.PreviousServices = serviceState{Gateway: true, Watchdog: true}
	writeInstallTree(t, transaction.TrashPath, previous)

	var calls []string
	err := rollbackSetupTransactionWithRuntime(
		transaction,
		func(string, string) error { return nil },
		func(string, string) (serviceState, error) {
			t.Fatal("uninstall trash rollback unexpectedly stopped a fixed-path runtime")
			return serviceState{}, nil
		},
		func(string, string) error {
			t.Fatal("uninstall trash rollback unexpectedly verified a fixed-path runtime")
			return nil
		},
		func(got setupTransaction) error {
			if got.PreviousStableHookStatus != stableHookSnapshotActive {
				t.Fatalf("restore posture = %q", got.PreviousStableHookStatus)
			}
			calls = append(calls, "hook")
			return nil
		},
		func(gatewayPath, gotDataRoot string, wanted serviceState) (serviceState, error) {
			if gatewayPath != filepath.Join(installRoot, "bin", "defenseclaw-gateway.exe") ||
				gotDataRoot != dataRoot || wanted != transaction.PreviousServices {
				t.Fatalf("restore services = %q, %q, %+v", gatewayPath, gotDataRoot, wanted)
			}
			calls = append(calls, "services")
			return wanted, nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(calls, ","); got != "hook,services" {
		t.Fatalf("uninstall rollback restore order = %q, want hook before services", got)
	}
	assertInstallVersion(t, installRoot, transaction, previous.Version)
	assertPathAbsent(t, transaction.TrashPath)
}

func TestUninstallRollbackPreservesInactiveHookPosture(t *testing.T) {
	installRoot, dataRoot, maintenancePath := testTransactionRoots(t)
	previous := testInstallState(
		installRoot,
		dataRoot,
		maintenancePath,
		testPreviousTransactionID,
		"1.0.0",
	)
	transaction := testSetupTransactionForRoots(
		"uninstall",
		installRoot,
		dataRoot,
		maintenancePath,
		&previous,
	)
	transaction.PreviousStableHookStatus = stableHookSnapshotInactive
	transaction.PreviousServices = serviceState{Gateway: true}
	writeInstallTree(t, transaction.TrashPath, previous)

	startCalled := false
	err := rollbackSetupTransactionWithRuntime(
		transaction,
		func(string, string) error { return nil },
		func(string, string) (serviceState, error) { return serviceState{}, nil },
		func(string, string) error { return nil },
		restorePreviousStableHookRuntime,
		func(string, string, serviceState) (serviceState, error) {
			startCalled = true
			return transaction.PreviousServices, nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !startCalled {
		t.Fatal("inactive hook posture prevented restoration of the previously running service")
	}
}

func TestRollbackDoesNotRestartServicesWhenStableHookRestoreFails(t *testing.T) {
	installRoot, dataRoot, maintenancePath := testTransactionRoots(t)
	previous := testInstallState(
		installRoot,
		dataRoot,
		maintenancePath,
		testPreviousTransactionID,
		"1.0.0",
	)
	transaction := testSetupTransactionForRoots(
		"install",
		installRoot,
		dataRoot,
		maintenancePath,
		&previous,
	)
	transaction.PreviousServices = serviceState{Gateway: true, Watchdog: true}
	writeInstallTree(t, installRoot, previous)
	restoreErr := errors.New("stable hook publication failed")
	startCalled := false
	err := rollbackSetupTransactionWithRuntime(
		transaction,
		func(string, string) error { return nil },
		func(string, string) (serviceState, error) { return serviceState{}, nil },
		func(string, string) error { return nil },
		func(setupTransaction) error { return restoreErr },
		func(string, string, serviceState) (serviceState, error) {
			startCalled = true
			return serviceState{}, nil
		},
	)
	if !errors.Is(err, restoreErr) || startCalled {
		t.Fatalf("rollback result = %v, services started=%t", err, startCalled)
	}
	assertInstallVersion(t, installRoot, transaction, previous.Version)
}

func TestRollbackRestoresOwnedRuntimeWhenFileRollbackFails(t *testing.T) {
	installRoot, dataRoot, maintenancePath := testTransactionRoots(t)
	previous := testInstallState(
		installRoot,
		dataRoot,
		maintenancePath,
		testPreviousTransactionID,
		"1.0.0",
	)
	transaction := testSetupTransactionForRoots(
		"install",
		installRoot,
		dataRoot,
		maintenancePath,
		&previous,
	)
	current := previous
	current.Version = "9.9.9"
	writeInstallTree(t, installRoot, current)
	if err := os.WriteFile(
		filepath.Join(installRoot, "bin", "defenseclaw-gateway.exe"),
		[]byte("fixture"),
		0o644,
	); err != nil {
		t.Fatal(err)
	}

	liveDuringRecovery := serviceState{Gateway: true, Watchdog: true}
	var restored serviceState
	restoreHookCalled := false
	err := rollbackSetupTransactionWithRuntime(
		transaction,
		func(string, string) error { return nil },
		func(string, string) (serviceState, error) { return liveDuringRecovery, nil },
		func(string, string) error { return nil },
		func(setupTransaction) error {
			restoreHookCalled = true
			return nil
		},
		func(_ string, _ string, wanted serviceState) (serviceState, error) {
			restored = wanted
			return wanted, nil
		},
	)

	if err == nil || !strings.Contains(err.Error(), "previous installation is missing") {
		t.Fatalf("rollback error = %v, want recorded-state mismatch", err)
	}
	if restored != liveDuringRecovery {
		t.Fatalf("rollback restored services = %+v, want %+v", restored, liveDuringRecovery)
	}
	if restoreHookCalled {
		t.Fatal("failed file rollback reactivated a stable hook against an uncommitted runtime tree")
	}
}

func TestRollbackRestoresStoppedFreshRuntimeWhenFileRollbackFails(t *testing.T) {
	installRoot, dataRoot, maintenancePath := testTransactionRoots(t)
	transaction := testSetupTransactionForRoots(
		"install",
		installRoot,
		dataRoot,
		maintenancePath,
		nil,
	)
	unrelated := testInstallState(
		installRoot,
		dataRoot,
		maintenancePath,
		testPreviousTransactionID,
		"9.9.9",
	)
	writeInstallTree(t, installRoot, unrelated)
	if err := os.WriteFile(
		filepath.Join(installRoot, "bin", "defenseclaw-gateway.exe"),
		[]byte("fixture"),
		0o644,
	); err != nil {
		t.Fatal(err)
	}

	liveDuringRecovery := serviceState{Gateway: true, Watchdog: true}
	var restored serviceState
	err := rollbackSetupTransactionWithRuntime(
		transaction,
		func(string, string) error { return nil },
		func(string, string) (serviceState, error) { return liveDuringRecovery, nil },
		func(string, string) error { return nil },
		func(setupTransaction) error { return nil },
		func(_ string, _ string, wanted serviceState) (serviceState, error) {
			restored = wanted
			return wanted, nil
		},
	)

	if err == nil || !strings.Contains(err.Error(), "refusing to remove an install tree") {
		t.Fatalf("rollback error = %v, want unrelated-tree refusal", err)
	}
	if restored != liveDuringRecovery {
		t.Fatalf("rollback restored services = %+v, want %+v", restored, liveDuringRecovery)
	}
}

func TestPublishedFailureRollbackDrainsLateHookBeforeRestoringFiles(t *testing.T) {
	installRoot, dataRoot, maintenancePath := testTransactionRoots(t)
	previous := testInstallState(
		installRoot,
		dataRoot,
		maintenancePath,
		testPreviousTransactionID,
		"1.0.0",
	)
	transaction := testSetupTransactionForRoots(
		"install",
		installRoot,
		dataRoot,
		maintenancePath,
		&previous,
	)
	writeInstallTree(t, transaction.BackupPath, previous)
	writeInstallTree(t, installRoot, testInstallState(
		installRoot,
		dataRoot,
		maintenancePath,
		transaction.ID,
		transaction.TargetVersion,
	))
	if err := os.WriteFile(
		filepath.Join(installRoot, "bin", "defenseclaw-gateway.exe"),
		[]byte("target gateway fixture"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	drained := false
	var calls []string
	err := rollbackSetupTransactionWithRuntime(
		transaction,
		func(gotRoot, gotTransactionID string) error {
			if gotRoot != installRoot || gotTransactionID != transaction.ID {
				t.Fatalf("drain identity = %q, %q", gotRoot, gotTransactionID)
			}
			calls = append(calls, "hook:drain")
			drained = true
			return nil
		},
		func(string, string) (serviceState, error) {
			if !drained {
				t.Fatal("runtime stop preceded late hook drain")
			}
			calls = append(calls, "runtime:stop")
			return serviceState{}, nil
		},
		func(string, string) error {
			calls = append(calls, "runtime:verify")
			return nil
		},
		func(setupTransaction) error {
			calls = append(calls, "hook:restore")
			assertInstallVersion(t, installRoot, transaction, previous.Version)
			assertPathAbsent(t, transaction.BackupPath)
			return nil
		},
		func(string, string, serviceState) (serviceState, error) {
			t.Fatal("rollback unexpectedly restored an inactive service")
			return serviceState{}, nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(calls, ","); got != "hook:drain,runtime:stop,runtime:verify,hook:restore" {
		t.Fatalf("published rollback calls = %q", got)
	}
}

func TestRollbackRecoveryRequiresRuntimeReleaseBeforeTreeMutation(t *testing.T) {
	installRoot, dataRoot, maintenancePath := testTransactionRoots(t)
	previous := testInstallState(
		installRoot,
		dataRoot,
		maintenancePath,
		testPreviousTransactionID,
		"1.0.0",
	)
	transaction := testSetupTransactionForRoots(
		"install",
		installRoot,
		dataRoot,
		maintenancePath,
		&previous,
	)
	transaction.PreviousServices = serviceState{Gateway: true, Watchdog: true}
	writeInstallTree(t, transaction.BackupPath, previous)
	writeInstallTree(t, installRoot, testInstallState(
		installRoot,
		dataRoot,
		maintenancePath,
		transaction.ID,
		transaction.TargetVersion,
	))
	if err := os.WriteFile(
		filepath.Join(installRoot, "bin", "defenseclaw-gateway.exe"),
		[]byte("target gateway fixture"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	releaseErr := errors.New("gateway executable handle remains open")
	var calls []string
	err := rollbackSetupTransactionWithRuntime(
		transaction,
		func(string, string) error { return nil },
		func(string, string) (serviceState, error) {
			calls = append(calls, "authenticate-stop")
			return serviceState{Gateway: true, Watchdog: true}, nil
		},
		func(string, string) error {
			calls = append(calls, "verify-release")
			return releaseErr
		},
		func(setupTransaction) error {
			calls = append(calls, "restore-hook")
			return nil
		},
		func(string, string, serviceState) (serviceState, error) {
			calls = append(calls, "restore-services")
			return serviceState{}, nil
		},
	)
	if !errors.Is(err, releaseErr) {
		t.Fatalf("rollback error = %v, want executable-release refusal", err)
	}
	if got := strings.Join(calls, ","); got != "authenticate-stop,verify-release" {
		t.Fatalf("recovery calls = %q, want stop and release verification only", got)
	}
	assertInstallVersion(t, installRoot, transaction, transaction.TargetVersion)
	assertInstallVersion(t, transaction.BackupPath, transaction, previous.Version)
}

func TestCommittedRecoveryQuiescesOwnedRuntimeBeforeConvergence(t *testing.T) {
	installRoot, dataRoot, maintenancePath := testTransactionRoots(t)
	transaction := testSetupTransactionForRoots(
		"install",
		installRoot,
		dataRoot,
		maintenancePath,
		nil,
	)
	if err := os.MkdirAll(filepath.Join(installRoot, "bin"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(installRoot, "bin", "defenseclaw-gateway.exe"),
		[]byte("committed gateway fixture"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	phase := setupPhaseCommitted
	var calls []string
	err := recoverSetupJournalPhase(setupJournal{
		SchemaVersion: setupJournalSchemaVersion,
		Phase:         setupPhaseCommitted,
		Transaction:   transaction,
	}, setupRecoveryOps{
		Converge: func(got setupTransaction) error {
			return convergeRecoveredCommittedSetupTransactionWithRuntime(
				got,
				func(string) error {
					calls = append(calls, "disable-hook")
					return nil
				},
				func(string, string) (serviceState, error) {
					calls = append(calls, "authenticate-stop:gateway+watchdog")
					return serviceState{Gateway: true, Watchdog: true}, nil
				},
				func(string, string) error {
					calls = append(calls, "verify-release")
					return nil
				},
				func(setupTransaction) error {
					calls = append(calls, "converge")
					return nil
				},
			)
		},
		Cleanup: func(setupTransaction) error {
			calls = append(calls, "cleanup")
			return nil
		},
		Transition: func(_ setupTransaction, from, to string) error {
			if phase != from {
				return fmt.Errorf("journal transition from %s while phase is %s", from, phase)
			}
			calls = append(calls, "journal:"+to)
			phase = to
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := "disable-hook,authenticate-stop:gateway+watchdog,verify-release,converge,journal:converged,cleanup,journal:complete"
	if got := strings.Join(calls, ","); got != want {
		t.Fatalf("committed recovery calls = %q, want %q", got, want)
	}
}

func TestCommittedRecoveryRejectsForeignRuntimeBeforeConvergence(t *testing.T) {
	installRoot, dataRoot, maintenancePath := testTransactionRoots(t)
	transaction := testSetupTransactionForRoots(
		"install",
		installRoot,
		dataRoot,
		maintenancePath,
		nil,
	)
	if err := os.MkdirAll(filepath.Join(installRoot, "bin"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(installRoot, "bin", "defenseclaw-gateway.exe"),
		[]byte("committed gateway fixture"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	foreignErr := errors.New("foreign process owns gateway path")
	converged := false
	err := convergeRecoveredCommittedSetupTransactionWithRuntime(
		transaction,
		func(string) error { return nil },
		func(string, string) (serviceState, error) { return serviceState{}, nil },
		func(string, string) error { return foreignErr },
		func(setupTransaction) error {
			converged = true
			return nil
		},
	)
	if !errors.Is(err, foreignErr) || converged {
		t.Fatalf("committed foreign-process result = %v, converged=%t", err, converged)
	}
}

func TestUninstallHandoffPreservesLegacyStableHookSnapshotAcrossRollbackRetry(t *testing.T) {
	installRoot, dataRoot, maintenancePath := testTransactionRoots(t)
	previous := testInstallState(
		installRoot,
		dataRoot,
		maintenancePath,
		testPreviousTransactionID,
		"1.0.0",
	)
	source := testSetupTransactionForRoots(
		"install",
		installRoot,
		dataRoot,
		maintenancePath,
		&previous,
	)
	source.PreviousStableHookStatus = ""
	next := testSetupTransactionForRoots(
		"uninstall",
		installRoot,
		dataRoot,
		maintenancePath,
		&previous,
	)
	next.PreviousStableHookStatus = stableHookSnapshotActive
	path := filepath.Join(t.TempDir(), "private", "setup-transaction.json")
	journal := setupJournal{
		SchemaVersion: setupJournalLegacySchemaVersion,
		Phase:         setupPhaseIntent,
		Transaction:   source,
	}
	if err := writeDurableJournal(path, journal, false); err != nil {
		t.Fatal(err)
	}
	expected := setupTransactionExpectations{
		InstallRoot: installRoot, DataRoot: dataRoot, MaintenancePath: maintenancePath,
	}

	snapshotCalls := 0
	rollbackAttempts := 0
	restoreErr := errors.New("injected hook restore failure during uninstall handoff")
	ops := uninstallRecoveryOps{
		snapshotStableHook: func(gatewayPath, gotDataRoot string) (bool, error) {
			snapshotCalls++
			if snapshotCalls > 2 {
				t.Fatal("uninstall retry re-snapshotted the now-disabled stable hook")
			}
			if gatewayPath != filepath.Join(installRoot, "bin", "defenseclaw-gateway.exe") ||
				gotDataRoot != dataRoot {
				t.Fatalf("snapshot roots = %q, %q", gatewayPath, gotDataRoot)
			}
			return true, nil
		},
		rollbackInstall: func(got setupTransaction) error {
			rollbackAttempts++
			if got.PreviousStableHookStatus != stableHookSnapshotActive {
				t.Fatalf("rollback attempt %d posture = %q", rollbackAttempts, got.PreviousStableHookStatus)
			}
			if rollbackAttempts == 1 {
				return restoreErr
			}
			return nil
		},
		buildHandoff: func(got setupTransaction) (setupTransaction, error) {
			if got.PreviousStableHookStatus != stableHookSnapshotActive {
				t.Fatalf("handoff source posture = %q", got.PreviousStableHookStatus)
			}
			if got.UninstallHandoffHookStatus != stableHookSnapshotActive {
				t.Fatalf("uninstall handoff posture = %q", got.UninstallHandoffHookStatus)
			}
			return next, nil
		},
		replaceWithHandoff: func(got setupJournal, next setupTransaction) error {
			return replaceSetupJournalWithUninstallIntentAt(path, expected, got, next)
		},
	}
	if _, err := preparePendingSetupTransactionForUninstallAt(path, expected, ops); !errors.Is(err, restoreErr) {
		t.Fatalf("first uninstall preparation error = %v, want restore failure", err)
	}
	loaded, err := readSetupJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded == nil || loaded.SchemaVersion != setupJournalLegacySchemaVersion ||
		loaded.Phase != setupPhaseIntent ||
		loaded.Transaction.PreviousStableHookStatus != stableHookSnapshotActive ||
		loaded.Transaction.UninstallHandoffHookStatus != stableHookSnapshotActive {
		t.Fatalf("journal after interrupted handoff rollback = %+v", loaded)
	}

	prepared, err := preparePendingSetupTransactionForUninstallAt(path, expected, ops)
	if err != nil {
		t.Fatal(err)
	}
	if prepared == nil || prepared.Action != "uninstall" {
		t.Fatalf("prepared uninstall handoff = %+v", prepared)
	}
	loaded, err = readSetupJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded == nil || loaded.SchemaVersion != setupJournalSchemaVersion ||
		loaded.Phase != setupPhaseIntent || loaded.Transaction.Action != "uninstall" {
		t.Fatalf("journal after uninstall handoff retry = %+v", loaded)
	}
	if snapshotCalls != 2 || rollbackAttempts != 2 {
		t.Fatalf("snapshot calls = %d, rollback attempts = %d", snapshotCalls, rollbackAttempts)
	}
}

func TestUninstallHandoffSurvivesInjectedCrashAndResumesIntent(t *testing.T) {
	t.Parallel()
	installRoot, dataRoot, maintenancePath := testTransactionRoots(t)
	source := testSetupTransactionForRoots("install", installRoot, dataRoot, maintenancePath, nil)
	next := testSetupTransactionForRoots("uninstall", installRoot, dataRoot, maintenancePath, nil)
	path := filepath.Join(t.TempDir(), "private", "setup-transaction.json")
	sourceJournal := setupJournal{
		SchemaVersion: setupJournalSchemaVersion,
		Phase:         setupPhaseCommitted,
		Transaction:   source,
	}
	if err := writeDurableJournal(path, sourceJournal, false); err != nil {
		t.Fatal(err)
	}
	expected := setupTransactionExpectations{
		InstallRoot: installRoot, DataRoot: dataRoot, MaintenancePath: maintenancePath,
	}
	injectedCrash := errors.New("injected crash after durable handoff")
	recoveryCalls := []string{}
	ops := uninstallRecoveryOps{
		prepareCommittedInstall: func(setupTransaction) error {
			recoveryCalls = append(recoveryCalls, "validate-quiesce-cleanup")
			return nil
		},
		buildHandoff: func(setupTransaction) (setupTransaction, error) { return next, nil },
		replaceWithHandoff: func(source setupJournal, next setupTransaction) error {
			return replaceSetupJournalWithUninstallIntentAt(path, expected, source, next)
		},
		afterHandoff: func() error { return injectedCrash },
	}
	if _, err := preparePendingSetupTransactionForUninstallAt(path, expected, ops); !errors.Is(err, injectedCrash) {
		t.Fatalf("handoff error = %v", err)
	}
	journal, err := readSetupJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	if journal == nil || journal.Phase != setupPhaseIntent || journal.Transaction.Action != "uninstall" ||
		journal.Transaction.ID != next.ID {
		t.Fatalf("journal after injected crash = %+v", journal)
	}

	ops = uninstallRecoveryOps{
		resumeUninstall: func(transaction setupTransaction) error {
			recoveryCalls = append(recoveryCalls, "resume-uninstall")
			if transaction.ID != next.ID {
				t.Fatalf("resumed transaction = %s, want %s", transaction.ID, next.ID)
			}
			return nil
		},
	}
	resumed, err := preparePendingSetupTransactionForUninstallAt(path, expected, ops)
	if err != nil {
		t.Fatal(err)
	}
	if resumed == nil || resumed.ID != next.ID {
		t.Fatalf("resumed handoff = %+v", resumed)
	}
	if got := strings.Join(recoveryCalls, ","); got != "validate-quiesce-cleanup,resume-uninstall" {
		t.Fatalf("handoff recovery calls = %q", got)
	}
}

func TestExplicitUninstallRecoversPreparedOrQuiescingInstallBeforeNewIntent(t *testing.T) {
	for _, phase := range []string{setupPhaseIntent, setupPhaseQuiescing} {
		t.Run(phase, func(t *testing.T) {
			installRoot, dataRoot, maintenancePath := testTransactionRoots(t)
			source := testSetupTransactionForRoots("install", installRoot, dataRoot, maintenancePath, nil)
			path := filepath.Join(t.TempDir(), "private", "setup-transaction.json")
			journal := setupJournal{
				SchemaVersion: setupJournalSchemaVersion,
				Phase:         phase,
				Transaction:   source,
			}
			if err := writeDurableJournal(path, journal, false); err != nil {
				t.Fatal(err)
			}
			expected := setupTransactionExpectations{
				InstallRoot: installRoot, DataRoot: dataRoot, MaintenancePath: maintenancePath,
			}
			recovered := false
			prepared, err := preparePendingSetupTransactionForUninstallAt(path, expected, uninstallRecoveryOps{
				rollbackInstall: func(setupTransaction) error {
					t.Fatal("v2 pre-publication install used legacy uninstall handoff rollback")
					return nil
				},
				buildHandoff: func(setupTransaction) (setupTransaction, error) {
					t.Fatal("v2 pre-publication install built an uninstall handoff")
					return setupTransaction{}, nil
				},
				recoverUninstall: func(got setupJournal) error {
					recovered = got.Phase == phase && got.Transaction.ID == source.ID
					return nil
				},
			})
			if err != nil || prepared != nil || !recovered {
				t.Fatalf("prepare uninstall = %+v, recovered=%v, error=%v", prepared, recovered, err)
			}
		})
	}
}

func TestInstallToUninstallHandoffBypassesFailingForwardConvergence(t *testing.T) {
	t.Parallel()
	installRoot, dataRoot, maintenancePath := testTransactionRoots(t)
	source := testSetupTransactionForRoots("install", installRoot, dataRoot, maintenancePath, nil)
	next := testSetupTransactionForRoots("uninstall", installRoot, dataRoot, maintenancePath, nil)
	path := filepath.Join(t.TempDir(), "private", "setup-transaction.json")
	journal := setupJournal{SchemaVersion: setupJournalSchemaVersion, Phase: setupPhaseCommitted, Transaction: source}
	if err := writeDurableJournal(path, journal, false); err != nil {
		t.Fatal(err)
	}
	expected := setupTransactionExpectations{
		InstallRoot: installRoot, DataRoot: dataRoot, MaintenancePath: maintenancePath,
	}
	forwardCalls := 0
	forwardFailure := errors.New("migration, PATH publication, and Apps & Features publication failed")
	ops := uninstallRecoveryOps{
		prepareCommittedInstall: func(setupTransaction) error { return nil },
		buildHandoff:            func(setupTransaction) (setupTransaction, error) { return next, nil },
		recoverUninstall: func(setupJournal) error {
			forwardCalls++
			return forwardFailure
		},
		replaceWithHandoff: func(source setupJournal, next setupTransaction) error {
			return replaceSetupJournalWithUninstallIntentAt(path, expected, source, next)
		},
	}
	prepared, err := preparePendingSetupTransactionForUninstallAt(path, expected, ops)
	if err != nil {
		t.Fatalf("explicit uninstall was blocked by forward convergence: %v", err)
	}
	if prepared == nil || prepared.Action != "uninstall" || forwardCalls != 0 {
		t.Fatalf("handoff = %+v, forward convergence calls = %d", prepared, forwardCalls)
	}
}

func TestExplicitUninstallRetriesOnlyConvergedUninstallBeforeCleanupRecovery(t *testing.T) {
	t.Parallel()
	installRoot, dataRoot, maintenancePath := testTransactionRoots(t)
	transaction := testSetupTransactionForRoots("uninstall", installRoot, dataRoot, maintenancePath, nil)
	transaction.PreviousStableHookStatus = stableHookSnapshotInactive
	path := filepath.Join(t.TempDir(), "private", "setup-transaction.json")
	journal := setupJournal{SchemaVersion: setupJournalSchemaVersion, Phase: setupPhaseConverged, Transaction: transaction}
	if err := writeDurableJournal(path, journal, false); err != nil {
		t.Fatal(err)
	}
	expected := setupTransactionExpectations{InstallRoot: installRoot, DataRoot: dataRoot, MaintenancePath: maintenancePath}
	var calls []string
	prepared, err := preparePendingSetupTransactionForUninstallAt(path, expected, uninstallRecoveryOps{
		retryConvergedUninstall: func(got setupTransaction) error {
			if got.ID != transaction.ID {
				t.Fatalf("retried transaction = %s", got.ID)
			}
			calls = append(calls, "retry-reconciliation")
			return nil
		},
		recoverUninstall: func(got setupJournal) error {
			if got.Phase != setupPhaseConverged || got.Transaction.ID != transaction.ID {
				t.Fatalf("recovered journal = %+v", got)
			}
			calls = append(calls, "cleanup")
			return nil
		},
	})
	if err != nil || prepared != nil {
		t.Fatalf("prepare result=%+v error=%v", prepared, err)
	}
	if got := strings.Join(calls, ","); got != "retry-reconciliation,cleanup" {
		t.Fatalf("recovery calls = %q", got)
	}
}

func TestExplicitUninstallRetainsConvergedJournalWhenReconciliationRetryFails(t *testing.T) {
	t.Parallel()
	installRoot, dataRoot, maintenancePath := testTransactionRoots(t)
	transaction := testSetupTransactionForRoots("uninstall", installRoot, dataRoot, maintenancePath, nil)
	transaction.PreviousStableHookStatus = stableHookSnapshotInactive
	path := filepath.Join(t.TempDir(), "private", "setup-transaction.json")
	journal := setupJournal{SchemaVersion: setupJournalSchemaVersion, Phase: setupPhaseConverged, Transaction: transaction}
	if err := writeDurableJournal(path, journal, false); err != nil {
		t.Fatal(err)
	}
	expected := setupTransactionExpectations{InstallRoot: installRoot, DataRoot: dataRoot, MaintenancePath: maintenancePath}
	want := errors.New("connector custody remains pending")
	_, err := preparePendingSetupTransactionForUninstallAt(path, expected, uninstallRecoveryOps{
		retryConvergedUninstall: func(setupTransaction) error { return want },
		recoverUninstall: func(setupJournal) error {
			t.Fatal("cleanup recovery ran after connector retry failed")
			return nil
		},
	})
	if !errors.Is(err, want) {
		t.Fatalf("retry error = %v, want %v", err, want)
	}
	retained, readErr := readSetupJournal(path)
	if readErr != nil || retained == nil || retained.Phase != setupPhaseConverged || retained.Transaction.ID != transaction.ID {
		t.Fatalf("retained journal=%+v error=%v", retained, readErr)
	}
}

func TestUninstallHandoffAcceptsOnlySourceBoundPartialPathOwnership(t *testing.T) {
	t.Parallel()
	installRoot, dataRoot, maintenancePath := testTransactionRoots(t)
	prior := testInstallState(installRoot, dataRoot, maintenancePath, testPreviousTransactionID, "1.0.0")
	published := testInstallState(installRoot, dataRoot, maintenancePath, testCurrentTransactionID, "1.1.0")
	published.PathEntryOwned = false
	transaction := testSetupTransactionForRoots("uninstall", installRoot, dataRoot, maintenancePath, &published)
	transaction.HandoffFromInstall = testCurrentTransactionID
	transaction.HandoffPreviousState = &prior
	transaction.UninstallPathEntryOwned = true
	transaction.UninstallPathValueCreated = true
	expected := setupTransactionExpectations{
		InstallRoot: installRoot, DataRoot: dataRoot, MaintenancePath: maintenancePath,
	}
	if err := validateSetupTransaction(transaction, expected); err != nil {
		t.Fatalf("source-bound handoff ownership was rejected: %v", err)
	}
	owned, reusedSeparator, valueCreated := uninstallPathOwnership(transaction)
	if !owned || reusedSeparator || !valueCreated {
		t.Fatalf("handoff PATH ownership = %v, %v, %v", owned, reusedSeparator, valueCreated)
	}

	transaction.HandoffFromInstall = testPreviousTransactionID
	if err := validateSetupTransaction(transaction, expected); err == nil {
		t.Fatal("partial PATH ownership not bound to the published install transaction was accepted")
	}
}

func testSetupTransactionForRoots(action, installRoot, dataRoot, maintenancePath string, previous *installState) setupTransaction {
	staging, backup, trash, maintenanceNew, maintenanceBackup := transactionArtifactPaths(
		installRoot,
		maintenancePath,
		testCurrentTransactionID,
	)
	targetVersion := "1.1.0"
	maintenanceSHA256 := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	if action == "uninstall" {
		targetVersion = ""
		maintenanceSHA256 = ""
	}
	antigravityConfigDir := ""
	if action == "install" {
		var err error
		antigravityConfigDir, err = officialAntigravityConfigHomeForTransaction(dataRoot)
		if err != nil {
			panic(fmt.Sprintf("resolve test Antigravity configuration home: %v", err))
		}
	}
	uninstallPathOwned := action == "uninstall" && previous != nil && previous.PathEntryOwned
	uninstallPathSeparatorReused := uninstallPathOwned && previous.PathSeparatorReused
	uninstallPathValueCreated := uninstallPathOwned && previous.PathValueCreated
	return setupTransaction{
		SchemaVersion:                setupTransactionSchemaVersion,
		ID:                           testCurrentTransactionID,
		Action:                       action,
		InstallRoot:                  installRoot,
		DataRoot:                     dataRoot,
		MaintenancePath:              maintenancePath,
		StagingPath:                  staging,
		BackupPath:                   backup,
		TrashPath:                    trash,
		MaintenanceNew:               maintenanceNew,
		MaintenanceBackup:            maintenanceBackup,
		HadInstall:                   previous != nil,
		PreviousState:                previous,
		PreviousPath:                 userPathSnapshot{},
		TargetConnector:              "none",
		TargetMode:                   "observe",
		TargetVersion:                targetVersion,
		AntigravityConfigDir:         antigravityConfigDir,
		MaintenanceSHA256:            maintenanceSHA256,
		UninstallPathEntryOwned:      uninstallPathOwned,
		UninstallPathSeparatorReused: uninstallPathSeparatorReused,
		UninstallPathValueCreated:    uninstallPathValueCreated,
	}
}

func assertInstallVersion(t *testing.T, tree string, transaction setupTransaction, want string) {
	t.Helper()
	state, err := loadTransactionInstallState(tree, transaction)
	if err != nil {
		t.Fatal(err)
	}
	if state == nil || state.Version != want {
		t.Fatalf("install state = %+v, want version %s", state, want)
	}
}

func assertPathAbsent(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("path %s remains after recovery: %v", path, err)
	}
}
