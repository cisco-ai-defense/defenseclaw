// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
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
	transaction.PreviousConnectors = []string{"codex"}
	transaction.TargetServices.Gateway = true
	transaction.PreviousCodexHome = filepath.Join(filepath.Dir(dataRoot), ".codex")
	transaction.CodexHome = transaction.PreviousCodexHome
	transaction.PreviousClaudeConfigDir = filepath.Join(filepath.Dir(dataRoot), ".claude")
	transaction.ClaudeConfigDir = transaction.PreviousClaudeConfigDir
	expected := setupTransactionExpectations{
		InstallRoot:     installRoot,
		DataRoot:        dataRoot,
		MaintenancePath: maintenancePath,
	}
	if err := validateSetupTransaction(transaction, expected); err != nil {
		t.Fatalf("valid connector-preserving transaction rejected: %v", err)
	}

	changedHome := transaction
	changedHome.CodexHome = filepath.Join(filepath.Dir(dataRoot), "other-codex")
	if err := validateSetupTransaction(changedHome, expected); err == nil {
		t.Fatal("connector-preserving transaction changed its recorded Codex home")
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
		PreviousConnectors: []string{"codex", "claudecode"},
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
	}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("connector opt-out calls = %v, want %v", calls, want)
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

func TestResolvePreviousConnectorHomeUsesBackupBindingWithoutInstallState(t *testing.T) {
	for _, test := range []struct {
		connector, logicalName, legacyBackup string
	}{
		{"codex", "config.toml", "codex_config_backup.json"},
		{"claudecode", "settings.json", "claudecode_backup.json"},
	} {
		t.Run(test.connector, func(t *testing.T) {
			dataRoot := t.TempDir()
			if err := os.WriteFile(filepath.Join(dataRoot, test.legacyBackup), []byte(`{}`), 0o600); err != nil {
				t.Fatal(err)
			}
			managedBackup := filepath.Join(
				dataRoot, "connector_backups", test.connector, test.logicalName+".json",
			)
			if err := os.MkdirAll(filepath.Dir(managedBackup), 0o700); err != nil {
				t.Fatal(err)
			}
			want := filepath.Join(t.TempDir(), test.connector+"-custom-home")
			if err := os.WriteFile(
				managedBackup,
				[]byte(fmt.Sprintf(`{"path":%q}`, filepath.Join(want, test.logicalName))),
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

func TestLegacyConnectorHomesFollowValidatedOverridesWithoutManagedBinding(t *testing.T) {
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
	clientRoot := filepath.Join(filepath.Dir(dataRoot), "client-homes")
	codexHome := filepath.Join(clientRoot, "codex")
	claudeHome := filepath.Join(clientRoot, "claude")
	for _, path := range []string{codexHome, claudeHome} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("CODEX_HOME", codexHome)
	t.Setenv("CLAUDE_CONFIG_DIR", claudeHome)

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
		!samePath(transaction.PreviousClaudeConfigDir, claudeHome) {
		t.Fatalf(
			"legacy transaction homes = (%q, %q), want validated overrides (%q, %q)",
			transaction.PreviousCodexHome,
			transaction.PreviousClaudeConfigDir,
			codexHome,
			claudeHome,
		)
	}

	source := transaction
	source.Action = "install"
	source.ID = testCurrentTransactionID
	source.CodexHome = codexHome
	source.ClaudeConfigDir = claudeHome
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
		!samePath(handoff.PreviousClaudeConfigDir, claudeHome) {
		t.Fatalf(
			"legacy handoff homes = (%q, %q), want source overrides (%q, %q)",
			handoff.PreviousCodexHome,
			handoff.PreviousClaudeConfigDir,
			codexHome,
			claudeHome,
		)
	}
	if handoff.PreviousStableHookStatus != stableHookSnapshotInactive {
		t.Fatalf("handoff stable-hook posture = %q", handoff.PreviousStableHookStatus)
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

func TestInstallMutationQuiescenceRevokesHookBeforeStoppingRuntime(t *testing.T) {
	t.Parallel()
	transaction := setupTransaction{ID: testCurrentTransactionID}
	var calls []string
	hookActive := true
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
		func(gatewayPath, dataRoot string) (serviceState, error) {
			if hookActive {
				t.Fatal("runtime stop began while stable-hook cold start remained authorized")
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
	if got := strings.Join(calls, ","); got != "hook:disable,runtime:stop,runtime:verify-release" {
		t.Fatalf("quiescence calls = %q", got)
	}
}

func TestInstallMutationQuiescenceRefusesRuntimeStopWhenHookDisableFails(t *testing.T) {
	t.Parallel()
	disableErr := errors.New("stable hook state is locked")
	stopCalled := false
	verifyCalled := false
	err := quiesceSetupRuntimeForMutation(
		setupTransaction{ID: testCurrentTransactionID},
		"gateway.exe",
		"data",
		func(string) error { return disableErr },
		func(string, string) (serviceState, error) {
			stopCalled = true
			return serviceState{}, nil
		},
		func(string, string) error {
			verifyCalled = true
			return nil
		},
	)
	if !errors.Is(err, disableErr) || stopCalled || verifyCalled {
		t.Fatalf("quiescence result = %v, stop=%t verify=%t", err, stopCalled, verifyCalled)
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
	want := "hook:disable,runtime:stop,runtime:verify-release,tree:rename"
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
