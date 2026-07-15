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

	if err := cleanupCommittedSetupTransaction(transaction); err != nil {
		t.Fatalf("cleanupCommittedSetupTransaction: %v", err)
	}
	assertPathAbsent(t, transaction.TrashPath)
	assertPathAbsent(t, filepath.Dir(maintenancePath))
	assertPathAbsent(t, dataRoot)
	if err := cleanupCommittedSetupTransaction(transaction); err != nil {
		t.Fatalf("idempotent cleanupCommittedSetupTransaction: %v", err)
	}
}

func TestCommittedUninstallCleanupFinishesPartiallyDeletedTrash(t *testing.T) {
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
		phase string
		want  []string
	}{
		{phase: setupPhaseIntent, want: []string{"rollback", "intent->complete"}},
		{phase: setupPhaseCommitted, want: []string{"converge", "committed->converged", "cleanup", "converged->complete"}},
		{phase: setupPhaseConverged, want: []string{"cleanup", "converged->complete"}},
		{phase: setupPhaseComplete, want: nil},
	}
	for _, test := range tests {
		t.Run(test.phase, func(t *testing.T) {
			var got []string
			appendStep := func(step string) error {
				got = append(got, step)
				return nil
			}
			transaction := testSetupTransactionForRoots("install", "root", "data", "maintenance", nil)
			err := recoverSetupJournalPhase(setupJournal{
				SchemaVersion: setupJournalSchemaVersion,
				Phase:         test.phase,
				Transaction:   transaction,
			}, setupRecoveryOps{
				Rollback: func(setupTransaction) error { return appendStep("rollback") },
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

func TestRecoverSetupJournalPhaseLeavesConvergedDuringDeferredCleanup(t *testing.T) {
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
		Transition: func(setupTransaction, string, string) error {
			transitioned = true
			return nil
		},
	})
	if !errors.Is(err, errTransactionCleanupDeferred) || transitioned {
		t.Fatalf("recovery error = %v, transitioned = %v", err, transitioned)
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
	if err := transitionSetupJournalAt(path, transaction, setupPhaseIntent, setupPhaseCommitted); err != nil {
		t.Fatalf("commit after JSON round trip: %v", err)
	}
	loaded, err = readSetupJournal(path)
	if err != nil || loaded == nil || loaded.Phase != setupPhaseCommitted {
		t.Fatalf("committed journal = %#v, %v", loaded, err)
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
			previous := connectorsForNativeUninstall(nil, dataRoot)
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
	for _, phase := range []string{setupPhaseIntent, setupPhaseCommitted, setupPhaseConverged} {
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
				Rollback: func(setupTransaction) error { effects++; return nil },
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
	err := rollbackSetupTransactionWithRuntime(
		transaction,
		func(gatewayPath, gotDataRoot string) (serviceState, error) {
			if gatewayPath != filepath.Join(installRoot, "bin", "defenseclaw-gateway.exe") || gotDataRoot != dataRoot {
				t.Fatalf("stop roots = %q, %q", gatewayPath, gotDataRoot)
			}
			return liveDuringRecovery, nil
		},
		func(gatewayPath, gotDataRoot string, wanted serviceState) (serviceState, error) {
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
	err := rollbackSetupTransactionWithRuntime(
		transaction,
		func(string, string) (serviceState, error) { return liveDuringRecovery, nil },
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
