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
	return setupTransaction{
		SchemaVersion:     setupTransactionSchemaVersion,
		ID:                testCurrentTransactionID,
		Action:            action,
		InstallRoot:       installRoot,
		DataRoot:          dataRoot,
		MaintenancePath:   maintenancePath,
		StagingPath:       staging,
		BackupPath:        backup,
		TrashPath:         trash,
		MaintenanceNew:    maintenanceNew,
		MaintenanceBackup: maintenanceBackup,
		HadInstall:        previous != nil,
		PreviousState:     previous,
		PreviousPath:      userPathSnapshot{},
		TargetConnector:   "none",
		TargetMode:        "observe",
		TargetVersion:     targetVersion,
		MaintenanceSHA256: maintenanceSHA256,
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
