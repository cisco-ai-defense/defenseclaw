//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWindowsUserRuntimeTransactionSerializesConcurrentConnectorInstalls(t *testing.T) {
	sid := currentWindowsTestSID(t).String()
	unlockFirst, err := lockWindowsUserRuntimeTransaction(sid)
	if err != nil {
		t.Fatal(err)
	}
	firstReleased := false
	defer func() {
		if !firstReleased {
			unlockFirst()
		}
	}()

	secondAttempting := make(chan struct{})
	secondEntered := make(chan struct{})
	secondDone := make(chan error, 1)
	go func() {
		close(secondAttempting)
		unlockSecond, lockErr := lockWindowsUserRuntimeTransaction(strings.ToLower(sid))
		if lockErr != nil {
			secondDone <- lockErr
			return
		}
		defer unlockSecond()
		close(secondEntered)
		secondDone <- nil
	}()
	<-secondAttempting
	sharedLock, err := windowsUserRuntimeTransactionMutex(strings.ToLower(sid))
	if err != nil {
		t.Fatal(err)
	}
	if sharedLock.TryLock() {
		sharedLock.Unlock()
		t.Fatal("same-SID connector transaction resolved a different unlocked gate")
	}
	unlockFirst()
	firstReleased = true
	select {
	case <-secondEntered:
	case <-time.After(5 * time.Second):
		t.Fatal("same-SID connector transaction did not resume after rollback released the gate")
	}
	if err := <-secondDone; err != nil {
		t.Fatalf("second same-SID connector transaction: %v", err)
	}
}

func TestWindowsSharedRuntimeConcurrentConnectorFailuresRollbackWithoutResidue(t *testing.T) {
	target := currentWindowsTestSID(t)
	home := newWindowsTargetOwnedTestHome(t, target)
	dataDir := filepath.Join(home, ".defenseclaw")

	firstCreated := make(chan struct{})
	allowFirstRollback := make(chan struct{})
	firstDone := make(chan error, 1)
	go func() {
		firstDone <- runWindowsTestFailingSharedRuntimeTransaction(
			target.String(),
			home,
			"codex",
			firstCreated,
			allowFirstRollback,
		)
	}()
	select {
	case <-firstCreated:
	case err := <-firstDone:
		t.Fatalf("first connector failed before creating shared parents: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("first connector did not create shared parents")
	}

	secondAttempting := make(chan struct{})
	secondCreated := make(chan struct{})
	secondDone := make(chan error, 1)
	go func() {
		close(secondAttempting)
		secondDone <- runWindowsTestFailingSharedRuntimeTransaction(
			target.String(),
			home,
			"cursor",
			secondCreated,
			nil,
		)
	}()
	<-secondAttempting
	sharedLock, err := windowsUserRuntimeTransactionMutex(target.String())
	if err != nil {
		t.Fatal(err)
	}
	if sharedLock.TryLock() {
		sharedLock.Unlock()
		t.Fatal("second connector resolved a different unlocked same-SID transaction gate")
	}

	close(allowFirstRollback)
	if err := <-firstDone; !errors.Is(err, errWindowsTestInjectedConnectorFailure) ||
		strings.Contains(err.Error(), "rollback failed") {
		t.Fatalf("first connector result = %v, want only injected failure after exact rollback", err)
	}
	select {
	case <-secondCreated:
	case <-time.After(5 * time.Second):
		t.Fatal("second connector did not recreate cleaned shared parents after the first rollback released the SID gate")
	}
	if err := <-secondDone; !errors.Is(err, errWindowsTestInjectedConnectorFailure) ||
		strings.Contains(err.Error(), "rollback failed") {
		t.Fatalf("second connector result = %v, want only injected failure after exact rollback", err)
	}
	if _, err := os.Lstat(dataDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("concurrent connector rollback left shared runtime residue: %v", err)
	}
}

var errWindowsTestInjectedConnectorFailure = errors.New("injected connector failure")

func runWindowsTestFailingSharedRuntimeTransaction(
	rawSID string,
	home string,
	connectorName string,
	created chan<- struct{},
	allowRollback <-chan struct{},
) error {
	unlock, err := lockWindowsUserRuntimeTransaction(rawSID)
	if err != nil {
		return err
	}
	defer unlock()
	target, err := validateWindowsEnterpriseTargetSID(rawSID)
	if err != nil {
		return err
	}
	return runWindowsTestThreadImpersonatedAsSelf(func() error {
		dataDir := filepath.Join(home, ".defenseclaw")
		hookDir := filepath.Join(dataDir, "hooks")
		paths := windowsCodexRuntimePaths(dataDir)
		if connectorName == "cursor" {
			paths = windowsCursorRuntimePaths(dataDir)
		}
		snapshot, err := snapshotWindowsRuntimeFiles(paths)
		if err != nil {
			return err
		}
		transaction := windowsCodexUserRuntimeTransaction{
			home:      home,
			dataDir:   dataDir,
			hookDir:   hookDir,
			paths:     paths,
			snapshot:  snapshot,
			targetSID: target,
		}
		creation, err := ensureWindowsTargetOwnedDirectoryTree(home, hookDir, target)
		transaction.createdDataDir = creation.createdDataDir
		transaction.createdHookDir = creation.createdHookDir
		if err != nil {
			return err
		}
		if !transaction.createdDataDir || !transaction.createdHookDir {
			return fmt.Errorf("connector %s did not own both fresh shared directories", connectorName)
		}
		close(created)
		if allowRollback != nil {
			<-allowRollback
		}
		if connectorName == "cursor" {
			cursorTransaction := windowsCursorUserRuntimeTransaction{
				home:           transaction.home,
				dataDir:        transaction.dataDir,
				hookDir:        transaction.hookDir,
				paths:          transaction.paths,
				snapshot:       transaction.snapshot,
				targetSID:      transaction.targetSID,
				createdDataDir: transaction.createdDataDir,
				createdHookDir: transaction.createdHookDir,
			}
			if err := restoreWindowsCursorUserRuntime(cursorTransaction); err != nil {
				return errors.Join(errWindowsTestInjectedConnectorFailure, fmt.Errorf("rollback failed: %w", err))
			}
		} else if err := restoreWindowsCodexUserRuntime(transaction); err != nil {
			return errors.Join(errWindowsTestInjectedConnectorFailure, fmt.Errorf("rollback failed: %w", err))
		}
		return errWindowsTestInjectedConnectorFailure
	})
}

func TestRestoreWindowsRuntimeFilesAcceptsAbsentParentForAbsentPreimage(t *testing.T) {
	home := t.TempDir()
	target := currentWindowsTestSID(t)
	dataDir := filepath.Join(home, ".defenseclaw")
	hookDir := filepath.Join(dataDir, "hooks")
	paths := []string{
		filepath.Join(hookDir, ".hook-codex.token"),
		filepath.Join(dataDir, "hook_contract_lock.json"),
	}
	snapshots, err := snapshotWindowsRuntimeFiles(paths)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(hookDir, 0o700); err != nil {
		t.Fatal(err)
	}
	// Model an earlier connector rollback that cleaned the shared parents
	// before this originally-absent transaction reached its own rollback.
	if err := removeEmptyWindowsDirectory(hookDir); err != nil {
		t.Fatal(err)
	}
	if err := removeEmptyWindowsDirectory(dataDir); err != nil {
		t.Fatal(err)
	}

	for attempt := 1; attempt <= 2; attempt++ {
		err = runWindowsTestThreadImpersonatedAsSelf(func() error {
			return restoreWindowsRuntimeFiles(home, target, snapshots)
		})
		if err != nil {
			t.Fatalf("rollback attempt %d of absent shared runtime preimage: %v", attempt, err)
		}
	}
	if _, err := os.Lstat(dataDir); !os.IsNotExist(err) {
		t.Fatalf("absent shared runtime rollback created residue: %v", err)
	}
}

func TestRestoreWindowsRuntimeFilesRequiresOriginallyPresentSharedParent(t *testing.T) {
	home := t.TempDir()
	target := currentWindowsTestSID(t)
	dataDir := filepath.Join(home, ".defenseclaw")
	hookDir := filepath.Join(dataDir, "hooks")
	path := filepath.Join(hookDir, ".hook-codex.token")
	if err := os.MkdirAll(hookDir, 0o700); err != nil {
		t.Fatal(err)
	}
	snapshots, err := snapshotWindowsRuntimeFiles([]string{path})
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshots) != 1 || !snapshots[0].parentExisted || snapshots[0].existed {
		t.Fatalf("absent-file snapshot = %+v, want present parent and absent file", snapshots)
	}
	if err := removeEmptyWindowsDirectory(hookDir); err != nil {
		t.Fatal(err)
	}
	if err := removeEmptyWindowsDirectory(dataDir); err != nil {
		t.Fatal(err)
	}

	err = runWindowsTestThreadImpersonatedAsSelf(func() error {
		return restoreWindowsRuntimeFiles(home, target, snapshots)
	})
	if err == nil || !strings.Contains(err.Error(), "runtime rollback parent") {
		t.Fatalf("absent file with removed pre-existing parent error = %v, want fail-closed parent refusal", err)
	}
}

func TestPrepareWindowsGenericPathRequiredRejectsMissingIntermediate(t *testing.T) {
	target := currentWindowsTestSID(t)
	home := newWindowsTargetOwnedTestHome(t, target)
	hookDir := filepath.Join(home, ".defenseclaw", "hooks")
	err := runWindowsTestThreadImpersonatedAsSelf(func() error {
		return prepareWindowsGenericPath(
			home,
			hookDir,
			target,
			true,
			true,
			false,
			"required rollback parent",
		)
	})
	if err == nil || !strings.Contains(err.Error(), ".defenseclaw") ||
		!strings.Contains(err.Error(), "is missing") {
		t.Fatalf("missing intermediate error = %v, want required-path refusal", err)
	}
}

func TestPrepareWindowsGenericPathRequiredRejectsMissingFinal(t *testing.T) {
	target := currentWindowsTestSID(t)
	home := newWindowsTargetOwnedTestHome(t, target)
	hookDir := filepath.Join(home, ".defenseclaw", "hooks")
	var creation windowsTargetOwnedDirectoryCreation
	err := runWindowsTestThreadImpersonatedAsSelf(func() error {
		var err error
		creation, err = ensureWindowsTargetOwnedDirectoryTree(home, hookDir, target)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if !creation.createdDataDir || !creation.createdHookDir {
		t.Fatalf("test directory creation = %+v, want both fresh parents", creation)
	}
	if err := os.Remove(hookDir); err != nil {
		t.Fatal(err)
	}
	err = runWindowsTestThreadImpersonatedAsSelf(func() error {
		return prepareWindowsGenericPath(
			home,
			hookDir,
			target,
			true,
			true,
			false,
			"required rollback parent",
		)
	})
	if err == nil || !strings.Contains(err.Error(), "hooks") ||
		!strings.Contains(err.Error(), "is missing") {
		t.Fatalf("missing final error = %v, want required-path refusal", err)
	}
}

func TestRestoreWindowsRuntimeFilesRequiresParentForExistingPreimage(t *testing.T) {
	home := t.TempDir()
	target := currentWindowsTestSID(t)
	snapshot := windowsRuntimeFileSnapshot{
		path:    filepath.Join(home, ".defenseclaw", "hooks", ".hook-codex.token"),
		existed: true,
		data:    []byte("restore-me"),
	}

	err := runWindowsTestThreadImpersonatedAsSelf(func() error {
		return restoreWindowsRuntimeFiles(home, target, []windowsRuntimeFileSnapshot{snapshot})
	})
	if err == nil || !strings.Contains(err.Error(), "runtime rollback parent") {
		t.Fatalf("existing runtime preimage with absent parent error = %v, want fail-closed parent refusal", err)
	}
	if _, statErr := os.Lstat(snapshot.path); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("failed existing-preimage rollback created an untrusted parent or file: %v", statErr)
	}
}
