// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// GAP-0045 (cowork-1-0-8): without purge, the LocalSystem finalize removes
// what the managed runtime wrote into the folder of each enrolled account
// whose registrations all went, and names the folder only when something
// stays. An account whose registrations stay keeps its folder untouched
// (its connector_backups restore them), and a run that is not LocalSystem
// changes nothing. No account's data or binaries are purged.
func TestWindowsManagedHooksStandaloneUserStatePlainUninstallRemovesManagedRuntime(t *testing.T) {
	originalIdentity := enterpriseHookWindowsUserCleanupIdentity
	originalRemover := windowsManagedHooksStandaloneUserRuntimeRemover
	originalPurger := windowsManagedHooksStandaloneUserStatePurger
	originalBinaries := windowsManagedHooksStandaloneUserBinariesPurger
	t.Cleanup(func() {
		enterpriseHookWindowsUserCleanupIdentity = originalIdentity
		windowsManagedHooksStandaloneUserRuntimeRemover = originalRemover
		windowsManagedHooksStandaloneUserStatePurger = originalPurger
		windowsManagedHooksStandaloneUserBinariesPurger = originalBinaries
	})
	windowsManagedHooksStandaloneUserStatePurger = func(string, string, string) error {
		t.Fatal("a plain uninstall purged an account's data")
		return nil
	}
	windowsManagedHooksStandaloneUserBinariesPurger = func(string, string) ([]string, error) {
		t.Fatal("a plain uninstall purged an account's binaries")
		return nil, nil
	}

	manifest := perUserTeardownManifest("claudecode")
	second := manifest.Targets[0]
	second.SID = userCleanupSIDB
	manifest.Targets = append(manifest.Targets, second)
	for index := range manifest.Targets {
		manifest.Targets[index].UserHome = t.TempDir()
		if err := os.Mkdir(filepath.Join(manifest.Targets[index].UserHome, ".defenseclaw"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	keepsB := func(sid string) bool { return sid == userCleanupSIDB }

	calls := map[string]int{}
	kept, removeErr := "", error(nil)
	windowsManagedHooksStandaloneUserRuntimeRemover = func(home, sid, dataDir string) (string, error) {
		calls[sid]++
		if home != manifest.Targets[0].UserHome || dataDir != manifest.Targets[0].DataDir {
			t.Fatalf("cleanup of %s %s %s", home, sid, dataDir)
		}
		return kept, removeErr
	}
	enterpriseHookWindowsUserCleanupIdentity = func() error { return nil }

	// The cleaned folder is gone and not named; B keeps its folder.
	remaining, purged, _ := windowsManagedHooksStandaloneUserState(manifest, false, keepsB)
	if calls[userCleanupSIDA] != 1 || calls[userCleanupSIDB] != 0 || len(purged) != 0 ||
		len(remaining) != 1 || !strings.HasPrefix(remaining[0], userCleanupSIDB+": ") ||
		!strings.HasSuffix(remaining[0], `\.defenseclaw`) {
		t.Fatalf("calls=%v remaining=%v purged=%v", calls, remaining, purged)
	}

	// A folder that keeps the account's own files is named with why.
	kept = "kept: it still holds notes.txt, which DefenseClaw's managed runtime did not write"
	remaining, _, _ = windowsManagedHooksStandaloneUserState(manifest, false, keepsB)
	if len(remaining) != 2 || !strings.HasSuffix(remaining[0], `\.defenseclaw: `+kept) {
		t.Fatalf("kept folder: remaining=%v", remaining)
	}

	// A cleanup that fails names the folder with the error.
	kept, removeErr = "", errors.New("remove hooks: access denied")
	remaining, _, _ = windowsManagedHooksStandaloneUserState(manifest, false, keepsB)
	if len(remaining) != 2 || !strings.HasSuffix(remaining[0], `\.defenseclaw: remove hooks: access denied`) {
		t.Fatalf("failed cleanup: remaining=%v", remaining)
	}

	// Not LocalSystem: nothing is changed and both folders are named.
	removeErr = nil
	enterpriseHookWindowsUserCleanupIdentity = func() error { return errors.New("not LocalSystem") }
	before := calls[userCleanupSIDA]
	remaining, _, _ = windowsManagedHooksStandaloneUserState(manifest, false, keepsB)
	if calls[userCleanupSIDA] != before || len(remaining) != 2 ||
		!strings.HasSuffix(remaining[0], `\.defenseclaw`) || !strings.HasSuffix(remaining[1], `\.defenseclaw`) {
		t.Fatalf("not LocalSystem: calls=%v remaining=%v", calls, remaining)
	}
}
