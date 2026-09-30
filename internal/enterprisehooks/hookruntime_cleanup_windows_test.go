// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func stubWindowsHookRuntimeRoot(t *testing.T) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "DefenseClaw-HookRuntime")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	previousRoot, previousDir, previousStandalone := windowsStandaloneHookRuntimeRoot, windowsPerUserManagedRuntimeDirResolver, windowsEnterpriseStandaloneProcess
	windowsStandaloneHookRuntimeRoot = func() (string, error) { return root, nil }
	windowsPerUserManagedRuntimeDirResolver = func(name string) (string, error) { return filepath.Join(root, name), nil }
	windowsEnterpriseStandaloneProcess = func() bool { return true }
	t.Cleanup(func() {
		windowsStandaloneHookRuntimeRoot, windowsPerUserManagedRuntimeDirResolver, windowsEnterpriseStandaloneProcess = previousRoot, previousDir, previousStandalone
	})
	return root
}

// Revoking enrollments during an uninstall must not create a runtime
// directory and lock file for connectors that never ran.
func TestRemoveWindowsPerUserManagedEnrollmentsCreatesNothingForUnusedConnectors(t *testing.T) {
	root := stubWindowsHookRuntimeRoot(t)
	if err := RemoveWindowsPerUserManagedEnrollments(`C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw-hook.exe`, WindowsStandalonePerUserConnectorNames()); err != nil {
		t.Fatalf("RemoveWindowsPerUserManagedEnrollments: %v", err)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("revocation created %d entries under the hook runtime directory, first %s", len(entries), entries[0].Name())
	}
}

func writeHookRuntimeFile(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestRemoveWindowsStandaloneHookRuntimeDirectoriesRemovesOnlyEmptiedDirectories(t *testing.T) {
	root := stubWindowsHookRuntimeRoot(t)
	writeHookRuntimeFile(t, filepath.Join(root, "copilot", windowsPerUserManagedEnrollmentLockFile))
	writeHookRuntimeFile(t, filepath.Join(root, "copilot", windowsManagedRuntimeSelectorLockFile))
	writeHookRuntimeFile(t, filepath.Join(root, "devin", windowsPerUserManagedEnrollmentLockFile))
	enrollment := filepath.Join(root, "devin", windowsPerUserManagedEnrollmentFile)
	writeHookRuntimeFile(t, enrollment)

	kept, err := RemoveWindowsStandaloneHookRuntimeDirectories()
	if err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(root, "copilot")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a directory holding only lock files must be removed: %v", err)
	}
	if _, err := os.Lstat(enrollment); err != nil {
		t.Fatalf("a directory with an enrollment must be left untouched: %v", err)
	}
	if len(kept) != 2 {
		t.Fatalf("kept = %v, want the devin directory and the root", kept)
	}

	if err := os.Remove(enrollment); err != nil {
		t.Fatal(err)
	}
	if kept, err := RemoveWindowsStandaloneHookRuntimeDirectories(); err != nil || len(kept) != 0 {
		t.Fatalf("second cleanup kept=%v err=%v, want everything removed", kept, err)
	}
	if _, err := os.Lstat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the emptied hook runtime root must be removed: %v", err)
	}
	if kept, err := RemoveWindowsStandaloneHookRuntimeDirectories(); err != nil || len(kept) != 0 {
		t.Fatalf("cleanup of an absent root kept=%v err=%v", kept, err)
	}
}

func TestRemoveWindowsStandaloneHookRuntimeDirectoriesIsStandaloneOnly(t *testing.T) {
	root := stubWindowsHookRuntimeRoot(t)
	windowsEnterpriseStandaloneProcess = func() bool { return false }
	if _, err := RemoveWindowsStandaloneHookRuntimeDirectories(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(root); err != nil {
		t.Fatalf("a Secure Client process must not touch the standalone hook runtime directory: %v", err)
	}
}

// A standalone uninstall drops the runtime selector lock from the vendor
// machine-policy directories and keeps the lock of a selector that still
// exists.
func TestRemoveWindowsStandaloneMachinePolicySelectorLocks(t *testing.T) {
	stubWindowsHookRuntimeRoot(t)
	base := t.TempDir()
	previous := windowsManagedRuntimeSelectorPathResolver
	windowsManagedRuntimeSelectorPathResolver = func(name string) (string, error) {
		return filepath.Join(base, name, windowsManagedRuntimeSelectorFile), nil
	}
	t.Cleanup(func() { windowsManagedRuntimeSelectorPathResolver = previous })
	claudeLock := filepath.Join(base, "claudecode", windowsManagedRuntimeSelectorLockFile)
	writeHookRuntimeFile(t, claudeLock)
	codexLock := filepath.Join(base, "codex", windowsManagedRuntimeSelectorLockFile)
	writeHookRuntimeFile(t, codexLock)
	writeHookRuntimeFile(t, filepath.Join(base, "codex", windowsManagedRuntimeSelectorFile))

	if err := RemoveWindowsStandaloneMachinePolicySelectorLocks(); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if _, err := os.Lstat(claudeLock); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the lock of a removed selector must be dropped: %v", err)
	}
	if _, err := os.Lstat(filepath.Dir(claudeLock)); err != nil {
		t.Fatalf("the vendor directory must be left in place: %v", err)
	}
	if _, err := os.Lstat(codexLock); err != nil {
		t.Fatalf("the lock of a selector that still exists must be kept: %v", err)
	}
}

// A standalone uninstall drops the runtime selector entries of a local
// account deleted with its profile, which the teardown manifest no longer
// names, and keeps every other entry. A selector left with no entry goes, and
// its lock with it.
func TestRemoveWindowsStandaloneDeletedAccountSelectorTargets(t *testing.T) {
	stubWindowsHookRuntimeRoot(t)
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		t.Fatalf("resolve test SID: %v", err)
	}
	owner := user.User.Sid
	const deleted = "S-1-5-21-1111111111-2222222222-3333333333-1021"
	base := t.TempDir()
	previousPath, previousOwner := windowsManagedRuntimeSelectorPathResolver, windowsManagedPolicyOwnerSID
	previousDirTrust, previousAncestorTrust := windowsManagedPolicyDirTrustCheck, windowsManagedPolicyAncestorTrustCheck
	previousFileTrust, previousMutation := windowsManagedPolicyFileTrustCheck, windowsManagedRuntimeSelectorMutationAuthorize
	previousRemoved := windowsSelectorTargetAccountRemoved
	windowsManagedRuntimeSelectorPathResolver = func(name string) (string, error) {
		return filepath.Join(base, name, windowsManagedRuntimeSelectorFile), nil
	}
	windowsManagedPolicyOwnerSID = func() (*windows.SID, error) { return owner, nil }
	windowsManagedPolicyDirTrustCheck = func(string) error { return nil }
	windowsManagedPolicyAncestorTrustCheck = func(string) error { return nil }
	windowsManagedPolicyFileTrustCheck = func(string) error { return nil }
	windowsManagedRuntimeSelectorMutationAuthorize = func() error { return nil }
	windowsSelectorTargetAccountRemoved = func(entry windowsManagedRuntimeSelectorTarget) bool {
		return entry.SID == deleted
	}
	t.Cleanup(func() {
		windowsManagedRuntimeSelectorPathResolver, windowsManagedPolicyOwnerSID = previousPath, previousOwner
		windowsManagedPolicyDirTrustCheck, windowsManagedPolicyAncestorTrustCheck = previousDirTrust, previousAncestorTrust
		windowsManagedPolicyFileTrustCheck, windowsManagedRuntimeSelectorMutationAuthorize = previousFileTrust, previousMutation
		windowsSelectorTargetAccountRemoved = previousRemoved
	})
	entries := func(connector string, sids ...string) []windowsManagedRuntimeSelectorTarget {
		sort.Strings(sids)
		var targets []windowsManagedRuntimeSelectorTarget
		for _, sid := range sids {
			targets = append(targets, windowsManagedRuntimeSelectorTarget{
				Connector:          connector,
				SID:                sid,
				DataDir:            filepath.Join(base, "profiles", sid, ".defenseclaw"),
				HookExecutable:     filepath.Join(base, "defenseclaw-hook.exe"),
				GatewayAddr:        "127.0.0.1:18970",
				GatewayServiceName: "DefenseClawGateway",
				GenerationID:       strings.Repeat("a", 32),
				BundleSHA256:       "sha256:" + strings.Repeat("b", 64),
			})
		}
		return targets
	}
	for connector, targets := range map[string][]windowsManagedRuntimeSelectorTarget{
		"claudecode": entries("claudecode", deleted, owner.String()),
		"codex":      entries("codex", deleted),
	} {
		if err := ensureWindowsManagedPolicyDirectory(filepath.Join(base, connector)); err != nil {
			t.Fatal(err)
		}
		if err := publishWindowsManagedRuntimeSelector(windowsManagedRuntimeSelector{
			SchemaVersion: windowsManagedRuntimeGenerationSchema,
			Connector:     connector,
			Targets:       targets,
		}); err != nil {
			t.Fatalf("publish %s selector: %v", connector, err)
		}
	}

	if err := RemoveWindowsStandaloneDeletedAccountSelectorTargets(); err != nil {
		t.Fatalf("drop deleted accounts: %v", err)
	}
	if err := RemoveWindowsStandaloneMachinePolicySelectorLocks(); err != nil {
		t.Fatalf("drop selector locks: %v", err)
	}
	claude, _, exists, err := readWindowsManagedRuntimeSelector("claudecode", true)
	if err != nil || !exists || len(claude.Targets) != 1 || claude.Targets[0].SID != owner.String() {
		t.Fatalf("the Claude Code selector must keep only the live entry: exists=%v targets=%+v err=%v", exists, claude.Targets, err)
	}
	for _, leaf := range []string{windowsManagedRuntimeSelectorFile, windowsManagedRuntimeSelectorLockFile} {
		if _, err := os.Lstat(filepath.Join(base, "codex", leaf)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("codex %s must be gone once its only entry was a deleted account's: %v", leaf, err)
		}
	}
}
