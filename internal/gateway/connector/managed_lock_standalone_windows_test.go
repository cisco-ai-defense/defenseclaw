// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"golang.org/x/sys/windows"
)

// GAP-0566: a managed lock another principal can write is refused on the
// standalone profile after the repair had its chance, while Secure Client
// keeps accepting and logging it. Benign drift (the inherited temp-folder
// descriptor) stays accepted on standalone, so a clean install never refuses
// its own locks.
func TestEnsureWindowsManagedLockProtectionStandaloneRefusesUntrustedWriter(t *testing.T) {
	t.Setenv(managed.TrustStrictAncestorsEnv, "")
	originalCanRepair := windowsManagedCanRepair
	t.Cleanup(func() { windowsManagedCanRepair = originalCanRepair })
	windowsManagedCanRepair = func() bool { return false }
	captureManagedResilienceEvents(t)

	user, err := windowsEffectiveUserSID()
	if err != nil {
		t.Fatal(err)
	}
	newLock := func(t *testing.T, sddl string) (windowsManagedLockRepair, *os.File) {
		t.Helper()
		path := filepath.Join(t.TempDir(), "settings.json.lock")
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatalf("write fixture: %v", err)
		}
		if sddl != "" {
			descriptor, err := windows.SecurityDescriptorFromString(sddl)
			if err != nil {
				t.Fatal(err)
			}
			dacl, _, err := descriptor.DACL()
			if err != nil {
				t.Fatal(err)
			}
			if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
				windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
				nil, nil, dacl, nil); err != nil {
				t.Fatal(err)
			}
		}
		file, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = file.Close() })
		return windowsManagedLockRepair{
			Label:  "managed lock",
			Path:   path,
			Handle: windows.Handle(file.Fd()),
			Validate: func(h windows.Handle) error {
				return validateWindowsManagedFileLockHandleForTarget(h, user)
			},
			Canonical: func() (*windows.SECURITY_DESCRIPTOR, error) {
				return windowsManagedFileLockSecurityDescriptorForTarget(user)
			},
			Policy: windowsManagedTargetRuntimeDriftPolicy(user),
		}, file
	}
	everyoneWrites := "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;" + user.String() + ")(A;;FW;;;WD)"

	t.Run("standalone refuses an untrusted writer", func(t *testing.T) {
		t.Setenv(managed.EnterpriseProfileEnv, managed.ProfileStandalone)
		lock, file := newLock(t, everyoneWrites)
		if err := ensureWindowsManagedLockProtection(lock); err == nil {
			t.Fatal("standalone accepted a lock Everyone can write")
		}
		if err := validateWindowsManagedFileLockHandleForTarget(windows.Handle(file.Fd()), user); err == nil {
			t.Fatal("fixture lock validated as canonical")
		} else if windowsManagedLockDriftAccepted(err, windows.Handle(file.Fd()), user) {
			t.Fatal("standalone re-validation accepted a lock Everyone can write")
		}
	})
	t.Run("standalone accepts benign drift", func(t *testing.T) {
		t.Setenv(managed.EnterpriseProfileEnv, managed.ProfileStandalone)
		lock, _ := newLock(t, "")
		if err := ensureWindowsManagedLockProtection(lock); err != nil {
			t.Fatalf("standalone refused the inherited temp-folder lock descriptor: %v", err)
		}
	})
	t.Run("secure client accepts and logs an untrusted writer", func(t *testing.T) {
		t.Setenv(managed.EnterpriseProfileEnv, "")
		lock, file := newLock(t, everyoneWrites)
		if err := ensureWindowsManagedLockProtection(lock); err != nil {
			t.Fatalf("Secure Client refused a drifted lock: %v", err)
		}
		if err := validateWindowsManagedFileLockHandleForTarget(windows.Handle(file.Fd()), user); err == nil ||
			!windowsManagedLockDriftAccepted(err, windows.Handle(file.Fd()), user) {
			t.Fatalf("Secure Client re-validation of a drifted lock = %v, want accepted drift", err)
		}
	})
}
