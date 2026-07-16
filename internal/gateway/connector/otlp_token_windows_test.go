// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestOTLPPathTokenWindowsSecureCreationAndRepairsBroadDACL(t *testing.T) {
	for _, test := range []struct {
		name       string
		permission windows.ACCESS_MASK
		wantError  string
	}{
		{name: "readable", permission: windows.GENERIC_READ, wantError: "read-like access"},
		{name: "writeable", permission: windows.GENERIC_WRITE, wantError: "write-like access"},
	} {
		t.Run(test.name, func(t *testing.T) {
			dataDir := t.TempDir()
			first, err := EnsureOTLPPathToken(dataDir, OTLPScopeCodex)
			if err != nil {
				t.Fatalf("initial EnsureOTLPPathToken: %v", err)
			}
			path, err := OTLPPathTokenFilePath(dataDir, OTLPScopeCodex)
			if err != nil {
				t.Fatal(err)
			}
			if err := setOTLPWindowsBroadDACL(path, test.permission); err != nil {
				t.Fatalf("install broad DACL: %v", err)
			}
			if token, err := LoadOTLPPathToken(dataDir, OTLPScopeCodex); err == nil ||
				token != "" || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("LoadOTLPPathToken token=%q err=%v, want %q rejection", token, err, test.wantError)
			}

			// Ensure must not keep bytes that an untrusted reader may know or an
			// untrusted writer may have replaced. It atomically publishes a fresh
			// owner-only token instead.
			second, err := EnsureOTLPPathToken(dataDir, OTLPScopeCodex)
			if err != nil {
				t.Fatalf("repair EnsureOTLPPathToken: %v", err)
			}
			if second == "" || second == first {
				t.Fatal("repair did not rotate the exposed scoped credential")
			}
			loaded, err := LoadOTLPPathToken(dataDir, OTLPScopeCodex)
			if err != nil || loaded != second {
				t.Fatalf("load repaired token: matched=%v err=%v", loaded == second, err)
			}
		})
	}
}

func TestOwnedFileLockWindowsRejectsBroadDACL(t *testing.T) {
	lockPath := filepath.Join(t.TempDir(), ".codex-lifecycle.lock")
	if err := withOwnedFileLock(lockPath, func() error { return nil }); err != nil {
		t.Fatalf("create secure lock: %v", err)
	}
	if err := setOTLPWindowsBroadDACL(lockPath, windows.GENERIC_READ); err != nil {
		t.Fatalf("install broad lock DACL: %v", err)
	}
	if err := withOwnedFileLock(lockPath, func() error {
		t.Fatal("callback ran with insecure lock file")
		return nil
	}); err == nil || !strings.Contains(err.Error(), "read-like access") {
		t.Fatalf("withOwnedFileLock err=%v, want broad-DACL rejection", err)
	}
}

func TestRemoveOTLPPathTokenWindowsRevokesBroadDACL(t *testing.T) {
	dataDir := t.TempDir()
	if _, err := EnsureOTLPPathToken(dataDir, OTLPScopeCodex); err != nil {
		t.Fatalf("seed token: %v", err)
	}
	path, err := OTLPPathTokenFilePath(dataDir, OTLPScopeCodex)
	if err != nil {
		t.Fatal(err)
	}
	if err := setOTLPWindowsBroadDACL(path, windows.GENERIC_READ|windows.GENERIC_WRITE); err != nil {
		t.Fatalf("install broad token DACL: %v", err)
	}
	if err := RemoveOTLPPathToken(dataDir, OTLPScopeCodex); err != nil {
		t.Fatalf("revoke exposed token: %v", err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("exposed token still exists after revoke: %v", err)
	}
}

func TestOwnedFileLockWindowsRejectsReparsePoint(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.lock")
	if err := withOwnedFileLock(target, func() error { return nil }); err != nil {
		t.Fatalf("create target lock: %v", err)
	}
	link := filepath.Join(dir, ".codex-lifecycle.lock")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("Windows symlink privilege unavailable: %v", err)
	}
	if err := withOwnedFileLock(link, func() error {
		t.Fatal("callback ran through a reparse-point lock")
		return nil
	}); err == nil || !strings.Contains(err.Error(), "reparse points are not allowed") {
		t.Fatalf("withOwnedFileLock err=%v, want reparse rejection", err)
	}
}

func setOTLPWindowsBroadDACL(path string, untrustedPermission windows.ACCESS_MASK) error {
	currentUser, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	everyone, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		return err
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{
		{
			AccessPermissions: windows.GENERIC_ALL,
			AccessMode:        windows.GRANT_ACCESS,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_USER,
				TrusteeValue: windows.TrusteeValueFromSID(currentUser.User.Sid),
			},
		},
		{
			AccessPermissions: untrustedPermission,
			AccessMode:        windows.GRANT_ACCESS,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
				TrusteeValue: windows.TrusteeValueFromSID(everyone),
			},
		},
	}, nil)
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		acl,
		nil,
	)
}
