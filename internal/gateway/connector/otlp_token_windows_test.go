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

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

func TestLoadOTLPPathTokenWindowsRejectsUntrustedWriteDACL(t *testing.T) {
	writeMasks := []struct {
		name string
		mask windows.ACCESS_MASK
	}{
		{name: "generic_write", mask: windows.GENERIC_WRITE},
		{name: "write_data", mask: windows.FILE_WRITE_DATA},
		{name: "append_data", mask: windows.FILE_APPEND_DATA},
		{name: "write_ea", mask: windows.FILE_WRITE_EA},
		{name: "write_attributes", mask: windows.FILE_WRITE_ATTRIBUTES},
	}
	for _, tc := range writeMasks {
		t.Run(tc.name, func(t *testing.T) {
			dataDir := testenv.PrivateTempDir(t)
			if _, err := EnsureOTLPPathToken(dataDir, OTLPScopeCodex); err != nil {
				t.Fatalf("seed token: %v", err)
			}
			path, err := OTLPPathTokenFilePath(dataDir, OTLPScopeCodex)
			if err != nil {
				t.Fatal(err)
			}
			setOTLPTokenWindowsDACL(t, path, tc.mask, false)

			if token, err := LoadOTLPPathToken(dataDir, OTLPScopeCodex); err == nil {
				t.Fatalf("LoadOTLPPathToken accepted untrusted %s access; token=%q", tc.name, token)
			}
		})
	}
}

// A write grant on a folder above the data directory is drift on a folder
// DefenseClaw doesn't own: the token keeps working (and can still be minted)
// and the drift is logged instead of turning off telemetry for that user.
func TestLoadOTLPPathTokenWindowsAcceptsWritableAncestor(t *testing.T) {
	for _, tc := range []struct {
		name string
		mask windows.ACCESS_MASK
	}{
		{name: "generic_write", mask: windows.GENERIC_WRITE},
		{name: "write_extended_attributes", mask: windows.FILE_WRITE_EA},
		{name: "write_attributes", mask: windows.FILE_WRITE_ATTRIBUTES},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := testenv.PrivateTempDir(t)
			ancestor := filepath.Join(root, "ancestor")
			dataDir := filepath.Join(ancestor, "data")
			if err := os.MkdirAll(dataDir, 0o700); err != nil {
				t.Fatalf("create token data path: %v", err)
			}
			seeded, err := EnsureOTLPPathToken(dataDir, OTLPScopeCodex)
			if err != nil {
				t.Fatalf("seed token: %v", err)
			}
			tokenPath, err := OTLPPathTokenFilePath(dataDir, OTLPScopeCodex)
			if err != nil {
				t.Fatalf("resolve token path: %v", err)
			}
			setOTLPTokenWindowsDACL(t, ancestor, tc.mask, true)

			if token, err := EnsureOTLPPathToken(dataDir, OTLPScopeCodex); err != nil || token != seeded {
				t.Fatalf("EnsureOTLPPathToken = %q, %v; want the seeded token", token, err)
			}
			if token, err := LoadOTLPPathToken(dataDir, OTLPScopeCodex); err != nil || token != seeded {
				t.Fatalf("LoadOTLPPathToken = %q, %v; want the seeded token", token, err)
			}
			if err := os.Remove(tokenPath); err != nil {
				t.Fatalf("remove seeded token: %v", err)
			}
			if token, err := EnsureOTLPPathToken(dataDir, OTLPScopeCodex); err != nil || token == "" {
				t.Fatalf("EnsureOTLPPathToken after removal = %q, %v; want a new token", token, err)
			}
		})
	}
}

func TestLoadOTLPPathTokenWindowsAllowsCreateChildOnSharedAncestor(t *testing.T) {
	root := testenv.PrivateTempDir(t)
	ancestor := filepath.Join(root, "ancestor")
	dataDir := filepath.Join(ancestor, "data")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatalf("create token data path: %v", err)
	}
	want, err := EnsureOTLPPathToken(dataDir, OTLPScopeCodex)
	if err != nil {
		t.Fatalf("seed token: %v", err)
	}
	setOTLPTokenWindowsDACL(t, ancestor, windows.FILE_WRITE_DATA, true)

	got, err := LoadOTLPPathToken(dataDir, OTLPScopeCodex)
	if err != nil {
		t.Fatalf("LoadOTLPPathToken rejected shared ancestor create-child access: %v", err)
	}
	if got != want {
		t.Fatalf("token = %q, want %q", got, want)
	}
}

func TestOTLPPathTokenWindowsRejectsUnsupportedWriteAllowACETypes(t *testing.T) {
	aceTypes := []struct {
		name   string
		typeID byte
	}{
		{name: "compound", typeID: 0x4},
		{name: "object", typeID: 0x5},
		{name: "callback", typeID: 0x9},
		{name: "callback_object", typeID: 0xB},
	}
	for _, tc := range aceTypes {
		t.Run(tc.name, func(t *testing.T) {
			everyone, err := windows.CreateWellKnownSid(windows.WinWorldSid)
			if err != nil {
				t.Fatalf("Everyone SID: %v", err)
			}
			acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
				AccessPermissions: windows.GENERIC_WRITE,
				AccessMode:        windows.GRANT_ACCESS,
				Trustee: windows.TRUSTEE{
					TrusteeForm:  windows.TRUSTEE_IS_SID,
					TrusteeType:  windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
					TrusteeValue: windows.TrusteeValueFromSID(everyone),
				},
			}}, nil)
			if err != nil {
				t.Fatalf("build DACL: %v", err)
			}
			var ace *windows.ACCESS_ALLOWED_ACE
			if err := windows.GetAce(acl, 0, &ace); err != nil {
				t.Fatalf("get ACE: %v", err)
			}
			ace.Header.AceType = tc.typeID
			if err := hookAPIRejectUntrustedWindowsWriteACEs("token", acl, false, true, false); err == nil ||
				!strings.Contains(err.Error(), "unsupported Windows allow ACE type") {
				t.Fatalf("write-capable ACE type 0x%x error = %v", tc.typeID, err)
			}
		})
	}
}

func TestOTLPPathTokenWindowsSecureCreationAndRepairsBroadDACL(t *testing.T) {
	t.Setenv(managed.TrustStrictAncestorsEnv, "")
	for _, test := range []struct {
		name       string
		permission windows.ACCESS_MASK
		// readDrift: an extra reader is permission drift. The token stays
		// usable (accepted and logged) and a privileged publish restores
		// its protection with the same value.
		readDrift bool
		wantError string
	}{
		{name: "readable", permission: windows.GENERIC_READ, readDrift: true},
		{name: "writeable", permission: windows.GENERIC_WRITE, wantError: "write-like access"},
	} {
		t.Run(test.name, func(t *testing.T) {
			captureManagedResilienceEvents(t)
			dataDir := testenv.PrivateTempDir(t)
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
			if test.readDrift {
				if token, err := LoadOTLPPathToken(dataDir, OTLPScopeCodex); err != nil || token != first {
					t.Fatalf("LoadOTLPPathToken with an extra reader matched=%v err=%v, want the token", token == first, err)
				}
				second, err := EnsureOTLPPathToken(dataDir, OTLPScopeCodex)
				if err != nil || second != first {
					t.Fatalf("EnsureOTLPPathToken with an extra reader matched=%v err=%v, want the same token", second == first, err)
				}
				if windowsManagedCanRepair() {
					if replace, err := otlpPathTokenNeedsSecureReplacement(path); err != nil || replace {
						t.Fatalf("privileged publish left the extra reader: replace=%v err=%v", replace, err)
					}
				}
				return
			}
			if token, err := LoadOTLPPathToken(dataDir, OTLPScopeCodex); err == nil ||
				token != "" || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("LoadOTLPPathToken token=%q err=%v, want %q rejection", token, err, test.wantError)
			}

			// A credential an untrusted principal could overwrite must be
			// rotated, not merely have its ACL tightened while retaining
			// bytes that principal may have planted.
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

// A data-free lock with an extra reader is drift, not a reason to stop the
// lifecycle: the callback runs and the drift is logged. A write grant still
// refuses, because another principal could replace the lock.
func TestOwnedFileLockWindowsAcceptsExtraReaderRejectsWriter(t *testing.T) {
	t.Setenv(managed.TrustStrictAncestorsEnv, "")
	captureManagedResilienceEvents(t)
	lockPath := filepath.Join(testenv.PrivateTempDir(t), ".codex-lifecycle.lock")
	if err := withOwnedFileLock(lockPath, func() error { return nil }); err != nil {
		t.Fatalf("create secure lock: %v", err)
	}
	if err := setOTLPWindowsBroadDACL(lockPath, windows.GENERIC_READ); err != nil {
		t.Fatalf("install broad lock DACL: %v", err)
	}
	ran := false
	if err := withOwnedFileLock(lockPath, func() error {
		ran = true
		return nil
	}); err != nil || !ran {
		t.Fatalf("withOwnedFileLock with an extra reader ran=%v err=%v, want accepted", ran, err)
	}

	if err := setOTLPWindowsBroadDACL(lockPath, windows.GENERIC_WRITE); err != nil {
		t.Fatalf("install writable lock DACL: %v", err)
	}
	if err := withOwnedFileLock(lockPath, func() error {
		t.Fatal("callback ran with a lock another principal can write")
		return nil
	}); err == nil || !strings.Contains(err.Error(), "write-like access") {
		t.Fatalf("withOwnedFileLock err=%v, want write-access rejection", err)
	}
}

func TestRemoveOTLPPathTokenWindowsRevokesBroadDACL(t *testing.T) {
	dataDir := testenv.PrivateTempDir(t)
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
	dir := testenv.PrivateTempDir(t)
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

func setOTLPTokenWindowsDACL(t *testing.T, path string, untrustedMask windows.ACCESS_MASK, inheritOwner bool) {
	t.Helper()
	inheritance := uint32(windows.NO_INHERITANCE)
	if inheritOwner {
		inheritance = windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT
	}
	currentUser, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatalf("current token user: %v", err)
	}
	everyone, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		t.Fatalf("Everyone SID: %v", err)
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{
		{
			AccessPermissions: windows.GENERIC_ALL,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       inheritance,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_USER,
				TrusteeValue: windows.TrusteeValueFromSID(currentUser.User.Sid),
			},
		},
		{
			AccessPermissions: untrustedMask,
			AccessMode:        windows.GRANT_ACCESS,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
				TrusteeValue: windows.TrusteeValueFromSID(everyone),
			},
		},
	}, nil)
	if err != nil {
		t.Fatalf("build DACL: %v", err)
	}
	if err := windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		acl,
		nil,
	); err != nil {
		t.Fatalf("set DACL: %v", err)
	}
}
