// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

func TestHookAPITokenWindowsRejectsUntrustedDirectoryACL(t *testing.T) {
	assertHookAPITokenRejectedByEnsureAndLoad(t, "untrusted Windows principal", func(t *testing.T) string {
		dataDir := testenv.PrivateTempDir(t)
		if _, err := EnsureHookAPIToken(dataDir, "codex"); err != nil {
			t.Fatalf("seed token: %v", err)
		}
		currentUser, err := windows.GetCurrentProcessToken().GetTokenUser()
		if err != nil {
			t.Fatalf("current token user: %v", err)
		}
		everyone, err := windows.CreateWellKnownSid(windows.WinWorldSid)
		if err != nil {
			t.Fatalf("Everyone SID: %v", err)
		}
		entries := []windows.EXPLICIT_ACCESS{
			{
				AccessPermissions: windows.GENERIC_ALL,
				AccessMode:        windows.GRANT_ACCESS,
				Inheritance:       windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT,
				Trustee: windows.TRUSTEE{
					TrusteeForm:  windows.TRUSTEE_IS_SID,
					TrusteeType:  windows.TRUSTEE_IS_USER,
					TrusteeValue: windows.TrusteeValueFromSID(currentUser.User.Sid),
				},
			},
			{
				AccessPermissions: windows.GENERIC_WRITE,
				AccessMode:        windows.GRANT_ACCESS,
				Inheritance:       windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT,
				Trustee: windows.TRUSTEE{
					TrusteeForm:  windows.TRUSTEE_IS_SID,
					TrusteeType:  windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
					TrusteeValue: windows.TrusteeValueFromSID(everyone),
				},
			},
		}
		acl, err := windows.ACLFromEntries(entries, nil)
		if err != nil {
			t.Fatalf("build DACL: %v", err)
		}
		hooksDir := filepath.Join(dataDir, "hooks")
		if err := windows.SetNamedSecurityInfo(
			hooksDir,
			windows.SE_FILE_OBJECT,
			windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
			nil,
			nil,
			acl,
			nil,
		); err != nil {
			t.Fatalf("set untrusted DACL: %v", err)
		}
		return dataDir
	})
}

func TestHookAPITokenWindowsAllowsReadOnlyUnsupportedAllowACE(t *testing.T) {
	everyone, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		t.Fatalf("Everyone SID: %v", err)
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: windows.GENERIC_READ,
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
	ace.Header.AceType = 0x5
	if err := hookAPIRejectUntrustedWindowsWriteACEs("test", acl, false, true); err != nil {
		t.Fatalf("read-only unsupported allow ACE was rejected: %v", err)
	}
}

func TestHookAPITokenWindowsAllowsInheritOnlyCreatorOwnerTemplate(t *testing.T) {
	creatorOwner, err := windows.CreateWellKnownSid(windows.WinCreatorOwnerSid)
	if err != nil {
		t.Fatalf("Creator Owner SID: %v", err)
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: windows.GENERIC_WRITE,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT | windows.INHERIT_ONLY,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
			TrusteeValue: windows.TrusteeValueFromSID(creatorOwner),
		},
	}}, nil)
	if err != nil {
		t.Fatalf("build DACL: %v", err)
	}
	if err := hookAPIRejectUntrustedWindowsWriteACEs("test", acl, true, true); err != nil {
		t.Fatalf("inherit-only Creator Owner template was rejected: %v", err)
	}
}

func TestHookAPITokenWindowsAllowsOwnerRightsACE(t *testing.T) {
	ownerRights, err := windows.CreateWellKnownSid(windows.WinCreatorOwnerRightsSid)
	if err != nil {
		t.Fatalf("Owner Rights SID: %v", err)
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: windows.GENERIC_ALL,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
			TrusteeValue: windows.TrusteeValueFromSID(ownerRights),
		},
	}}, nil)
	if err != nil {
		t.Fatalf("build DACL: %v", err)
	}
	if err := hookAPIRejectUntrustedWindowsWriteACEs("test", acl, true, true); err != nil {
		t.Fatalf("Owner Rights ACE was rejected after trusted-owner validation: %v", err)
	}
}

func TestHookAPITokenWindowsRejectsDirectCreatorOwnerACE(t *testing.T) {
	creatorOwner, err := windows.CreateWellKnownSid(windows.WinCreatorOwnerSid)
	if err != nil {
		t.Fatalf("Creator Owner SID: %v", err)
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: windows.GENERIC_WRITE,
		AccessMode:        windows.GRANT_ACCESS,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
			TrusteeValue: windows.TrusteeValueFromSID(creatorOwner),
		},
	}}, nil)
	if err != nil {
		t.Fatalf("build DACL: %v", err)
	}
	if err := hookAPIRejectUntrustedWindowsWriteACEs("test", acl, true, true); err == nil {
		t.Fatal("direct Creator Owner ACE was accepted")
	}
}

func TestHookAPITokenWindowsAllowsCreateChildOnSharedAncestor(t *testing.T) {
	everyone, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		t.Fatalf("Everyone SID: %v", err)
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: windows.FILE_WRITE_DATA,
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
	if err := hookAPIRejectUntrustedWindowsWriteACEs("ancestor", acl, true, false); err != nil {
		t.Fatalf("shared ancestor create-child permission was rejected: %v", err)
	}
}

func TestHookAPITokenWindowsRejectsOrdinaryWriteOnSharedAncestor(t *testing.T) {
	everyone, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		t.Fatalf("Everyone SID: %v", err)
	}

	for _, tc := range []struct {
		name string
		mask windows.ACCESS_MASK
	}{
		{name: "generic_write", mask: windows.GENERIC_WRITE},
		{name: "write_extended_attributes", mask: windows.FILE_WRITE_EA},
		{name: "write_attributes", mask: windows.FILE_WRITE_ATTRIBUTES},
	} {
		t.Run(tc.name, func(t *testing.T) {
			acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
				AccessPermissions: tc.mask,
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
			if err := hookAPIRejectUntrustedWindowsWriteACEs("ancestor", acl, true, false); err == nil {
				t.Fatalf("shared ancestor accepted untrusted %s access", tc.name)
			}
		})
	}
}

func TestHookAPITokenWindowsRejectsWritableAncestorThroughPublicOperations(t *testing.T) {
	for _, tc := range []struct {
		name string
		mask windows.ACCESS_MASK
	}{
		{name: "generic_write", mask: windows.GENERIC_WRITE},
		{name: "write_extended_attributes", mask: windows.FILE_WRITE_EA},
		{name: "write_attributes", mask: windows.FILE_WRITE_ATTRIBUTES},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assertHookAPITokenRejectedByEnsureAndLoad(t, "untrusted Windows principal", func(t *testing.T) string {
				root := testenv.PrivateTempDir(t)
				ancestor := filepath.Join(root, "ancestor")
				dataDir := filepath.Join(ancestor, "data")
				if err := os.MkdirAll(dataDir, 0o700); err != nil {
					t.Fatalf("create token data path: %v", err)
				}
				if _, err := EnsureHookAPIToken(dataDir, "codex"); err != nil {
					t.Fatalf("seed token: %v", err)
				}
				setHookAPITokenWindowsUntrustedDACL(t, ancestor, tc.mask)
				return dataDir
			})
		})
	}
}

func TestHookAPITokenWindowsAllowsInheritOnlyTemplateOnSharedAncestor(t *testing.T) {
	const inheritedModifyMask windows.ACCESS_MASK = 0xe0010000

	authenticatedUsers, err := windows.CreateWellKnownSid(windows.WinAuthenticatedUserSid)
	if err != nil {
		t.Fatalf("Authenticated Users SID: %v", err)
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: inheritedModifyMask,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT | windows.INHERIT_ONLY,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
			TrusteeValue: windows.TrusteeValueFromSID(authenticatedUsers),
		},
	}}, nil)
	if err != nil {
		t.Fatalf("build DACL: %v", err)
	}
	if err := hookAPIRejectUntrustedWindowsWriteACEs("ancestor", acl, true, false); err != nil {
		t.Fatalf("shared ancestor inherit-only template was rejected: %v", err)
	}
	if err := hookAPIRejectUntrustedWindowsWriteACEs("protected", acl, true, true); err == nil {
		t.Fatal("protected directory inherit-only template was accepted")
	}
}

func TestHookAPITokenWindowsRejectsDeleteChildOnSharedAncestor(t *testing.T) {
	const fileDeleteChild windows.ACCESS_MASK = 0x00000040

	everyone, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		t.Fatalf("Everyone SID: %v", err)
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: fileDeleteChild,
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
	if err := hookAPIRejectUntrustedWindowsWriteACEs("ancestor", acl, true, false); err == nil {
		t.Fatal("shared ancestor delete-child permission was accepted")
	}
}

func TestHookAPITokenWindowsRejectsReparsePointDirectory(t *testing.T) {
	assertHookAPITokenRejectedByEnsureAndLoadAny(t, []string{"reparse points are not allowed", "escapes hooks dir"}, func(t *testing.T) string {
		dataDir := testenv.PrivateTempDir(t)
		targetDataDir := testenv.PrivateTempDir(t)
		if _, err := EnsureHookAPIToken(targetDataDir, "codex"); err != nil {
			t.Fatalf("seed target token: %v", err)
		}
		if err := os.Symlink(filepath.Join(targetDataDir, "hooks"), filepath.Join(dataDir, "hooks")); err != nil {
			t.Skipf("Windows symlink privilege unavailable: %v", err)
		}
		return dataDir
	})
}

func setHookAPITokenWindowsUntrustedDACL(t *testing.T, path string, mask windows.ACCESS_MASK) {
	t.Helper()
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
			Inheritance:       windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_USER,
				TrusteeValue: windows.TrusteeValueFromSID(currentUser.User.Sid),
			},
		},
		{
			AccessPermissions: mask,
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
		t.Fatalf("set untrusted ancestor DACL: %v", err)
	}
}
