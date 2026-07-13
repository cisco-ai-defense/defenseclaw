// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"strings"
	"testing"

	"golang.org/x/sys/windows"

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
			setOTLPTokenWindowsDACL(t, path, tc.mask)

			if token, err := LoadOTLPPathToken(dataDir, OTLPScopeCodex); err == nil {
				t.Fatalf("LoadOTLPPathToken accepted untrusted %s access; token=%q", tc.name, token)
			}
		})
	}
}

func TestLoadOTLPPathTokenWindowsAllowsUntrustedReadOnlyDACL(t *testing.T) {
	dataDir := testenv.PrivateTempDir(t)
	want, err := EnsureOTLPPathToken(dataDir, OTLPScopeCodex)
	if err != nil {
		t.Fatalf("seed token: %v", err)
	}
	path, err := OTLPPathTokenFilePath(dataDir, OTLPScopeCodex)
	if err != nil {
		t.Fatal(err)
	}
	setOTLPTokenWindowsDACL(t, path, windows.GENERIC_READ)

	got, err := LoadOTLPPathToken(dataDir, OTLPScopeCodex)
	if err != nil {
		t.Fatalf("LoadOTLPPathToken rejected read-only DACL: %v", err)
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
			if err := hookAPIRejectUntrustedWindowsWriteACEs("token", acl, false, true); err == nil ||
				!strings.Contains(err.Error(), "unsupported Windows allow ACE type") {
				t.Fatalf("write-capable ACE type 0x%x error = %v", tc.typeID, err)
			}
		})
	}
}

func setOTLPTokenWindowsDACL(t *testing.T, path string, untrustedMask windows.ACCESS_MASK) {
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
