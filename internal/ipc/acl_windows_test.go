// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package ipc

import (
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// TestBaselineIPCACEsShapeDirectory asserts the four-ACE table
// applyBaselineIPCACL writes for a DIRECTORY object matches spec 004
// REQ-03 + REQ-04, with the Authenticated Users mask constrained to
// traverse+list (CR spec-004:PRRT_kwDORuAK-s6ankzk — refuses
// FILE_ADD_FILE / FILE_ADD_SUBDIRECTORY leakage).
//
// The ACL-shape test supplies a syntactically valid NT SERVICE SID directly so
// it does not depend on DefenseClawGateway being registered on the CI runner.
func TestBaselineIPCACEsShapeDirectory(t *testing.T) {
	assertBaselineIPCACEs(t, aclObjectDirectory,
		windows.FILE_TRAVERSE|windows.FILE_LIST_DIRECTORY)
}

// TestBaselineIPCACEsShapeSocketFile asserts the socket-file variant:
// Authenticated Users gets GENERIC_READ|GENERIC_WRITE. Enough for
// connect() + gRPC handshake; still refuses WRITE_DAC (not in
// GENERIC_WRITE for FILE objects).
func TestBaselineIPCACEsShapeSocketFile(t *testing.T) {
	assertBaselineIPCACEs(t, aclObjectSocketFile,
		windows.GENERIC_READ|windows.GENERIC_WRITE)
}

func assertBaselineIPCACEs(t *testing.T, class aclObjectClass, wantAuthUsersMask windows.ACCESS_MASK) {
	t.Helper()
	gatewaySID := testGatewayServiceSID(t)
	entries, err := baselineIPCACEsForGatewaySID(class, gatewaySID)
	if err != nil {
		t.Fatalf("baselineIPCACEs(%v): %v", class, err)
	}
	if got, want := len(entries), 4; got != want {
		t.Fatalf("ACE count = %d, want %d — spec 004 REQ-03 fixes this at four ACEs", got, want)
	}

	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		t.Fatalf("resolve SYSTEM SID: %v", err)
	}
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatalf("resolve Administrators SID: %v", err)
	}
	authUsers, err := windows.CreateWellKnownSid(windows.WinAuthenticatedUserSid)
	if err != nil {
		t.Fatalf("resolve Authenticated Users SID: %v", err)
	}
	if !sidIsNTService(gatewaySID) {
		t.Fatalf("gateway SID does not live under NT SERVICE authority — spec 004 refuses this in the DACL")
	}

	// Slot order is deterministic:
	//   0: SYSTEM               GENERIC_ALL
	//   1: Administrators       GENERIC_ALL
	//   2: gateway service      GENERIC_ALL     (authority = NT SERVICE)
	//   3: Authenticated Users  wantAuthUsersMask
	cases := []struct {
		name       string
		want       *windows.SID
		wantMask   windows.ACCESS_MASK
		wantAccess uint32
	}{
		{"SYSTEM", system, windows.GENERIC_ALL, uint32(windows.GRANT_ACCESS)},
		{"Administrators", admins, windows.GENERIC_ALL, uint32(windows.GRANT_ACCESS)},
		{"gateway service", gatewaySID, windows.GENERIC_ALL, uint32(windows.GRANT_ACCESS)},
		{"Authenticated Users", authUsers, wantAuthUsersMask, uint32(windows.GRANT_ACCESS)},
	}
	for i, tc := range cases {
		got := entries[i]
		if uint32(got.AccessMode) != tc.wantAccess {
			t.Errorf("entry %d (%s): AccessMode = %v, want GRANT_ACCESS", i, tc.name, got.AccessMode)
		}
		if got.AccessPermissions != tc.wantMask {
			t.Errorf("entry %d (%s): AccessPermissions = %#x, want %#x", i, tc.name, got.AccessPermissions, tc.wantMask)
		}
		if got.Inheritance != windows.NO_INHERITANCE {
			t.Errorf("entry %d (%s): Inheritance = %v, want NO_INHERITANCE (spec 004: DACL is self-contained per object)", i, tc.name, got.Inheritance)
		}
		if got.Trustee.TrusteeForm != windows.TRUSTEE_IS_SID {
			t.Errorf("entry %d (%s): TrusteeForm = %v, want TRUSTEE_IS_SID", i, tc.name, got.Trustee.TrusteeForm)
		}
		assertExplicitAccessTrusteeSID(t, i, tc.name, got, tc.want)
	}
}

// assertExplicitAccessTrusteeSID materializes a single EXPLICIT_ACCESS entry
// through the same Windows ACL API used by applyBaselineIPCACL, then compares
// the copied SID contents. TrusteeValue itself embeds a pointer, so comparing
// it directly would reject equivalent independently allocated well-known SIDs.
func assertExplicitAccessTrusteeSID(
	t *testing.T,
	index int,
	name string,
	entry windows.EXPLICIT_ACCESS,
	want *windows.SID,
) {
	t.Helper()
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{entry}, nil)
	if err != nil {
		t.Fatalf("entry %d (%s): materialize ACL: %v", index, name, err)
	}
	if acl == nil {
		t.Fatalf("entry %d (%s): materialized ACL is nil", index, name)
	}
	if acl.AceCount != 1 {
		t.Fatalf("entry %d (%s): materialized ACE count = %d, want 1", index, name, acl.AceCount)
	}

	var ace *windows.ACCESS_ALLOWED_ACE
	if err := windows.GetAce(acl, 0, &ace); err != nil {
		t.Fatalf("entry %d (%s): read materialized ACE: %v", index, name, err)
	}
	if ace == nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
		t.Fatalf("entry %d (%s): materialized ACE is not an allow ACE", index, name)
	}
	got := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
	if !got.IsValid() || !got.Equals(want) {
		t.Errorf("entry %d (%s): trustee SID = %s, want %s", index, name, got, want)
	}
}

// TestSIDIsNTServiceRejectsNonServicePrincipals directly exercises
// sidIsNTService against the SIDs an adversary might plant in
// managed.WindowsServiceAccountEnv. All of these must be rejected —
// the DACL construction is fail-closed on its own (CR
// spec-004:PRRT_kwDORuAK-s6ankzl).
func TestSIDIsNTServiceRejectsNonServicePrincipals(t *testing.T) {
	cases := []struct {
		name    string
		sidType windows.WELL_KNOWN_SID_TYPE
	}{
		{"Everyone", windows.WinWorldSid},
		{"Anonymous", windows.WinAnonymousSid},
		{"AuthenticatedUsers", windows.WinAuthenticatedUserSid},
		{"LocalSystem", windows.WinLocalSystemSid},
		{"Administrators", windows.WinBuiltinAdministratorsSid},
		{"BuiltinUsers", windows.WinBuiltinUsersSid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sid, err := windows.CreateWellKnownSid(tc.sidType)
			if err != nil {
				t.Fatalf("build well-known SID %s: %v", tc.name, err)
			}
			if sidIsNTService(sid) {
				t.Fatalf("sidIsNTService accepted %s — a non-NT-SERVICE principal must be refused so the DACL cannot promote e.g. Everyone to gateway-full-control", tc.name)
			}
		})
	}
}

// TestSIDIsNTServiceAcceptsNTServiceSIDs asserts a syntactically valid NT
// SERVICE virtual account SID passes without requiring an installed service.
func TestSIDIsNTServiceAcceptsNTServiceSIDs(t *testing.T) {
	sid := testGatewayServiceSID(t)
	if !sidIsNTService(sid) {
		t.Fatalf("sidIsNTService rejected a legitimate NT SERVICE SID")
	}
}

func testGatewayServiceSID(t *testing.T) *windows.SID {
	t.Helper()
	sid, err := windows.StringToSid("S-1-5-80-111-222-333-444-555")
	if err != nil {
		t.Fatalf("build test NT SERVICE SID: %v", err)
	}
	return sid
}
