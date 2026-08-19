// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package ipc

import (
	"testing"

	"golang.org/x/sys/windows"
)

// TestBaselineIPCACEsShapeDirectory asserts the four-ACE table
// applyBaselineIPCACL writes for a DIRECTORY object matches spec 004
// REQ-03 + REQ-04, with the Authenticated Users mask constrained to
// traverse+list (CR spec-004:PRRT_kwDORuAK-s6ankzk — refuses
// FILE_ADD_FILE / FILE_ADD_SUBDIRECTORY leakage).
//
// Windows' LookupSID on "NT SERVICE\<name>" returns the correct SID
// for ANY syntactically-valid service name — virtual-service SIDs
// under NT SERVICE authority (S-1-5-80-...) are computed from the
// service name hash, not read from an installed-service registry.
// So this test works whether or not DefenseClawGateway is actually
// registered on the CI runner.
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
	entries, err := baselineIPCACEs(class)
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
	// Slot 2's expected trustee: resolve via the same helper the
	// production code uses so the test tracks a possible env
	// override (managed.WindowsServiceAccountEnv) consistently. The
	// helper enforces NT SERVICE authority — a resolved SID under
	// any other authority makes this call fail, which is exactly
	// the guard the DACL path needs. See CR
	// spec-004:PRRT_kwDORuAK-s6ankzg + PRRT_kwDORuAK-s6ankzl.
	gatewaySID, err := resolveGatewayServiceSID()
	if err != nil {
		t.Fatalf("resolveGatewayServiceSID: %v", err)
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
		// The trustee value is a uintptr embedding the SID pointer;
		// compare via TrusteeValueFromSID against the expected SID
		// (which for slot 2 came through resolveGatewayServiceSID,
		// so this asserts BOTH identity AND authority).
		wantTV := windows.TrusteeValueFromSID(tc.want)
		if got.Trustee.TrusteeValue != wantTV {
			t.Errorf("entry %d (%s): trustee SID mismatch", i, tc.name)
		}
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

// TestSIDIsNTServiceAcceptsNTServiceSIDs asserts a real NT SERVICE
// virtual account SID passes. Uses resolveGatewayServiceSID() to
// avoid duplicating the LookupSID call; the helper's own
// authority-check guarantees the returned SID is under NT SERVICE.
func TestSIDIsNTServiceAcceptsNTServiceSIDs(t *testing.T) {
	sid, err := resolveGatewayServiceSID()
	if err != nil {
		t.Fatalf("resolveGatewayServiceSID: %v", err)
	}
	if !sidIsNTService(sid) {
		t.Fatalf("sidIsNTService rejected a legitimately-resolved NT SERVICE SID")
	}
}
