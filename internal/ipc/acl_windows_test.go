// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package ipc

import (
	"testing"

	"golang.org/x/sys/windows"
)

// TestBaselineIPCACEsShape asserts the four-ACE table
// applyBaselineIPCACL writes matches spec 004 REQ-03. The test
// exercises `baselineIPCACEs()` in isolation — no filesystem
// object involved — so it runs on any Windows runner regardless of
// the DefenseClawGateway service being registered. (The service
// SID lookup uses `NT SERVICE\<name>` which resolves for ANY name
// that syntactically matches the virtual-service pattern, even if
// the service hasn't been installed; that's a documented Windows
// behaviour.)
func TestBaselineIPCACEsShape(t *testing.T) {
	entries, err := baselineIPCACEs()
	if err != nil {
		t.Fatalf("baselineIPCACEs: %v", err)
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

	// The order returned by baselineIPCACEs is deterministic:
	// SYSTEM, Administrators, gateway service, Authenticated Users.
	// Assert each slot's access mode + mask + inheritance.
	cases := []struct {
		name       string
		want       *windows.SID
		wantMask   windows.ACCESS_MASK
		wantAccess uint32
	}{
		{"SYSTEM", system, windows.GENERIC_ALL, uint32(windows.GRANT_ACCESS)},
		{"Administrators", admins, windows.GENERIC_ALL, uint32(windows.GRANT_ACCESS)},
		// slot 2 is the gateway service SID — we don't assert its
		// value directly (it varies by service registration), just
		// that the mask + access mode are correct.
		{"gateway service", nil, windows.GENERIC_ALL, uint32(windows.GRANT_ACCESS)},
		{"Authenticated Users", authUsers, windows.GENERIC_READ | windows.GENERIC_WRITE, uint32(windows.GRANT_ACCESS)},
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
		if tc.want != nil {
			// The trustee value is a `uintptr` in the EXPLICIT_ACCESS
			// struct; compare via windows.TrusteeValueFromSID.
			wantTV := windows.TrusteeValueFromSID(tc.want)
			if got.Trustee.TrusteeValue != wantTV {
				t.Errorf("entry %d (%s): trustee SID mismatch", i, tc.name)
			}
		}
	}
}
