// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"testing"

	"golang.org/x/sys/windows"
)

// A guardian verifying a signed-out user's per-user plugin has no user token,
// so custody checks trust the named target SID explicitly. Only that SID is
// added; malformed values and other users trust nothing extra.
func TestHookAPITrustedOwnerSIDIsExactAndOptional(t *testing.T) {
	target, err := windows.StringToSid("S-1-5-21-111-222-333-1017")
	if err != nil {
		t.Fatal(err)
	}
	other, err := windows.StringToSid("S-1-5-21-111-222-333-1018")
	if err != nil {
		t.Fatal(err)
	}
	pinWindowsEffectiveUserSIDForTest(t, mustSIDForTrustedOwnerTest(t, "S-1-5-18"))

	for _, value := range []string{"", " ", "not-a-sid", "S-1-bogus"} {
		if hookAPIParseTrustedOwnerSID(value) != nil {
			t.Fatalf("malformed trusted owner %q parsed", value)
		}
	}
	extra := hookAPIParseTrustedOwnerSID(target.String())
	if extra == nil {
		t.Fatal("well-formed target SID did not parse")
	}
	if !hookAPIWindowsTrustedPrincipalOrExtra(target, extra) {
		t.Fatal("target SID was not trusted as the explicit extra owner")
	}
	if hookAPIWindowsTrustedPrincipalOrExtra(other, extra) {
		t.Fatal("a different user was trusted through the target's extra owner")
	}
	if hookAPIWindowsTrustedPrincipalOrExtra(target, nil) {
		t.Fatal("target SID was trusted without an explicit extra owner")
	}

	grant := func(sid *windows.SID) *windows.ACL {
		acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
			AccessPermissions: windows.GENERIC_WRITE,
			AccessMode:        windows.GRANT_ACCESS,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_USER,
				TrusteeValue: windows.TrusteeValueFromSID(sid),
			},
		}}, nil)
		if err != nil {
			t.Fatalf("build DACL: %v", err)
		}
		return acl
	}
	if err := hookAPIRejectUntrustedWindowsWriteACEsTrusting("plugin dir", grant(target), true, true, false, extra); err != nil {
		t.Fatalf("target write grant refused with the target as extra owner: %v", err)
	}
	if err := hookAPIRejectUntrustedWindowsWriteACEsTrusting("plugin dir", grant(other), true, true, false, extra); err == nil {
		t.Fatal("another user's write grant was accepted")
	}
	if err := hookAPIRejectUntrustedWindowsWriteACEs("plugin dir", grant(target), true, true, false); err == nil {
		t.Fatal("target write grant was accepted without an explicit extra owner")
	}
}

func mustSIDForTrustedOwnerTest(t *testing.T, value string) *windows.SID {
	t.Helper()
	sid, err := windows.StringToSid(value)
	if err != nil {
		t.Fatal(err)
	}
	return sid
}
