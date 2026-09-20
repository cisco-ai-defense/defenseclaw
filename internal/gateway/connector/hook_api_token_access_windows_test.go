// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"testing"

	"golang.org/x/sys/windows"
)

// programDataUsersMask is the mask stock Windows grants BUILTIN\Users on
// C:\ProgramData via (A;CI;DCLCRPCR;;;BU): add-file, append, write-EA and
// write-attributes. Every managed state root sits beneath that directory.
const programDataUsersMask windows.ACCESS_MASK = 0x116

func ancestorDACL(t *testing.T, sidType windows.WELL_KNOWN_SID_TYPE, mask windows.ACCESS_MASK) *windows.ACL {
	t.Helper()
	sid, err := windows.CreateWellKnownSid(sidType)
	if err != nil {
		t.Fatalf("well-known SID: %v", err)
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: mask,
		AccessMode:        windows.GRANT_ACCESS,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	}}, nil)
	if err != nil {
		t.Fatalf("build DACL: %v", err)
	}
	return acl
}

func TestHookAPIAncestorAcceptsStockProgramDataGrant(t *testing.T) {
	acl := ancestorDACL(t, windows.WinBuiltinUsersSid, programDataUsersMask)
	if err := hookAPIRejectUntrustedWindowsWriteACEs("ancestor", acl, true, false); err != nil {
		t.Fatalf("stock C:\\ProgramData grant rejected; the gateway cannot start on a default Windows host: %v", err)
	}
	if err := hookAPIRejectUntrustedWindowsWriteACEs("token dir", acl, true, true); err == nil {
		t.Fatal("token directory must still reject create and write-attribute rights")
	}
}

// The exemption is scoped to BUILTIN\Users because a mapped GENERIC_WRITE ACE
// carries the same write bits as the stock grant, so only the principal
// separates a default ProgramData ACL from a directory opened up to Everyone.
func TestHookAPIAncestorRejectsSameMaskForBroaderPrincipals(t *testing.T) {
	for name, sidType := range map[string]windows.WELL_KNOWN_SID_TYPE{
		"everyone":            windows.WinWorldSid,
		"authenticated_users": windows.WinAuthenticatedUserSid,
	} {
		t.Run(name, func(t *testing.T) {
			acl := ancestorDACL(t, sidType, programDataUsersMask)
			if err := hookAPIRejectUntrustedWindowsWriteACEs("ancestor", acl, true, false); err == nil {
				t.Fatal("ancestor accepted a write grant to a principal Windows does not grant by default")
			}
		})
	}
}

func TestHookAPIAncestorRejectsReplacementRightsForUsers(t *testing.T) {
	const fileDeleteChild windows.ACCESS_MASK = 0x00000040
	for name, mask := range map[string]windows.ACCESS_MASK{
		"delete":       windows.DELETE,
		"delete_child": fileDeleteChild,
		"write_dac":    windows.WRITE_DAC,
		"write_owner":  windows.WRITE_OWNER,
		"generic_all":  windows.GENERIC_ALL,
	} {
		t.Run(name, func(t *testing.T) {
			acl := ancestorDACL(t, windows.WinBuiltinUsersSid, programDataUsersMask|mask)
			if err := hookAPIRejectUntrustedWindowsWriteACEs("ancestor", acl, true, false); err == nil {
				t.Fatalf("ancestor accepted %s, which can replace a protected child", name)
			}
		})
	}
}
