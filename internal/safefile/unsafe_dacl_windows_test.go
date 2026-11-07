// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package safefile

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// GAP-0731: the refusal named the inheriting child and no account. The one
// rule that refuses a descriptor also says which entry it refused.
func TestPrivateSecurityDescriptorRefusalNamesTheRefusedEntry(t *testing.T) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sid := user.User.Sid.String()
	subject := windowsProtectionSubject{sid: user.User.Sid}
	users, err := windows.StringToSid("S-1-5-32-545")
	if err != nil {
		t.Fatal(err)
	}

	own, err := windows.SecurityDescriptorFromString("O:" + sid + "D:P(A;;GA;;;" + sid + ")(A;;GA;;;SY)")
	if err != nil {
		t.Fatal(err)
	}
	if refusal, err := privateSecurityDescriptorRefusal(own, subject, true); err != nil || refusal != nil {
		t.Fatalf("a private descriptor was refused: %+v, %v", refusal, err)
	}

	inherited, err := windows.SecurityDescriptorFromString("O:" + sid + "D:(A;;GA;;;" + sid + ")(A;;GA;;;SY)(A;OICIID;FW;;;BU)")
	if err != nil {
		t.Fatal(err)
	}
	refusal, err := privateSecurityDescriptorRefusal(inherited, subject, true)
	if err != nil || refusal == nil || refusal.sid == nil {
		t.Fatalf("refusal=%+v err=%v", refusal, err)
	}
	if !refusal.sid.Equals(users) || !refusal.inherited || refusal.deny {
		t.Fatalf("refusal=%+v, want an inherited allow entry of BUILTIN Users", refusal)
	}

	// The boolean answer is the same rule.
	repairable, err := privateSecurityDescriptorIsWriterRepairableForSubject(inherited, subject, true)
	if err != nil || repairable {
		t.Fatalf("repairable=%v err=%v", repairable, err)
	}

	// A descriptor with no DACL is refused without naming an account.
	owned, err := windows.SecurityDescriptorFromString("O:" + sid)
	if err != nil {
		t.Fatal(err)
	}
	if refusal, err := privateSecurityDescriptorRefusal(owned, subject, true); err != nil || refusal == nil || refusal.sid != nil {
		t.Fatalf("a descriptor without a DACL: refusal=%+v err=%v", refusal, err)
	}
}

// The entry sits on the folder above; the error names that folder and the
// account, and a private tree stays accepted.
func TestUnsafePrivateDACLErrorNamesTheFolderThatCarriesTheEntry(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "opencode")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	ownWindowsTestPath(t, parent)
	everyone, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		t.Fatal(err)
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: windows.GENERIC_ALL,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
			TrusteeValue: windows.TrusteeValueFromSID(everyone),
		},
	}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(
		parent, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, acl, nil,
	); err != nil {
		t.Fatal(err)
	}
	child := filepath.Join(parent, "plugins")
	if err := os.Mkdir(child, 0o700); err != nil {
		t.Fatal(err)
	}

	err = ValidatePrivateDirectoryOwnershipAllowingAdministrators(child)
	var refusal *UnsafePrivateDACLError
	if !errors.As(err, &refusal) {
		t.Fatalf("err=%v, want an UnsafePrivateDACLError", err)
	}
	if refusal.Path != child || refusal.Carrier != parent || refusal.Deny || !strings.Contains(refusal.Trustee, "Everyone") {
		t.Fatalf("refusal=%+v, want the entry of Everyone carried by %s", refusal, parent)
	}
	if !strings.Contains(err.Error(), "private path DACL is unsafe to repair: "+child) || !strings.Contains(err.Error(), parent) {
		t.Fatalf("message lost the refused path or the carrier: %v", err)
	}

	private := filepath.Join(t.TempDir(), "private")
	if _, err := CreatePrivateDirectory(private); err != nil {
		t.Fatal(err)
	}
	if err := ValidatePrivateDirectoryOwnershipAllowingAdministrators(private); err != nil {
		t.Fatalf("a private folder was refused: %v", err)
	}
}
