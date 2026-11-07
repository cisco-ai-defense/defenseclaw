// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package safefile

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
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
	if refusal.Path != child || !slices.Equal(refusal.Carriers, []string{parent}) || refusal.Deny || !strings.Contains(refusal.Trustee, "Everyone") {
		t.Fatalf("refusal=%+v, want the entry of Everyone carried by %s", refusal, parent)
	}
	if !strings.Contains(err.Error(), "private path DACL is unsafe to repair: "+child) || !strings.Contains(err.Error(), "inherited from "+parent) {
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

// The carrier is the folder holding the refused entry itself, not a nearer
// folder that holds a harmless entry of the same account: the middle folder
// has its own read entry for Everyone and inherits the write entry from the
// top one, so removing the read entry would leave the refusal (review 1 of
// GAP-0731).
func TestUnsafePrivateDACLCarrierFollowsTheRefusedEntryNotAnyEntryOfTheAccount(t *testing.T) {
	top := filepath.Join(t.TempDir(), "top")
	if err := os.Mkdir(top, 0o700); err != nil {
		t.Fatal(err)
	}
	ownWindowsTestPath(t, top)
	grantEveryone(t, top, windows.GENERIC_ALL, true)
	middle := filepath.Join(top, "middle")
	if err := os.Mkdir(middle, 0o700); err != nil {
		t.Fatal(err)
	}
	grantEveryone(t, middle, windows.FILE_GENERIC_READ, false)
	child := filepath.Join(middle, "plugins")
	if err := os.Mkdir(child, 0o700); err != nil {
		t.Fatal(err)
	}

	err := ValidatePrivateDirectoryOwnershipAllowingAdministrators(child)
	var refusal *UnsafePrivateDACLError
	if !errors.As(err, &refusal) {
		t.Fatalf("err=%v, want an UnsafePrivateDACLError", err)
	}
	if !slices.Equal(refusal.Carriers, []string{top}) {
		t.Fatalf("carriers=%q, want %q (the folder holding the write entry itself)", refusal.Carriers, []string{top})
	}
}

// Two folders can each grant the same account inheritable write: the child
// inherits both, so naming the nearer one alone leaves the refusal in place
// (review 2 of GAP-0731). Every folder that holds an entry of its own for the
// account is named, outermost first.
func TestUnsafePrivateDACLCarriersNameEveryFolderThatGrantsTheEntry(t *testing.T) {
	top := filepath.Join(t.TempDir(), "top")
	if err := os.Mkdir(top, 0o700); err != nil {
		t.Fatal(err)
	}
	ownWindowsTestPath(t, top)
	grantEveryone(t, top, windows.GENERIC_ALL, true)
	middle := filepath.Join(top, "middle")
	if err := os.Mkdir(middle, 0o700); err != nil {
		t.Fatal(err)
	}
	grantEveryone(t, middle, windows.GENERIC_ALL, false)
	child := filepath.Join(middle, "plugins")
	if err := os.Mkdir(child, 0o700); err != nil {
		t.Fatal(err)
	}

	err := ValidatePrivateDirectoryOwnershipAllowingAdministrators(child)
	var refusal *UnsafePrivateDACLError
	if !errors.As(err, &refusal) {
		t.Fatalf("err=%v, want an UnsafePrivateDACLError", err)
	}
	if len(refusal.Carriers) == 0 || refusal.Carriers[0] != top {
		t.Fatalf("carriers=%q, want the outermost grant %q first", refusal.Carriers, top)
	}
	// The set is exactly the folders that hold the refused entry as their own.
	why := &daclRefusal{sid: mustWorldSID(t), inherited: true}
	for _, folder := range []string{top, middle} {
		explicit, _ := daclRefusedEntryOf(folder, why, 0)
		if explicit != slices.Contains(refusal.Carriers, folder) {
			t.Fatalf("folder %s: holds an entry of its own=%v, named=%v (carriers %q)", folder, explicit, slices.Contains(refusal.Carriers, folder), refusal.Carriers)
		}
	}
}

func mustWorldSID(t *testing.T) *windows.SID {
	t.Helper()
	everyone, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		t.Fatal(err)
	}
	return everyone
}

// grantEveryone adds an allow entry for Everyone on path that folders and files
// below inherit. A protected DACL stops inheriting from the parent.
func grantEveryone(t *testing.T, path string, access windows.ACCESS_MASK, protected bool) {
	t.Helper()
	everyone := mustWorldSID(t)
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	old, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: access,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
			TrusteeValue: windows.TrusteeValueFromSID(everyone),
		},
	}}, old)
	if err != nil {
		t.Fatal(err)
	}
	info := windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION | windows.UNPROTECTED_DACL_SECURITY_INFORMATION)
	if protected {
		info = windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, info, nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
}
