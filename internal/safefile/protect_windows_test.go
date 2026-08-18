// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package safefile

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestWriteWindowsRemovesInheritedUnauthorizedWriter(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "Unicode space 測試")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	ownWindowsTestPath(t, dir)
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
		dir, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, acl, nil,
	); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(dir, "state.json")
	if err := ProtectDirectory(dir); err != nil {
		t.Fatalf("protect managed directory: %v", err)
	}
	if err := Write(path, []byte(`{"fixture":"synthetic"}`)); err != nil {
		t.Fatalf("initial write: %v", err)
	}
	if err := Write(path, []byte(`{"fixture":"rewritten"}`)); err != nil {
		t.Fatalf("atomic rewrite: %v", err)
	}
	assertNoUnauthorizedWindowsWriter(t, path)
	assertNoUnauthorizedWindowsWriter(t, dir)
}

func TestPrivateDACLRejectsExtendedAndUnknownACETypes(t *testing.T) {
	const (
		accessAllowedObjectACE         = 0x05
		accessDeniedObjectACE          = 0x06
		accessAllowedCallbackACE       = 0x09
		accessDeniedCallbackACE        = 0x0A
		accessAllowedCallbackObjectACE = 0x0B
		accessDeniedCallbackObjectACE  = 0x0C
	)

	for _, tc := range []struct {
		name    string
		aceType byte
		want    bool
	}{
		{name: "basic allow", aceType: windows.ACCESS_ALLOWED_ACE_TYPE, want: true},
		{name: "basic deny", aceType: windows.ACCESS_DENIED_ACE_TYPE, want: true},
		{name: "object allow", aceType: accessAllowedObjectACE},
		{name: "object deny", aceType: accessDeniedObjectACE},
		{name: "callback allow", aceType: accessAllowedCallbackACE},
		{name: "callback deny", aceType: accessDeniedCallbackACE},
		{name: "callback object allow", aceType: accessAllowedCallbackObjectACE},
		{name: "callback object deny", aceType: accessDeniedCallbackObjectACE},
		{name: "unknown future type", aceType: 0x7F},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := isSimpleDiscretionaryACE(tc.aceType); got != tc.want {
				t.Fatalf("isSimpleDiscretionaryACE(0x%x) = %v, want %v", tc.aceType, got, tc.want)
			}
		})
	}
}

func TestWindowsProtectionIdentityDistinguishesActualThreadToken(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	processUser, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || processUser == nil || processUser.User.Sid == nil {
		t.Fatalf("current process token user: %v", err)
	}
	ordinary, err := windowsProtectionIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if ordinary.impersonated {
		t.Fatal("ordinary process unexpectedly has a thread impersonation token")
	}
	if !ordinary.sid.Equals(processUser.User.Sid) {
		t.Fatalf("ordinary protection SID %s, want process SID %s", ordinary.sid, processUser.User.Sid)
	}

	if err := windows.ImpersonateSelf(windows.SecurityImpersonation); err != nil {
		t.Skipf("same-user impersonation unavailable: %v", err)
	}
	defer func() {
		if err := windows.RevertToSelf(); err != nil {
			t.Errorf("revert same-user impersonation: %v", err)
		}
	}()
	impersonated, err := windowsProtectionIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if !impersonated.impersonated {
		t.Fatal("same-SID thread token was misclassified as ordinary process context")
	}
	if !impersonated.sid.Equals(processUser.User.Sid) {
		t.Fatalf("same-user impersonation SID %s, want process SID %s", impersonated.sid, processUser.User.Sid)
	}
}

func TestWindowsPrivateOwnershipRepairUsesImpersonatedSubject(t *testing.T) {
	processUser, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || processUser == nil || processUser.User.Sid == nil {
		t.Fatalf("current process token user: %v", err)
	}
	anonymous, err := windows.CreateWellKnownSid(windows.WinAnonymousSid)
	if err != nil {
		t.Fatal(err)
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	impersonateAnonymous := windows.NewLazySystemDLL("advapi32.dll").NewProc("ImpersonateAnonymousToken")
	result, _, callErr := impersonateAnonymous.Call(uintptr(windows.CurrentThread()))
	if result == 0 {
		t.Fatalf("ImpersonateAnonymousToken: %v", callErr)
	}
	reverted := false
	defer func() {
		if !reverted {
			if err := windows.RevertToSelf(); err != nil {
				t.Errorf("revert anonymous impersonation: %v", err)
			}
		}
	}()

	identity, err := windowsProtectionIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if !identity.impersonated || !identity.sid.Equals(anonymous) {
		t.Fatalf("effective protection subject = %+v, want anonymous SID %s", identity, anonymous)
	}
	if identity.sid.Equals(processUser.User.Sid) {
		t.Fatal("anonymous thread token did not produce a distinct effective SID")
	}
	if err := windows.RevertToSelf(); err != nil {
		t.Fatalf("revert anonymous impersonation: %v", err)
	}
	reverted = true

	sid := identity.sid.String()
	descriptor, err := windows.SecurityDescriptorFromString(
		"O:" + sid + "D:P(A;;GA;;;" + sid + ")(A;;GA;;;SY)",
	)
	if err != nil {
		t.Fatal(err)
	}
	repairable, err := privateSecurityDescriptorIsWriterRepairableForSubject(
		descriptor,
		identity,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !repairable {
		t.Fatal("repairability rejected the effective impersonated subject")
	}
	repairable, err = privateSecurityDescriptorIsWriterRepairableForSubject(
		descriptor,
		windowsProtectionSubject{sid: processUser.User.Sid},
	)
	if err != nil {
		t.Fatal(err)
	}
	if repairable {
		t.Fatal("repairability accepted the different process-token subject")
	}
}

func TestOrdinaryWindowsProtectionRetainsLegacyAdministratorACENormalization(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ordinary-private.json")
	if err := os.WriteFile(path, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	ownWindowsTestPath(t, path)
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		t.Fatalf("current token user: %v", err)
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		t.Fatal(err)
	}
	administrators, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatal(err)
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{
		windowsAccessEntry(user.User.Sid, windows.GENERIC_ALL),
		windowsAccessEntry(system, windows.GENERIC_ALL),
		windowsAccessEntry(administrators, windows.GENERIC_READ),
	}, nil)
	if err != nil {
		t.Fatal(err)
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
		t.Fatal(err)
	}

	identity, err := windowsProtectionIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if identity.impersonated {
		t.Fatal("ordinary test process unexpectedly selected impersonated protection semantics")
	}
	safe, err := privateDACLIsSafe(path)
	if err != nil {
		t.Fatal(err)
	}
	if safe {
		t.Fatal("ordinary protection accepted an Administrators ACE that legacy behavior normalizes")
	}
	if err := ProtectFile(path); err != nil {
		t.Fatalf("normalize ordinary private file: %v", err)
	}
	if got := windowsAllowMaskForSID(t, path, administrators); got != 0 {
		t.Fatalf("Administrators ACE retained mask 0x%x after ordinary normalization", uint32(got))
	}
}

func TestOrdinaryWindowsProtectionRetainsLegacyOwnerRightsCompatibility(t *testing.T) {
	path := filepath.Join(t.TempDir(), "owner-rights.json")
	if err := os.WriteFile(path, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	ownWindowsTestPath(t, path)
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		t.Fatal(err)
	}
	ownerRights, err := windows.CreateWellKnownSid(windows.WinCreatorOwnerRightsSid)
	if err != nil {
		t.Fatal(err)
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{
		windowsAccessEntry(ownerRights, windows.GENERIC_ALL),
		windowsAccessEntry(system, windows.GENERIC_ALL),
	}, nil)
	if err != nil {
		t.Fatal(err)
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
		t.Fatal(err)
	}
	safe, err := privateDACLIsSafe(path)
	if err != nil {
		t.Fatal(err)
	}
	if !safe {
		t.Fatal("ordinary protection rejected the legacy OWNER RIGHTS owner surrogate")
	}
}

func TestWindowsPrivateDACLNormalAndImpersonatedPolicies(t *testing.T) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		t.Fatalf("current token user: %v", err)
	}
	subjectSID, err := user.User.Sid.Copy()
	if err != nil {
		t.Fatal(err)
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		t.Fatal(err)
	}
	administrators, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatal(err)
	}
	everyone, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		t.Fatal(err)
	}
	ownerRights, err := windows.CreateWellKnownSid(windows.WinCreatorOwnerRightsSid)
	if err != nil {
		t.Fatal(err)
	}
	normal := windowsProtectionSubject{sid: subjectSID}
	impersonated := windowsProtectionSubject{sid: subjectSID, impersonated: true}

	tests := []struct {
		name                 string
		entries              []windows.EXPLICIT_ACCESS
		wantNormalSafe       bool
		wantImpersonatedSafe bool
	}{
		{
			name: "exact user and system",
			entries: []windows.EXPLICIT_ACCESS{
				windowsAccessEntry(subjectSID, windows.GENERIC_ALL),
				windowsAccessEntry(system, windows.GENERIC_ALL),
			},
			wantNormalSafe:       true,
			wantImpersonatedSafe: true,
		},
		{
			name: "administrators allow",
			entries: []windows.EXPLICIT_ACCESS{
				windowsAccessEntry(subjectSID, windows.GENERIC_ALL),
				windowsAccessEntry(system, windows.GENERIC_ALL),
				windowsAccessEntry(administrators, windows.GENERIC_READ),
			},
			wantNormalSafe:       false,
			wantImpersonatedSafe: true,
		},
		{
			name: "unrelated deny",
			entries: []windows.EXPLICIT_ACCESS{
				windowsDenyEntry(everyone, windows.GENERIC_WRITE),
				windowsAccessEntry(subjectSID, windows.GENERIC_ALL),
				windowsAccessEntry(system, windows.GENERIC_ALL),
			},
			wantNormalSafe:       true,
			wantImpersonatedSafe: false,
		},
		{
			name: "owner rights substitutes for owner",
			entries: []windows.EXPLICIT_ACCESS{
				windowsAccessEntry(ownerRights, windows.GENERIC_ALL),
				windowsAccessEntry(system, windows.GENERIC_ALL),
			},
			wantNormalSafe:       true,
			wantImpersonatedSafe: false,
		},
		{
			name: "exact owner rights read control",
			entries: []windows.EXPLICIT_ACCESS{
				windowsAccessEntry(subjectSID, windows.GENERIC_ALL),
				windowsAccessEntry(system, windows.GENERIC_ALL),
				windowsAccessEntry(ownerRights, windows.READ_CONTROL),
			},
			wantNormalSafe:       true,
			wantImpersonatedSafe: true,
		},
		{
			name: "excess owner rights",
			entries: []windows.EXPLICIT_ACCESS{
				windowsAccessEntry(subjectSID, windows.GENERIC_ALL),
				windowsAccessEntry(system, windows.GENERIC_ALL),
				windowsAccessEntry(ownerRights, windows.GENERIC_READ),
			},
			wantNormalSafe:       true,
			wantImpersonatedSafe: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "private.json")
			if err := os.WriteFile(path, []byte("fixture"), 0o600); err != nil {
				t.Fatal(err)
			}
			ownWindowsTestPath(t, path)
			acl, err := windows.ACLFromEntries(test.entries, nil)
			if err != nil {
				t.Fatal(err)
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
				t.Fatal(err)
			}
			gotNormal, err := privateDACLIsSafeForSubject(path, normal)
			if err != nil {
				t.Fatal(err)
			}
			if gotNormal != test.wantNormalSafe {
				t.Fatalf("normal safety = %v, want %v", gotNormal, test.wantNormalSafe)
			}
			gotImpersonated, err := privateDACLIsSafeForSubject(path, impersonated)
			if err != nil {
				t.Fatal(err)
			}
			if gotImpersonated != test.wantImpersonatedSafe {
				t.Fatalf(
					"impersonated safety = %v, want %v",
					gotImpersonated,
					test.wantImpersonatedSafe,
				)
			}
		})
	}
}

func TestWindowsPrivateDACLImpersonatedPolicyRequiresProtection(t *testing.T) {
	path := filepath.Join(t.TempDir(), "unprotected.json")
	if err := os.WriteFile(path, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	ownWindowsTestPath(t, path)
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		t.Fatalf("current token user: %v", err)
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		t.Fatal(err)
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{
		windowsAccessEntry(user.User.Sid, windows.GENERIC_ALL),
		windowsAccessEntry(system, windows.GENERIC_ALL),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.UNPROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		acl,
		nil,
	); err != nil {
		t.Fatal(err)
	}
	subjectSID, err := user.User.Sid.Copy()
	if err != nil {
		t.Fatal(err)
	}
	safe, err := privateDACLIsSafeForSubject(
		path,
		windowsProtectionSubject{sid: subjectSID, impersonated: true},
	)
	if err != nil {
		t.Fatal(err)
	}
	if safe {
		t.Fatal("impersonated policy accepted an unprotected DACL")
	}
}

func TestPrivateSecurityDescriptorRejectsForeignOwner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "owned.json")
	if err := WritePrivate(path, []byte("{}")); err != nil {
		t.Fatal(err)
	}
	sd, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		t.Fatal(err)
	}
	absolute, err := sd.ToAbsolute()
	if err != nil {
		t.Fatal(err)
	}
	foreignOwner, err := windows.CreateWellKnownSid(windows.WinLocalServiceSid)
	if err != nil {
		t.Fatal(err)
	}
	if err := absolute.SetOwner(foreignOwner, false); err != nil {
		t.Fatal(err)
	}
	if safe, err := privateSecurityDescriptorIsSafe(absolute); err != nil {
		t.Fatal(err)
	} else if safe {
		t.Fatal("private security descriptor accepted a foreign owner")
	}
}

func TestProtectFileWindowsDoesNotRequireWriteOwner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "owner-no-write-owner.json")
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		t.Fatalf("current token user: %v", err)
	}
	descriptor, err := windows.SecurityDescriptorFromString(
		"O:" + user.User.Sid.String() +
			"D:P(A;;GRGWRCWD;;;" + user.User.Sid.String() + ")(A;;GA;;;SY)",
	)
	if err != nil {
		t.Fatalf("private test descriptor: %v", err)
	}
	attributes := windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: descriptor,
	}
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := windows.CreateFile(
		pathPtr,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ,
		&attributes,
		windows.CREATE_NEW,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		t.Fatalf("create current-user-owned test file: %v", err)
	}
	if err := windows.CloseHandle(handle); err != nil {
		t.Fatalf("close current-user-owned test file: %v", err)
	}
	if mask := windowsAllowMaskForSID(t, path, user.User.Sid); mask&windows.WRITE_OWNER != 0 {
		t.Fatalf("test precondition failed: owner ACE grants WRITE_OWNER (mask 0x%x)", uint32(mask))
	}

	if err := ProtectFile(path); err != nil {
		t.Fatalf("ProtectFile should not require WRITE_OWNER for an already-owned file: %v", err)
	}
	owner, err := windowsPathOwner(path)
	if err != nil {
		t.Fatalf("inspect protected owner: %v", err)
	}
	if owner == nil || !owner.Equals(user.User.Sid) {
		t.Fatalf("ProtectFile changed owner: got %v, want %s", owner, user.User.Sid)
	}
	safe, err := privateDACLIsSafe(path)
	if err != nil {
		t.Fatalf("inspect protected DACL: %v", err)
	}
	if !safe {
		t.Fatal("ProtectFile did not install a protected current-user/SYSTEM DACL")
	}
}

func ownWindowsTestPath(t *testing.T, path string) {
	t.Helper()
	owned, err := windowsPathOwnedByCurrentUser(path)
	if err != nil {
		t.Fatalf("inspect test path owner %s: %v", path, err)
	}
	if owned {
		return
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		t.Fatalf("current token user: %v", err)
	}
	owner, err := windowsPathOwner(path)
	if err != nil {
		t.Fatalf("inspect test path owner %s: %v", path, err)
	}
	if owner != nil && owner.Equals(user.User.Sid) {
		return
	}
	if err := windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION,
		user.User.Sid,
		nil,
		nil,
		nil,
	); err != nil {
		t.Fatalf("own test path %s: %v", path, err)
	}
}

func TestSetPrivateDACLWindowsCurrentOwnerDoesNotRequireWriteOwner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "modify-owned.json")
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	ownWindowsTestPath(t, path)

	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		t.Fatalf("current token user: %v", err)
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		t.Fatal(err)
	}
	modifyWithoutOwner := windows.ACCESS_MASK(
		windows.GENERIC_READ |
			windows.GENERIC_WRITE |
			windows.GENERIC_EXECUTE |
			windows.DELETE,
	)
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{
		windowsAccessEntry(user.User.Sid, modifyWithoutOwner),
		windowsAccessEntry(system, windows.GENERIC_ALL),
	}, nil)
	if err != nil {
		t.Fatal(err)
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
		t.Fatalf("install Modify-only owner fixture: %v", err)
	}
	if mask := windowsAllowMaskForSID(t, path, user.User.Sid); mask&windows.WRITE_OWNER != 0 {
		t.Fatalf("fixture unexpectedly grants WRITE_OWNER: 0x%x", uint32(mask))
	}

	if err := setPrivateDACL(path, false); err != nil {
		t.Fatalf("protect current-user-owned file without WRITE_OWNER: %v", err)
	}
	safe, err := privateDACLIsSafe(path)
	if err != nil {
		t.Fatal(err)
	}
	if !safe {
		t.Fatal("setPrivateDACL did not produce current-user-owned private protection")
	}
}

func TestSetWindowsOwnerIfDifferentSkipsMatchingOwner(t *testing.T) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		t.Fatalf("current token user: %v", err)
	}
	calls := 0
	err = setWindowsOwnerIfDifferent(
		"unused",
		user.User.Sid,
		user.User.Sid,
		func(
			_ string,
			_ windows.SE_OBJECT_TYPE,
			_ windows.SECURITY_INFORMATION,
			_ *windows.SID,
			_ *windows.SID,
			_ *windows.ACL,
			_ *windows.ACL,
		) error {
			calls++
			return windows.ERROR_ACCESS_DENIED
		},
	)
	if err != nil {
		t.Fatalf("matching owner unexpectedly invoked setter: %v", err)
	}
	if calls != 0 {
		t.Fatalf("matching owner invoked setter %d times, want 0", calls)
	}
}

func TestWriteWindowsPreservesStricterExistingDACL(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "stricter.json")
	if err := Write(path, []byte("first")); err != nil {
		t.Fatal(err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		t.Fatal(err)
	}
	entries := []windows.EXPLICIT_ACCESS{
		windowsAccessEntry(user.User.Sid, windows.GENERIC_ALL),
		windowsAccessEntry(system, windows.GENERIC_READ),
	}
	acl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(
		path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, acl, nil,
	); err != nil {
		t.Fatal(err)
	}
	wantSystemMask := windowsAllowMaskForSID(t, path, system)
	if err := Write(path, []byte("second")); err != nil {
		t.Fatal(err)
	}
	if got := windowsAllowMaskForSID(t, path, system); got != wantSystemMask {
		t.Fatalf("SYSTEM mask = 0x%x, want preserved 0x%x", uint32(got), uint32(wantSystemMask))
	}
}

func TestWriteWindowsReplacesForeignReadACE(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "private.json")
	if err := Write(path, []byte("first")); err != nil {
		t.Fatal(err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		t.Fatal(err)
	}
	everyone, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		t.Fatal(err)
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{
		windowsAccessEntry(user.User.Sid, windows.GENERIC_ALL),
		windowsAccessEntry(system, windows.GENERIC_ALL),
		windowsAccessEntry(everyone, windows.GENERIC_READ),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(
		path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, acl, nil,
	); err != nil {
		t.Fatal(err)
	}
	if err := Write(path, []byte("second")); err != nil {
		t.Fatal(err)
	}
	if mask := windowsAllowMaskForSID(t, path, everyone); mask != 0 {
		t.Fatalf("Everyone retained read access mask 0x%x", uint32(mask))
	}
}

func TestProtectDirectoryWindowsRejectsNestedJunction(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(root, "outside")
	child := filepath.Join(outside, "child")
	if err := os.MkdirAll(child, 0o700); err != nil {
		t.Fatal(err)
	}
	junction := filepath.Join(root, "junction")
	if output, err := exec.Command("cmd.exe", "/d", "/c", "mklink", "/J", junction, outside).CombinedOutput(); err != nil {
		t.Skipf("junction creation unavailable: %v (%s)", err, output)
	}
	defer os.Remove(junction)

	if err := ProtectDirectory(filepath.Join(junction, "child")); err == nil {
		t.Fatal("ProtectDirectory accepted a nested junction escape")
	}
}

func TestCreatePrivateDirectoryWindowsReportsCreation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "created-private")
	created, err := CreatePrivateDirectory(path)
	if err != nil {
		t.Fatalf("CreatePrivateDirectory: %v", err)
	}
	if !created {
		t.Fatal("CreatePrivateDirectory did not report creating a missing target")
	}
	safe, err := privateDACLIsSafe(path)
	if err != nil {
		t.Fatalf("inspect created directory DACL: %v", err)
	}
	if !safe {
		t.Fatal("created directory does not have a private DACL")
	}

	created, err = CreatePrivateDirectory(path)
	if err != nil {
		t.Fatalf("CreatePrivateDirectory existing target: %v", err)
	}
	if created {
		t.Fatal("CreatePrivateDirectory reported creating an existing target")
	}
}

func TestCreatePrivateDirectoryWindowsPreservesExistingACL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "operator-owned")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	ownWindowsTestPath(t, path)
	everyone, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		t.Fatal(err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		t.Fatalf("current token user: %v", err)
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{
		windowsAccessEntry(user.User.Sid, windows.GENERIC_ALL),
		windowsAccessEntry(everyone, windows.GENERIC_WRITE),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(
		path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, acl, nil,
	); err != nil {
		t.Fatal(err)
	}
	wantMask := windowsAllowMaskForSID(t, path, everyone)

	created, err := CreatePrivateDirectory(path)
	if err != nil {
		t.Fatalf("CreatePrivateDirectory existing target: %v", err)
	}
	if created {
		t.Fatal("CreatePrivateDirectory reported creating an existing target")
	}
	if got := windowsAllowMaskForSID(t, path, everyone); got != wantMask {
		t.Fatalf("existing Everyone mask = 0x%x, want preserved 0x%x", uint32(got), uint32(wantMask))
	}
}

func TestCreateExclusiveWindowsRejectsParentJunction(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(root, "outside")
	if err := os.Mkdir(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	junction := filepath.Join(root, "junction")
	if output, err := exec.Command("cmd.exe", "/d", "/c", "mklink", "/J", junction, outside).CombinedOutput(); err != nil {
		t.Skipf("junction creation unavailable: %v (%s)", err, output)
	}
	defer os.Remove(junction)

	target := filepath.Join(junction, "exclusive.json")
	if _, err := CreateExclusive(target); err == nil {
		t.Fatal("CreateExclusive accepted a parent junction escape")
	}
	if _, err := os.Stat(filepath.Join(outside, "exclusive.json")); !os.IsNotExist(err) {
		t.Fatalf("exclusive file escaped through junction: %v", err)
	}
}

func TestWritePrivateWindowsHoldsDirectoryAgainstSwap(t *testing.T) {
	root := t.TempDir()
	parent := filepath.Join(root, "managed")
	target := filepath.Join(parent, "state.json")
	moved := filepath.Join(root, "moved")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	swapRefused := false
	err := writePrivate(target, []byte("synthetic fixture"), func() {
		if renameErr := os.Rename(parent, moved); renameErr != nil {
			swapRefused = true
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	if !swapRefused {
		t.Fatal("managed directory was swappable while private write lock was held")
	}
	if _, err := os.Stat(target); err != nil {
		t.Fatalf("state file missing after locked write: %v", err)
	}
}

func windowsAccessEntry(sid *windows.SID, mask windows.ACCESS_MASK) windows.EXPLICIT_ACCESS {
	return windows.EXPLICIT_ACCESS{
		AccessPermissions: mask,
		AccessMode:        windows.GRANT_ACCESS,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_USER,
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	}
}

func windowsDenyEntry(sid *windows.SID, mask windows.ACCESS_MASK) windows.EXPLICIT_ACCESS {
	return windows.EXPLICIT_ACCESS{
		AccessPermissions: mask,
		AccessMode:        windows.DENY_ACCESS,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_USER,
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	}
}

func windowsAllowMaskForSID(t *testing.T, path string, want *windows.SID) windows.ACCESS_MASK {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		t.Fatalf("DACL: %v", err)
	}
	for index := uint16(0); index < dacl.AceCount; index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(index), &ace); err != nil {
			t.Fatal(err)
		}
		if ace == nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if sid.Equals(want) {
			return ace.Mask
		}
	}
	return 0
}

func assertNoUnauthorizedWindowsWriter(t *testing.T, path string) {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(
		path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		t.Fatal(err)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		t.Fatalf("DACL: %v", err)
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		t.Fatal(err)
	}
	foundSystem := false
	const writeLike = windows.GENERIC_ALL | windows.GENERIC_WRITE | windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER | windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA | windows.FILE_WRITE_EA | windows.FILE_WRITE_ATTRIBUTES | 0x40
	for index := uint16(0); index < dacl.AceCount; index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(index), &ace); err != nil {
			t.Fatal(err)
		}
		if ace == nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Mask&writeLike == 0 {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if sid.Equals(system) {
			foundSystem = true
			continue
		}
		if owner != nil && sid.Equals(owner) {
			continue
		}
		t.Fatalf("unauthorized writable SID %s on %s", sid.String(), path)
	}
	if !foundSystem {
		t.Fatalf("LocalSystem access missing on %s", path)
	}
}
