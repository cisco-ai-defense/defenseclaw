//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

func TestWindowsAuthorizedRepairRecoversSelfDeniedConfigDACL(t *testing.T) {
	var rescue windows.Handle
	fixture := newWindowsGenericCodexFixtureBeforeProtection(t, func(configPath string) {
		rescue = openWindowsDACLRescueHandle(t, configPath)
	})
	t.Cleanup(func() { _ = windows.CloseHandle(rescue) })
	canonical, err := windowsUserPathProtectionACL(fixture.targetSID, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = windows.SetSecurityInfo(
			rescue,
			windows.SE_FILE_OBJECT,
			windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
			nil,
			nil,
			canonical,
			nil,
		)
	})
	setWindowsSelfDenyDACLOnHandle(t, rescue, fixture.targetSID, windows.GENERIC_READ)

	if _, err := os.ReadFile(fixture.config); !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		t.Fatalf("self-denied config read error = %v, want access denied", err)
	}
	opts := fixture.opts
	opts.AllowMissingHookConfigRepair = true
	if _, err := installWindowsGenericManagedResult(context.Background(), opts); err != nil {
		t.Fatalf("authorized repair: %v", err)
	}
	if err := validateWindowsUserPathElement(fixture.config, fixture.targetSID, false, false, true); err != nil {
		t.Fatalf("repaired config DACL: %v", err)
	}
}

func TestWindowsGuardianDACLRepairCannotRewriteProfileRoot(t *testing.T) {
	target := currentWindowsTestSID(t)
	home := filepath.Join(t.TempDir(), "home")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := setWindowsUserPathProtection(home, target, true); err != nil {
		t.Fatal(err)
	}
	before := windowsTestSecurityDescriptorString(t, home)

	originalEffective := windowsEnterpriseEffectiveTokenCheck
	originalGuardian := windowsEnterpriseGuardianDACLRepair
	windowsEnterpriseEffectiveTokenCheck = func(*windows.SID) error { return nil }
	guardianCalled := false
	windowsEnterpriseGuardianDACLRepair = func(string, string, *windows.SID, bool) error {
		guardianCalled = true
		return nil
	}
	t.Cleanup(func() {
		windowsEnterpriseEffectiveTokenCheck = originalEffective
		windowsEnterpriseGuardianDACLRepair = originalGuardian
	})

	if err := repairWindowsTargetOwnedPathDACL(home, home, target, true); err == nil {
		t.Fatal("authorized repair wrapper accepted profile-root DACL rewrite")
	}
	if guardianCalled {
		t.Fatal("profile-root DACL rewrite reached guardian callback")
	}
	if err := repairWindowsTargetOwnedPathDACLNoFollow(home, home, target, true); err == nil {
		t.Fatal("no-follow repair implementation accepted profile-root DACL rewrite")
	}
	after := windowsTestSecurityDescriptorString(t, home)
	if after != before {
		t.Fatalf("profile-root DACL changed:\nbefore=%s\nafter=%s", before, after)
	}
}

func TestWindowsOwnerRightsDenialDispatchesBoundedGuardianRepair(t *testing.T) {
	target := currentWindowsTestSID(t)
	home := filepath.Join(t.TempDir(), "home")
	path := filepath.Join(home, "hooks.json")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rescue := openWindowsDACLRescueHandle(t, path)
	t.Cleanup(func() { _ = windows.CloseHandle(rescue) })
	if err := setWindowsUserPathProtection(home, target, true); err != nil {
		t.Fatal(err)
	}
	if err := setWindowsUserPathProtection(path, target, false); err != nil {
		t.Fatal(err)
	}

	setWindowsOwnerRightsDenyDACLOnHandle(t, rescue, target)
	canonical, err := windowsUserPathProtectionACL(target, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = windows.SetSecurityInfo(
			rescue,
			windows.SE_FILE_OBJECT,
			windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
			nil,
			nil,
			canonical,
			nil,
		)
	})

	if err := repairWindowsTargetOwnedPathDACLNoFollow(home, path, target, false); err == nil {
		t.Fatal("owner token unexpectedly bypassed OWNER RIGHTS denial without guardian privilege")
	}

	originalEffective := windowsEnterpriseEffectiveTokenCheck
	originalGuardian := windowsEnterpriseGuardianDACLRepair
	windowsEnterpriseEffectiveTokenCheck = func(*windows.SID) error { return nil }
	guardianCalls := 0
	windowsEnterpriseGuardianDACLRepair = func(gotHome, gotPath string, gotTarget *windows.SID, directory bool) error {
		guardianCalls++
		if !sameWindowsEnterprisePath(gotHome, home) ||
			!sameWindowsEnterprisePath(gotPath, path) ||
			gotTarget == nil ||
			!gotTarget.Equals(target) ||
			directory {
			return errors.New("guardian DACL repair received a widened target")
		}
		return windows.SetSecurityInfo(
			rescue,
			windows.SE_FILE_OBJECT,
			windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
			nil,
			nil,
			canonical,
			nil,
		)
	}
	t.Cleanup(func() {
		windowsEnterpriseEffectiveTokenCheck = originalEffective
		windowsEnterpriseGuardianDACLRepair = originalGuardian
	})

	if err := repairWindowsTargetOwnedPathDACL(home, path, target, false); err != nil {
		t.Fatalf("bounded guardian repair dispatch: %v", err)
	}
	if guardianCalls != 1 {
		t.Fatalf("guardian repair calls = %d, want 1", guardianCalls)
	}
	if err := validateWindowsUserPathElement(path, target, false, false, true); err != nil {
		t.Fatalf("guardian-repaired OWNER RIGHTS DACL: %v", err)
	}
}

func TestWindowsGuardianDACLWalkRejectsIntermediateJunction(t *testing.T) {
	target := currentWindowsTestSID(t)
	scope := t.TempDir()
	home := filepath.Join(scope, "home")
	outside := filepath.Join(scope, "outside")
	child := filepath.Join(outside, "sentinel.json")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(child, []byte("outside-sentinel\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct {
		path string
		dir  bool
	}{
		{home, true},
		{outside, true},
		{child, false},
	} {
		if err := setWindowsUserPathProtection(item.path, target, item.dir); err != nil {
			t.Fatalf("protect %s: %v", item.path, err)
		}
	}
	link := filepath.Join(home, "redirect")
	if err := os.Symlink(outside, link); err != nil {
		output, junctionErr := exec.Command("cmd.exe", "/d", "/c", "mklink", "/J", link, outside).CombinedOutput()
		if junctionErr != nil {
			t.Fatalf("create junction after symlink error %v: %v: %s", err, junctionErr, output)
		}
	}

	err := repairWindowsTargetOwnedPathDACLNoFollow(
		home,
		filepath.Join(link, filepath.Base(child)),
		target,
		false,
	)
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "reparse") {
		t.Fatalf("intermediate junction repair error = %v, want no-follow refusal", err)
	}
	data, readErr := os.ReadFile(child)
	if readErr != nil || string(data) != "outside-sentinel\n" {
		t.Fatalf("outside sentinel changed: data=%q err=%v", data, readErr)
	}
}

func TestWindowsGuardianDACLRepairRequiresExactTargetAuthorization(t *testing.T) {
	target := currentWindowsTestSID(t)
	other, err := windows.StringToSid("S-1-5-21-111-222-333-1001")
	if err != nil {
		t.Fatal(err)
	}
	originalEffective := windowsEnterpriseEffectiveTokenCheck
	originalGuardian := windowsEnterpriseGuardianDACLRepair
	sentinel := errors.New("effective target mismatch")
	windowsEnterpriseEffectiveTokenCheck = func(got *windows.SID) error {
		if got == nil || !got.Equals(target) {
			return sentinel
		}
		return nil
	}
	guardianCalled := false
	windowsEnterpriseGuardianDACLRepair = func(string, string, *windows.SID, bool) error {
		guardianCalled = true
		return nil
	}
	t.Cleanup(func() {
		windowsEnterpriseEffectiveTokenCheck = originalEffective
		windowsEnterpriseGuardianDACLRepair = originalGuardian
	})

	err = repairWindowsTargetOwnedPathDACL(`C:\Users\alice`, `C:\Users\alice\.codex\config.toml`, other, false)
	if !errors.Is(err, sentinel) {
		t.Fatalf("authorization error = %v, want %v", err, sentinel)
	}
	if guardianCalled {
		t.Fatal("guardian repair ran without exact target-token authorization")
	}
}

func setWindowsSelfDenyDACL(t *testing.T, path string, owner *windows.SID, denied windows.ACCESS_MASK) {
	t.Helper()
	setWindowsTestDACL(t, path, windowsSelfDenyTestACL(t, owner, denied))
}

func setWindowsSelfDenyDACLOnHandle(
	t *testing.T,
	handle windows.Handle,
	owner *windows.SID,
	denied windows.ACCESS_MASK,
) {
	t.Helper()
	setWindowsTestDACLOnHandle(t, handle, windowsSelfDenyTestACL(t, owner, denied))
}

func windowsSelfDenyTestACL(
	t *testing.T,
	owner *windows.SID,
	denied windows.ACCESS_MASK,
) *windows.ACL {
	t.Helper()
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		t.Fatal(err)
	}
	administrators, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatal(err)
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{
		windowsDACLTestEntry(owner, denied, windows.DENY_ACCESS),
		windowsDACLTestEntry(owner, windows.GENERIC_ALL, windows.GRANT_ACCESS),
		windowsDACLTestEntry(system, windows.GENERIC_ALL, windows.GRANT_ACCESS),
		windowsDACLTestEntry(administrators, windows.GENERIC_ALL, windows.GRANT_ACCESS),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return acl
}

func setWindowsOwnerRightsDenyDACL(t *testing.T, path string, owner *windows.SID) {
	t.Helper()
	setWindowsTestDACL(t, path, windowsOwnerRightsDenyTestACL(t, owner))
}

func setWindowsOwnerRightsDenyDACLOnHandle(
	t *testing.T,
	handle windows.Handle,
	owner *windows.SID,
) {
	t.Helper()
	setWindowsTestDACLOnHandle(t, handle, windowsOwnerRightsDenyTestACL(t, owner))
}

func windowsOwnerRightsDenyTestACL(t *testing.T, owner *windows.SID) *windows.ACL {
	t.Helper()
	ownerRights, err := windows.CreateWellKnownSid(windows.WinCreatorOwnerRightsSid)
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
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{
		windowsDACLTestEntry(
			ownerRights,
			windows.READ_CONTROL|windows.WRITE_DAC|windows.FILE_READ_ATTRIBUTES,
			windows.DENY_ACCESS,
		),
		windowsDACLTestEntry(
			owner,
			windows.FILE_GENERIC_READ|windows.FILE_GENERIC_WRITE|windows.DELETE,
			windows.GRANT_ACCESS,
		),
		windowsDACLTestEntry(system, windows.GENERIC_ALL, windows.GRANT_ACCESS),
		windowsDACLTestEntry(administrators, windows.GENERIC_ALL, windows.GRANT_ACCESS),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return acl
}

func windowsDACLTestEntry(
	sid *windows.SID,
	mask windows.ACCESS_MASK,
	mode windows.ACCESS_MODE,
) windows.EXPLICIT_ACCESS {
	return windows.EXPLICIT_ACCESS{
		AccessPermissions: mask,
		AccessMode:        mode,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_USER,
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	}
}

func setWindowsTestDACL(t *testing.T, path string, acl *windows.ACL) {
	t.Helper()
	extended, err := winpath.Extended(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(
		extended,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		acl,
		nil,
	); err != nil {
		t.Fatalf("set hostile DACL on %s: %v", path, err)
	}
}

func setWindowsTestDACLOnHandle(t *testing.T, handle windows.Handle, acl *windows.ACL) {
	t.Helper()
	if err := windows.SetSecurityInfo(
		handle,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		acl,
		nil,
	); err != nil {
		t.Fatalf("set hostile DACL by rescue handle: %v", err)
	}
}

func openWindowsDACLRescueHandle(t *testing.T, path string) windows.Handle {
	t.Helper()
	extended, err := winpath.Extended(path)
	if err != nil {
		t.Fatal(err)
	}
	ptr, err := windows.UTF16PtrFromString(extended)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := windows.CreateFile(
		ptr,
		windows.READ_CONTROL|windows.WRITE_DAC,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS,
		0,
	)
	if err != nil {
		t.Fatalf("open DACL rescue handle: %v", err)
	}
	return handle
}
