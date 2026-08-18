// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

func TestHookAPIWindowsTrustUsesEffectiveImpersonatedUserSID(t *testing.T) {
	t.Setenv(managed.DeploymentModeEnv, managed.DeploymentModeManagedEnterprise)
	targetSID, err := windows.StringToSid("S-1-5-21-111-222-333-1001")
	if err != nil {
		t.Fatal(err)
	}
	pinWindowsEffectiveUserSIDForTest(t, targetSID)
	if !hookAPIWindowsTrustedPrincipal(targetSID) {
		t.Fatal("effective impersonated user SID was not trusted")
	}
	previous := windowsEffectiveUserSID
	windowsEffectiveUserSID = func() (*windows.SID, error) {
		return nil, errors.New("thread token unavailable")
	}
	t.Cleanup(func() { windowsEffectiveUserSID = previous })
	if hookAPIWindowsTrustedPrincipal(targetSID) {
		t.Fatal("effective-token lookup failure trusted a non-system target SID")
	}
}

// A thread token can be installed outside managed mode, so trust follows the
// effective user rather than the deployment mode.
func TestHookAPIWindowsTrustUsesEffectiveUserSIDOutsideManagedMode(t *testing.T) {
	t.Setenv(managed.DeploymentModeEnv, "")
	targetSID, err := windows.StringToSid("S-1-5-21-111-222-333-1002")
	if err != nil {
		t.Fatal(err)
	}
	pinWindowsEffectiveUserSIDForTest(t, targetSID)
	if !hookAPIWindowsTrustedPrincipal(targetSID) {
		t.Fatal("effective user SID was not trusted outside managed mode")
	}
}

func TestManagedWindowsTokenOperationsAllowOnlyPinnedGatewayServiceSID(t *testing.T) {
	const serviceAccount = `NT SERVICE\EventLog`
	serviceSID, err := managed.WindowsServiceAccountSID(serviceAccount)
	if err != nil {
		t.Fatalf("resolve fixture service SID: %v", err)
	}
	dataDir := testenv.PrivateTempDir(t)
	setHookAPITokenWindowsServiceDACL(t, dataDir, serviceSID)
	t.Setenv(managed.DeploymentModeEnv, managed.DeploymentModeManagedEnterprise)
	t.Setenv(managed.WindowsServiceAccountEnv, serviceAccount)

	hookToken, err := EnsureHookAPIToken(dataDir, "codex")
	if err != nil {
		t.Fatalf("EnsureHookAPIToken with pinned service SID: %v", err)
	}
	if loaded, err := LoadHookAPIToken(dataDir, "codex"); err != nil || loaded != hookToken {
		t.Fatalf("LoadHookAPIToken = %q, %v; want %q", loaded, err, hookToken)
	}
	otlpToken, err := EnsureOTLPPathToken(dataDir, OTLPScopeCodex)
	if err != nil {
		t.Fatalf("EnsureOTLPPathToken with pinned service SID: %v", err)
	}
	if loaded, err := LoadOTLPPathToken(dataDir, OTLPScopeCodex); err != nil || loaded != otlpToken {
		t.Fatalf("LoadOTLPPathToken = %q, %v; want %q", loaded, err, otlpToken)
	}

	t.Setenv(managed.WindowsServiceAccountEnv, `NT SERVICE\DefenseClawNonexistentFixture`)
	if token, err := LoadHookAPIToken(dataDir, "codex"); err == nil {
		t.Fatalf("LoadHookAPIToken accepted a different/unresolved service SID; token=%q", token)
	}
	t.Setenv(managed.WindowsServiceAccountEnv, serviceAccount)
	t.Setenv(managed.DeploymentModeEnv, "")
	if token, err := LoadHookAPIToken(dataDir, "codex"); err == nil {
		t.Fatalf("normal mode accepted managed service-SID write access; token=%q", token)
	}
}

func setHookAPITokenWindowsServiceDACL(t *testing.T, path string, serviceSID *windows.SID) {
	t.Helper()
	currentUser, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatalf("current token user: %v", err)
	}
	const serviceModify = windows.GENERIC_READ |
		windows.GENERIC_WRITE |
		windows.GENERIC_EXECUTE |
		windows.DELETE
	entries := []windows.EXPLICIT_ACCESS{
		{
			AccessPermissions: windows.GENERIC_ALL,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_USER,
				TrusteeValue: windows.TrusteeValueFromSID(currentUser.User.Sid),
			},
		},
		{
			AccessPermissions: serviceModify,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_USER,
				TrusteeValue: windows.TrusteeValueFromSID(serviceSID),
			},
		},
	}
	acl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		t.Fatalf("build service runtime DACL: %v", err)
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
		t.Fatalf("set service runtime DACL: %v", err)
	}
}

func TestPublishHookAPITokenWindowsPreservesManagedCustodyDACL(t *testing.T) {
	dataDir := testenv.PrivateTempDir(t)
	token := strings.Repeat("a", 64)
	if err := PublishHookAPIToken(dataDir, "amp", token); err != nil {
		t.Fatalf("PublishHookAPIToken: %v", err)
	}
	tokenPath, err := HookAPITokenFilePath(dataDir, "amp")
	if err != nil {
		t.Fatal(err)
	}

	parent, err := openAtomicTransformBoundDirectoryPlatform(filepath.Dir(tokenPath))
	if err != nil {
		t.Fatalf("open bound hook token directory: %v", err)
	}
	defer parent.Close()
	file, err := openAtomicTransformBoundFilePlatform(parent, filepath.Base(tokenPath), false)
	if err != nil {
		t.Fatalf("open bound hook token file: %v", err)
	}
	defer file.Close()
	if err := validateHookAPITokenBoundFileCustodyPlatform(file); err != nil {
		t.Fatalf("managed hook token custody validation: %v", err)
	}
	if err := validateAtomicTransformBoundFilePrivatePlatform(file); err == nil ||
		!strings.Contains(err.Error(), "grants access to another principal") {
		t.Fatalf("generic private-file validation error = %v, want scoped Administrators rejection", err)
	}

	descriptor, err := windows.GetSecurityInfo(
		windows.Handle(file.Fd()),
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		t.Fatalf("read published hook token security descriptor: %v", err)
	}
	control, _, err := descriptor.Control()
	if err != nil {
		t.Fatalf("read published hook token DACL control: %v", err)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		t.Fatal("published hook token DACL is inheritable")
	}
	owner, _, err := descriptor.Owner()
	if err != nil {
		t.Fatalf("read published hook token owner: %v", err)
	}
	currentUser, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatalf("current token user: %v", err)
	}
	if owner == nil || currentUser == nil || currentUser.User.Sid == nil || !owner.Equals(currentUser.User.Sid) {
		t.Fatalf("published hook token owner = %s, want current user", hookAPIWindowsSIDString(owner))
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		t.Fatalf("read published hook token DACL: %v", err)
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		t.Fatalf("LocalSystem SID: %v", err)
	}
	administrators, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatalf("Administrators SID: %v", err)
	}
	for _, principal := range []struct {
		name string
		sid  *windows.SID
	}{
		{name: "current user", sid: currentUser.User.Sid},
		{name: "LocalSystem", sid: system},
		{name: "Administrators", sid: administrators},
	} {
		if !windowsACLGrantsGenericAllToSID(t, dacl, principal.sid) {
			t.Fatalf("published hook token DACL does not grant GENERIC_ALL to %s", principal.name)
		}
	}
}

func TestPublishHookAPITokenWindowsPreservesExactCustomCustodyDescriptor(t *testing.T) {
	dataDir := testenv.PrivateTempDir(t)
	oldToken := strings.Repeat("a", 64)
	newToken := strings.Repeat("b", 64)
	if err := PublishHookAPIToken(dataDir, "amp", oldToken); err != nil {
		t.Fatalf("seed hook API token: %v", err)
	}
	tokenPath, err := HookAPITokenFilePath(dataDir, "amp")
	if err != nil {
		t.Fatal(err)
	}
	setHookAPITokenWindowsCustomCustodyDACL(t, tokenPath, windows.GENERIC_READ)
	before, beforeInfo := captureHookAPITokenWindowsProtectionAndInfo(t, tokenPath)

	if err := PublishHookAPIToken(dataDir, "amp", newToken); err != nil {
		t.Fatalf("publish changed hook API token: %v", err)
	}
	after, afterInfo := captureHookAPITokenWindowsProtectionAndInfo(t, tokenPath)
	if os.SameFile(beforeInfo, afterInfo) {
		t.Fatal("changed publication did not replace the token inode")
	}
	if !hookAPITokenPublishProtectionsEqual(before, after) {
		t.Fatal("changed publication did not preserve the exact accepted owner/DACL/protection descriptor")
	}
	raw, err := os.ReadFile(tokenPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != newToken+"\n" {
		t.Fatal("changed publication did not publish the requested token bytes")
	}
}

func TestPublishHookAPITokenWindowsRollbackRestoresExactCustomCustodyDescriptor(t *testing.T) {
	dataDir := testenv.PrivateTempDir(t)
	oldToken := strings.Repeat("a", 64)
	newToken := strings.Repeat("b", 64)
	if err := PublishHookAPIToken(dataDir, "amp", oldToken); err != nil {
		t.Fatalf("seed hook API token: %v", err)
	}
	tokenPath, err := HookAPITokenFilePath(dataDir, "amp")
	if err != nil {
		t.Fatal(err)
	}
	setHookAPITokenWindowsCustomCustodyDACL(t, tokenPath, windows.GENERIC_READ)
	before := captureHookAPITokenWindowsProtection(t, tokenPath)

	originalPublisher := publishHookAPITokenFile
	publishHookAPITokenFile = func(source, destination string, info os.FileInfo, mode os.FileMode) error {
		if err := atomicFilePublishHookAPIToken(source, destination, info, mode); err != nil {
			return err
		}
		return errors.New("injected failure after publication")
	}
	t.Cleanup(func() { publishHookAPITokenFile = originalPublisher })

	err = PublishHookAPIToken(dataDir, "amp", newToken)
	if err == nil || !strings.Contains(err.Error(), "injected failure after publication") {
		t.Fatalf("PublishHookAPIToken error = %v, want injected post-publication failure", err)
	}
	after := captureHookAPITokenWindowsProtection(t, tokenPath)
	if !hookAPITokenPublishProtectionsEqual(before, after) {
		t.Fatal("rollback did not restore the exact accepted owner/DACL/protection descriptor")
	}
	raw, readErr := os.ReadFile(tokenPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(raw) != oldToken+"\n" {
		t.Fatal("rollback did not restore the original token bytes")
	}
}

func TestPublishHookAPITokenWindowsRollbackRejectsDACLOnlyConcurrentMutation(t *testing.T) {
	dataDir := testenv.PrivateTempDir(t)
	oldToken := strings.Repeat("a", 64)
	newToken := strings.Repeat("b", 64)
	if err := PublishHookAPIToken(dataDir, "amp", oldToken); err != nil {
		t.Fatalf("seed hook API token: %v", err)
	}
	tokenPath, err := HookAPITokenFilePath(dataDir, "amp")
	if err != nil {
		t.Fatal(err)
	}
	setHookAPITokenWindowsCustomCustodyDACL(t, tokenPath, windows.GENERIC_READ)

	var concurrentProtection hookAPITokenPublishProtection
	originalPublisher := publishHookAPITokenFile
	publishHookAPITokenFile = func(source, destination string, info os.FileInfo, mode os.FileMode) error {
		if err := atomicFilePublishHookAPIToken(source, destination, info, mode); err != nil {
			return err
		}
		// Preserve the just-published bytes and mutate only the otherwise-safe
		// DACL. Rollback must treat this as a concurrent state change.
		setHookAPITokenWindowsCustomCustodyDACL(t, destination, windows.GENERIC_ALL)
		concurrentProtection = captureHookAPITokenWindowsProtection(t, destination)
		return errors.New("injected failure after DACL-only concurrent mutation")
	}
	t.Cleanup(func() { publishHookAPITokenFile = originalPublisher })

	err = PublishHookAPIToken(dataDir, "amp", newToken)
	if err == nil || !strings.Contains(err.Error(), "changed before rollback") {
		t.Fatalf("PublishHookAPIToken error = %v, want DACL-only concurrent-change refusal", err)
	}
	after := captureHookAPITokenWindowsProtection(t, tokenPath)
	if !hookAPITokenPublishProtectionsEqual(concurrentProtection, after) {
		t.Fatal("rollback overwrote the concurrent DACL-only mutation")
	}
	raw, readErr := os.ReadFile(tokenPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(raw) != newToken+"\n" {
		t.Fatal("rollback overwrote bytes associated with the concurrent DACL-only mutation")
	}
}

func captureHookAPITokenWindowsProtection(t *testing.T, tokenPath string) hookAPITokenPublishProtection {
	t.Helper()
	protection, _ := captureHookAPITokenWindowsProtectionAndInfo(t, tokenPath)
	return protection
}

func captureHookAPITokenWindowsProtectionAndInfo(
	t *testing.T, tokenPath string,
) (hookAPITokenPublishProtection, os.FileInfo) {
	t.Helper()
	parent, err := openAtomicTransformBoundDirectoryPlatform(filepath.Dir(tokenPath))
	if err != nil {
		t.Fatalf("open bound hook token directory: %v", err)
	}
	defer parent.Close()
	file, err := openAtomicTransformBoundFilePlatform(parent, filepath.Base(tokenPath), false)
	if err != nil {
		t.Fatalf("open bound hook token file: %v", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		t.Fatalf("stat bound hook token file: %v", err)
	}
	protection, private, err := captureHookAPITokenPublishProtectionPlatform(file, info)
	if err != nil {
		t.Fatalf("capture bound hook token protection: %v", err)
	}
	if !private {
		t.Fatal("custom hook token descriptor does not satisfy managed custody")
	}
	return protection, info
}

func setHookAPITokenWindowsCustomCustodyDACL(
	t *testing.T, tokenPath string, trustedInstallerAccess windows.ACCESS_MASK,
) {
	t.Helper()
	currentUser, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatalf("current token user: %v", err)
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		t.Fatalf("LocalSystem SID: %v", err)
	}
	administrators, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatalf("Administrators SID: %v", err)
	}
	trustedInstaller, err := windows.StringToSid("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464")
	if err != nil {
		t.Fatalf("TrustedInstaller SID: %v", err)
	}
	entries := make([]windows.EXPLICIT_ACCESS, 0, 4)
	for _, principal := range []struct {
		sid        *windows.SID
		permission windows.ACCESS_MASK
		typeID     windows.TRUSTEE_TYPE
	}{
		{currentUser.User.Sid, windows.GENERIC_ALL, windows.TRUSTEE_IS_USER},
		{system, windows.GENERIC_ALL, windows.TRUSTEE_IS_WELL_KNOWN_GROUP},
		{administrators, windows.GENERIC_ALL, windows.TRUSTEE_IS_WELL_KNOWN_GROUP},
		{trustedInstaller, trustedInstallerAccess, windows.TRUSTEE_IS_USER},
	} {
		entries = append(entries, windows.EXPLICIT_ACCESS{
			AccessPermissions: principal.permission,
			AccessMode:        windows.GRANT_ACCESS,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  principal.typeID,
				TrusteeValue: windows.TrusteeValueFromSID(principal.sid),
			},
		})
	}
	dacl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		t.Fatalf("build custom custody DACL: %v", err)
	}
	if err := windows.SetNamedSecurityInfo(
		tokenPath,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		dacl,
		nil,
	); err != nil {
		t.Fatalf("set custom custody DACL: %v", err)
	}
}

func windowsACLGrantsGenericAllToSID(t *testing.T, dacl *windows.ACL, want *windows.SID) bool {
	t.Helper()
	const fileAllAccess windows.ACCESS_MASK = 0x001F01FF
	for index := uint16(0); index < dacl.AceCount; index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(index), &ace); err != nil {
			t.Fatalf("read Windows ACE %d: %v", index, err)
		}
		if ace == nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE ||
			ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 ||
			(ace.Mask&windows.GENERIC_ALL == 0 && ace.Mask&fileAllAccess != fileAllAccess) {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if sid.Equals(want) {
			return true
		}
	}
	return false
}

func TestHookAPITokenWindowsRejectsUntrustedDirectoryACL(t *testing.T) {
	assertHookAPITokenRejectedByEnsureAndLoad(t, "untrusted Windows principal", func(t *testing.T) string {
		dataDir := testenv.PrivateTempDir(t)
		if _, err := EnsureHookAPIToken(dataDir, "codex"); err != nil {
			t.Fatalf("seed token: %v", err)
		}
		currentUser, err := windows.GetCurrentProcessToken().GetTokenUser()
		if err != nil {
			t.Fatalf("current token user: %v", err)
		}
		everyone, err := windows.CreateWellKnownSid(windows.WinWorldSid)
		if err != nil {
			t.Fatalf("Everyone SID: %v", err)
		}
		entries := []windows.EXPLICIT_ACCESS{
			{
				AccessPermissions: windows.GENERIC_ALL,
				AccessMode:        windows.GRANT_ACCESS,
				Inheritance:       windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT,
				Trustee: windows.TRUSTEE{
					TrusteeForm:  windows.TRUSTEE_IS_SID,
					TrusteeType:  windows.TRUSTEE_IS_USER,
					TrusteeValue: windows.TrusteeValueFromSID(currentUser.User.Sid),
				},
			},
			{
				AccessPermissions: windows.GENERIC_WRITE,
				AccessMode:        windows.GRANT_ACCESS,
				Inheritance:       windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT,
				Trustee: windows.TRUSTEE{
					TrusteeForm:  windows.TRUSTEE_IS_SID,
					TrusteeType:  windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
					TrusteeValue: windows.TrusteeValueFromSID(everyone),
				},
			},
		}
		acl, err := windows.ACLFromEntries(entries, nil)
		if err != nil {
			t.Fatalf("build DACL: %v", err)
		}
		hooksDir := filepath.Join(dataDir, "hooks")
		if err := windows.SetNamedSecurityInfo(
			hooksDir,
			windows.SE_FILE_OBJECT,
			windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
			nil,
			nil,
			acl,
			nil,
		); err != nil {
			t.Fatalf("set untrusted DACL: %v", err)
		}
		return dataDir
	})
}

func TestHookAPITokenWindowsAllowsReadOnlyUnsupportedAllowACE(t *testing.T) {
	everyone, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		t.Fatalf("Everyone SID: %v", err)
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: windows.GENERIC_READ,
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
	ace.Header.AceType = 0x5
	if err := hookAPIRejectUntrustedWindowsWriteACEs("test", acl, false, true); err != nil {
		t.Fatalf("read-only unsupported allow ACE was rejected: %v", err)
	}
}

func TestHookAPITokenWindowsAllowsInheritOnlyCreatorOwnerTemplate(t *testing.T) {
	creatorOwner, err := windows.CreateWellKnownSid(windows.WinCreatorOwnerSid)
	if err != nil {
		t.Fatalf("Creator Owner SID: %v", err)
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: windows.GENERIC_WRITE,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT | windows.INHERIT_ONLY,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
			TrusteeValue: windows.TrusteeValueFromSID(creatorOwner),
		},
	}}, nil)
	if err != nil {
		t.Fatalf("build DACL: %v", err)
	}
	if err := hookAPIRejectUntrustedWindowsWriteACEs("test", acl, true, true); err != nil {
		t.Fatalf("inherit-only Creator Owner template was rejected: %v", err)
	}
}

func TestHookAPITokenWindowsAllowsOwnerRightsACE(t *testing.T) {
	ownerRights, err := windows.CreateWellKnownSid(windows.WinCreatorOwnerRightsSid)
	if err != nil {
		t.Fatalf("Owner Rights SID: %v", err)
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: windows.GENERIC_ALL,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
			TrusteeValue: windows.TrusteeValueFromSID(ownerRights),
		},
	}}, nil)
	if err != nil {
		t.Fatalf("build DACL: %v", err)
	}
	if err := hookAPIRejectUntrustedWindowsWriteACEs("test", acl, true, true); err != nil {
		t.Fatalf("Owner Rights ACE was rejected after trusted-owner validation: %v", err)
	}
}

func TestHookAPITokenWindowsRejectsDirectCreatorOwnerACE(t *testing.T) {
	creatorOwner, err := windows.CreateWellKnownSid(windows.WinCreatorOwnerSid)
	if err != nil {
		t.Fatalf("Creator Owner SID: %v", err)
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: windows.GENERIC_WRITE,
		AccessMode:        windows.GRANT_ACCESS,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
			TrusteeValue: windows.TrusteeValueFromSID(creatorOwner),
		},
	}}, nil)
	if err != nil {
		t.Fatalf("build DACL: %v", err)
	}
	if err := hookAPIRejectUntrustedWindowsWriteACEs("test", acl, true, true); err == nil {
		t.Fatal("direct Creator Owner ACE was accepted")
	}
}

func TestHookAPITokenWindowsAllowsCreateChildOnSharedAncestor(t *testing.T) {
	everyone, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		t.Fatalf("Everyone SID: %v", err)
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: windows.FILE_WRITE_DATA,
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
	if err := hookAPIRejectUntrustedWindowsWriteACEs("ancestor", acl, true, false); err != nil {
		t.Fatalf("shared ancestor create-child permission was rejected: %v", err)
	}
}

func TestHookAPITokenWindowsRejectsOrdinaryWriteOnSharedAncestor(t *testing.T) {
	everyone, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		t.Fatalf("Everyone SID: %v", err)
	}

	for _, tc := range []struct {
		name string
		mask windows.ACCESS_MASK
	}{
		{name: "generic_write", mask: windows.GENERIC_WRITE},
		{name: "write_extended_attributes", mask: windows.FILE_WRITE_EA},
		{name: "write_attributes", mask: windows.FILE_WRITE_ATTRIBUTES},
	} {
		t.Run(tc.name, func(t *testing.T) {
			acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
				AccessPermissions: tc.mask,
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
			if err := hookAPIRejectUntrustedWindowsWriteACEs("ancestor", acl, true, false); err == nil {
				t.Fatalf("shared ancestor accepted untrusted %s access", tc.name)
			}
		})
	}
}

func TestHookAPITokenWindowsRejectsWritableAncestorThroughPublicOperations(t *testing.T) {
	for _, tc := range []struct {
		name string
		mask windows.ACCESS_MASK
	}{
		{name: "generic_write", mask: windows.GENERIC_WRITE},
		{name: "write_extended_attributes", mask: windows.FILE_WRITE_EA},
		{name: "write_attributes", mask: windows.FILE_WRITE_ATTRIBUTES},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assertHookAPITokenRejectedByEnsureAndLoad(t, "untrusted Windows principal", func(t *testing.T) string {
				root := testenv.PrivateTempDir(t)
				ancestor := filepath.Join(root, "ancestor")
				dataDir := filepath.Join(ancestor, "data")
				if err := os.MkdirAll(dataDir, 0o700); err != nil {
					t.Fatalf("create token data path: %v", err)
				}
				if _, err := EnsureHookAPIToken(dataDir, "codex"); err != nil {
					t.Fatalf("seed token: %v", err)
				}
				setHookAPITokenWindowsUntrustedDACL(t, ancestor, tc.mask)
				return dataDir
			})
		})
	}
}

func TestHookAPITokenWindowsAllowsInheritOnlyTemplateOnSharedAncestor(t *testing.T) {
	const inheritedModifyMask windows.ACCESS_MASK = 0xe0010000

	authenticatedUsers, err := windows.CreateWellKnownSid(windows.WinAuthenticatedUserSid)
	if err != nil {
		t.Fatalf("Authenticated Users SID: %v", err)
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: inheritedModifyMask,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT | windows.INHERIT_ONLY,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
			TrusteeValue: windows.TrusteeValueFromSID(authenticatedUsers),
		},
	}}, nil)
	if err != nil {
		t.Fatalf("build DACL: %v", err)
	}
	if err := hookAPIRejectUntrustedWindowsWriteACEs("ancestor", acl, true, false); err != nil {
		t.Fatalf("shared ancestor inherit-only template was rejected: %v", err)
	}
	if err := hookAPIRejectUntrustedWindowsWriteACEs("protected", acl, true, true); err == nil {
		t.Fatal("protected directory inherit-only template was accepted")
	}
}

func TestHookAPITokenWindowsRejectsDeleteChildOnSharedAncestor(t *testing.T) {
	const fileDeleteChild windows.ACCESS_MASK = 0x00000040

	everyone, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		t.Fatalf("Everyone SID: %v", err)
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: fileDeleteChild,
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
	if err := hookAPIRejectUntrustedWindowsWriteACEs("ancestor", acl, true, false); err == nil {
		t.Fatal("shared ancestor delete-child permission was accepted")
	}
}

func TestHookAPITokenWindowsRejectsReparsePointDirectory(t *testing.T) {
	assertHookAPITokenRejectedByEnsureAndLoadAny(t, []string{"reparse points are not allowed", "escapes hooks dir"}, func(t *testing.T) string {
		dataDir := testenv.PrivateTempDir(t)
		targetDataDir := testenv.PrivateTempDir(t)
		if _, err := EnsureHookAPIToken(targetDataDir, "codex"); err != nil {
			t.Fatalf("seed target token: %v", err)
		}
		createTestDirectoryRedirect(t, filepath.Join(dataDir, "hooks"), filepath.Join(targetDataDir, "hooks"))
		return dataDir
	})
}

func setHookAPITokenWindowsUntrustedDACL(t *testing.T, path string, mask windows.ACCESS_MASK) {
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
			Inheritance:       windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_USER,
				TrusteeValue: windows.TrusteeValueFromSID(currentUser.User.Sid),
			},
		},
		{
			AccessPermissions: mask,
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
		t.Fatalf("set untrusted ancestor DACL: %v", err)
	}
}
