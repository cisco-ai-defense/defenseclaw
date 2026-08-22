//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"golang.org/x/sys/windows"
)

var auditDBWindowsServiceAccountSID = managed.WindowsServiceAccountSID

func openAuditDBFileNoFollow(path string, create, harden bool) (*os.File, error) {
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, fmt.Errorf("audit: encode Windows database path: %w", err)
	}
	disposition := uint32(windows.OPEN_EXISTING)
	if create {
		disposition = windows.CREATE_NEW
	}
	handle, err := windows.CreateFile(
		pathPtr,
		auditDBWindowsFileAccess(harden),
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		disposition,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return nil, err
	}
	var handleInfo windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &handleInfo); err != nil {
		_ = windows.CloseHandle(handle)
		return nil, fmt.Errorf("audit: inspect Windows database handle: %w", err)
	}
	if handleInfo.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		_ = windows.CloseHandle(handle)
		return nil, errors.New("audit: database file must not be a reparse point")
	}
	if handleInfo.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 {
		_ = windows.CloseHandle(handle)
		return nil, errors.New("audit: database file must be regular")
	}
	if handleInfo.NumberOfLinks != 1 {
		_ = windows.CloseHandle(handle)
		return nil, fmt.Errorf(
			"audit: database file has %d hard links, expected exactly 1",
			handleInfo.NumberOfLinks,
		)
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		_ = windows.CloseHandle(handle)
		return nil, errors.New("audit: create Windows database file handle")
	}
	return file, nil
}

func auditDBWindowsFileAccess(harden bool) uint32 {
	access := uint32(windows.GENERIC_READ | windows.GENERIC_WRITE)
	if harden {
		// ACL-changing access is short-lived and reserved for a new file or an
		// existing safe file whose protected DACL still needs to be installed.
		access |= windows.WRITE_DAC
	}
	return access
}

// auditDBPlatformFileNeedsHardening validates the security descriptor through
// the already pinned no-follow handle. A protected, trusted descriptor needs
// no WRITE_DAC reopen; an unprotected but otherwise trusted descriptor is
// eligible for the narrowly scoped hardening path.
func auditDBPlatformFileNeedsHardening(file *os.File) (bool, error) {
	if file == nil {
		return false, errors.New("audit: inspect Windows file ACL: file handle is unavailable")
	}
	sd, err := windows.GetSecurityInfo(
		windows.Handle(file.Fd()),
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return false, fmt.Errorf("audit: inspect pinned Windows security descriptor: %w", err)
	}
	if err := validateAuditDBWindowsSecurityDescriptor(file.Name(), sd, false, true); err != nil {
		return false, err
	}
	control, _, err := sd.Control()
	if err != nil {
		return false, fmt.Errorf("audit: inspect pinned Windows DACL control: %w", err)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		return true, nil
	}
	gatewayServiceSID, err := auditDBWindowsPinnedGatewayServiceSID()
	if err != nil {
		return false, err
	}
	if gatewayServiceSID == nil {
		return false, nil
	}
	currentUser, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || currentUser == nil || currentUser.User.Sid == nil {
		return false, fmt.Errorf("audit: resolve current Windows user for managed audit validation: %w", err)
	}
	if !currentUser.User.Sid.Equals(gatewayServiceSID) {
		return false, fmt.Errorf(
			"audit: managed gateway token SID %s does not match pinned service SID %s",
			auditDBWindowsSID(currentUser.User.Sid),
			auditDBWindowsSID(gatewayServiceSID),
		)
	}
	canonical, err := auditDBWindowsManagedRuntimeFileCanonical(sd, gatewayServiceSID)
	if err != nil {
		return false, err
	}
	return !canonical, nil
}

func auditDBPlatformSidecarNeedsHardening(file *os.File) (bool, error) {
	return auditDBPlatformFileNeedsHardening(file)
}

func auditDBPlatformHardeningNeedsCapabilityReopen() bool { return true }

func validateAuditDBPlatformTrust(path string, _ os.FileInfo, directory, protectChildren bool) error {
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return fmt.Errorf("audit: encode Windows path: %w", err)
	}
	attributes, err := windows.GetFileAttributes(pathPtr)
	if err != nil {
		return fmt.Errorf("audit: inspect Windows path attributes: %w", err)
	}
	if attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errors.New("audit: database path contains a Windows reparse point")
	}

	sd, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return fmt.Errorf("audit: inspect Windows security descriptor: %w", err)
	}
	return validateAuditDBWindowsSecurityDescriptor(path, sd, directory, protectChildren)
}

func validateAuditDBWindowsSecurityDescriptor(
	path string,
	sd *windows.SECURITY_DESCRIPTOR,
	directory bool,
	protectChildren bool,
) error {
	if sd == nil {
		return errors.New("audit: missing Windows security descriptor")
	}
	gatewayServiceSID, err := auditDBWindowsPinnedGatewayServiceSID()
	if err != nil {
		return err
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return fmt.Errorf("audit: inspect Windows owner: %w", err)
	}
	if !auditDBWindowsTrustedPrincipal(owner, gatewayServiceSID) {
		return fmt.Errorf("audit: Windows owner %s is not trusted", auditDBWindowsSID(owner))
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("audit: inspect Windows DACL: %w", err)
	}
	if dacl == nil {
		return errors.New("audit: null Windows DACL is not trusted")
	}
	return rejectUntrustedAuditDBWindowsACEs(
		path,
		dacl,
		directory,
		protectChildren,
		gatewayServiceSID,
	)
}

func secureAuditDBPlatformPath(path string, directory bool) error {
	dacl, err := auditDBWindowsProtectedDACL(directory)
	if err != nil {
		return err
	}
	if err := windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		dacl,
		nil,
	); err != nil {
		return fmt.Errorf("audit: apply protected Windows DACL: %w", err)
	}
	return nil
}

func secureAuditDBPlatformFile(file *os.File, directory bool) error {
	if file == nil {
		return errors.New("audit: secure Windows file ACL: file handle is unavailable")
	}
	ownerDescriptor, err := windows.GetSecurityInfo(
		windows.Handle(file.Fd()),
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION,
	)
	if err != nil {
		return fmt.Errorf("audit: inspect Windows file owner before DACL hardening: %w", err)
	}
	owner, _, err := ownerDescriptor.Owner()
	if err != nil || owner == nil {
		return fmt.Errorf("audit: resolve Windows file owner before DACL hardening: %w", err)
	}
	dacl, err := auditDBWindowsProtectedDACLForOwner(directory, owner)
	if err != nil {
		return err
	}
	if err := windows.SetSecurityInfo(
		windows.Handle(file.Fd()),
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		dacl,
		nil,
	); err != nil {
		return fmt.Errorf("audit: apply protected Windows DACL by handle: %w", err)
	}
	// Verify the exact handle that received SetSecurityInfo before releasing the
	// short-lived WRITE_DAC capability. Managed files must now match either the
	// installer RuntimeFile form or the owner-suppressing runtime form.
	if directory {
		sd, err := windows.GetSecurityInfo(
			windows.Handle(file.Fd()),
			windows.SE_FILE_OBJECT,
			windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
		)
		if err != nil {
			return fmt.Errorf("audit: verify protected Windows directory DACL by handle: %w", err)
		}
		if err := validateAuditDBWindowsSecurityDescriptor(file.Name(), sd, true, true); err != nil {
			return fmt.Errorf("audit: verify protected Windows directory DACL by handle: %w", err)
		}
		control, _, err := sd.Control()
		if err != nil {
			return fmt.Errorf("audit: inspect protected Windows directory DACL control: %w", err)
		}
		if control&windows.SE_DACL_PROTECTED == 0 {
			return errors.New("audit: protected Windows directory DACL verification failed")
		}
		return nil
	}
	needsHardening, err := auditDBPlatformFileNeedsHardening(file)
	if err != nil {
		return fmt.Errorf("audit: verify protected Windows file DACL by handle: %w", err)
	}
	if needsHardening {
		return errors.New("audit: protected Windows file DACL remains noncanonical after hardening")
	}
	return nil
}

func auditDBWindowsProtectedDACL(directory bool) (*windows.ACL, error) {
	return auditDBWindowsProtectedDACLForOwner(directory, nil)
}

func auditDBWindowsProtectedDACLForOwner(
	directory bool,
	owner *windows.SID,
) (*windows.ACL, error) {
	gatewayServiceSID, err := auditDBWindowsPinnedGatewayServiceSID()
	if err != nil {
		return nil, err
	}
	currentUser, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || currentUser == nil || currentUser.User.Sid == nil {
		return nil, fmt.Errorf("audit: resolve current Windows user: %w", err)
	}
	administrators, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return nil, fmt.Errorf("audit: resolve Windows Administrators SID: %w", err)
	}
	localSystem, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return nil, fmt.Errorf("audit: resolve Windows LocalSystem SID: %w", err)
	}
	inheritance := uint32(windows.NO_INHERITANCE)
	if directory {
		inheritance = uint32(windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT)
	}
	if gatewayServiceSID != nil {
		if !currentUser.User.Sid.Equals(gatewayServiceSID) {
			return nil, fmt.Errorf(
				"audit: managed gateway token SID %s does not match pinned service SID %s",
				auditDBWindowsSID(currentUser.User.Sid),
				auditDBWindowsSID(gatewayServiceSID),
			)
		}
		ownerRights, err := windows.CreateWellKnownSid(windows.WinCreatorOwnerRightsSid)
		if err != nil {
			return nil, fmt.Errorf("audit: resolve Windows OWNER RIGHTS SID: %w", err)
		}
		const (
			fileAllAccess windows.ACCESS_MASK = 0x001f01ff
			fileModify    windows.ACCESS_MASK = 0x001301bf
		)
		entries := make([]windows.EXPLICIT_ACCESS, 0, 4)
		if directory || owner == nil || !owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
			entries = append(entries,
				auditDBWindowsExplicitAccess(ownerRights, windows.READ_CONTROL, windows.NO_INHERITANCE),
			)
		}
		entries = append(entries,
			auditDBWindowsExplicitAccess(localSystem, fileAllAccess, inheritance),
			auditDBWindowsExplicitAccess(administrators, fileAllAccess, inheritance),
			auditDBWindowsExplicitAccess(gatewayServiceSID, fileModify, inheritance),
		)
		dacl, err := windows.ACLFromEntries(entries, nil)
		if err != nil {
			return nil, fmt.Errorf("audit: build managed protected Windows DACL: %w", err)
		}
		return dacl, nil
	}
	trustedSIDs := []*windows.SID{currentUser.User.Sid, administrators, localSystem}
	entries := make([]windows.EXPLICIT_ACCESS, 0, len(trustedSIDs))
	seen := make(map[string]struct{}, len(trustedSIDs))
	for _, sid := range trustedSIDs {
		if sid == nil {
			continue
		}
		key := strings.ToUpper(sid.String())
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		entries = append(entries, windows.EXPLICIT_ACCESS{
			AccessPermissions: windows.GENERIC_ALL,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       inheritance,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_USER,
				TrusteeValue: windows.TrusteeValueFromSID(sid),
			},
		})
	}
	dacl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		return nil, fmt.Errorf("audit: build protected Windows DACL: %w", err)
	}
	return dacl, nil
}

func auditDBWindowsExplicitAccess(
	sid *windows.SID,
	mask windows.ACCESS_MASK,
	inheritance uint32,
) windows.EXPLICIT_ACCESS {
	return windows.EXPLICIT_ACCESS{
		AccessPermissions: mask,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       inheritance,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_USER,
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	}
}

func auditDBWindowsManagedRuntimeFileCanonical(
	sd *windows.SECURITY_DESCRIPTOR,
	gatewayServiceSID *windows.SID,
) (bool, error) {
	if sd == nil || gatewayServiceSID == nil {
		return false, nil
	}
	control, _, err := sd.Control()
	if err != nil {
		return false, err
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		return false, nil
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return false, err
	}
	ownerIsAdministrators := owner.IsWellKnown(windows.WinBuiltinAdministratorsSid)
	ownerIsGateway := owner.Equals(gatewayServiceSID)
	if !ownerIsAdministrators && !ownerIsGateway {
		return false, nil
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		return false, err
	}
	localSystem, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return false, err
	}
	administrators, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return false, err
	}
	ownerRights, err := windows.CreateWellKnownSid(windows.WinCreatorOwnerRightsSid)
	if err != nil {
		return false, err
	}
	const (
		fileAllAccess windows.ACCESS_MASK = 0x001f01ff
		fileModify    windows.ACCESS_MASK = 0x001301bf
	)
	type expectedACE struct {
		sid  *windows.SID
		mask windows.ACCESS_MASK
	}
	expected := []expectedACE{
		{sid: localSystem, mask: fileAllAccess},
		{sid: administrators, mask: fileAllAccess},
		{sid: gatewayServiceSID, mask: fileModify},
	}
	ownerRightsSeen := false
	seen := make([]bool, len(expected))
	for index := uint16(0); index < dacl.AceCount; index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(index), &ace); err != nil {
			return false, err
		}
		if ace == nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags != 0 {
			return false, nil
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if sid.Equals(ownerRights) {
			if ownerRightsSeen || ace.Mask != windows.READ_CONTROL {
				return false, nil
			}
			ownerRightsSeen = true
			continue
		}
		matched := false
		for candidate, want := range expected {
			if !seen[candidate] && sid.Equals(want.sid) && ace.Mask == want.mask {
				seen[candidate] = true
				matched = true
				break
			}
		}
		if !matched {
			return false, nil
		}
	}
	for _, found := range seen {
		if !found {
			return false, nil
		}
	}
	if ownerIsAdministrators && ownerRightsSeen {
		return false, nil
	}
	if ownerIsGateway && !ownerRightsSeen {
		return false, nil
	}
	wantCount := len(expected)
	if ownerRightsSeen {
		wantCount++
	}
	return int(dacl.AceCount) == wantCount, nil
}

func rejectUntrustedAuditDBWindowsACEs(
	path string,
	dacl *windows.ACL,
	directory bool,
	protectChildren bool,
	gatewayServiceSID *windows.SID,
) error {
	const (
		accessAllowedCompoundACEType       = 0x4
		accessAllowedObjectACEType         = 0x5
		accessAllowedCallbackACEType       = 0x9
		accessAllowedCallbackObjectACEType = 0xB
	)
	for i := uint16(0); i < dacl.AceCount; i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(i), &ace); err != nil {
			return fmt.Errorf("audit: inspect Windows ACE %d for %s: %w", i, path, err)
		}
		if ace == nil {
			continue
		}
		inheritOnly := ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0
		inheritsToChildren := ace.Header.AceFlags&(windows.OBJECT_INHERIT_ACE|windows.CONTAINER_INHERIT_ACE) != 0
		if inheritOnly && (!directory || !protectChildren || !inheritsToChildren) {
			continue
		}
		readExposesSidecars := protectChildren && (!directory || inheritsToChildren) &&
			auditDBWindowsReadLikeAccess(ace.Mask)
		if !auditDBWindowsWriteLikeAccess(ace.Mask, protectChildren) && !readExposesSidecars {
			continue
		}
		switch ace.Header.AceType {
		case accessAllowedCompoundACEType, accessAllowedObjectACEType,
			accessAllowedCallbackACEType, accessAllowedCallbackObjectACEType:
			return fmt.Errorf("audit: unsupported Windows allow ACE type 0x%x on %s", ace.Header.AceType, path)
		case windows.ACCESS_ALLOWED_ACE_TYPE:
		default:
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if sid.IsWellKnown(windows.WinCreatorOwnerRightsSid) ||
			inheritOnly && sid.IsWellKnown(windows.WinCreatorOwnerSid) {
			continue
		}
		if !auditDBWindowsTrustedPrincipal(sid, gatewayServiceSID) {
			return fmt.Errorf(
				"audit: untrusted Windows principal %s has access mask 0x%x that can expose or modify audit storage on %s",
				auditDBWindowsSID(sid), uint32(ace.Mask), path,
			)
		}
	}
	return nil
}

func auditDBWindowsReadLikeAccess(mask windows.ACCESS_MASK) bool {
	readLike := windows.ACCESS_MASK(
		windows.GENERIC_READ |
			windows.FILE_READ_DATA |
			windows.FILE_READ_EA |
			windows.FILE_READ_ATTRIBUTES |
			windows.FILE_EXECUTE,
	)
	return mask&readLike != 0
}

func auditDBWindowsWriteLikeAccess(mask windows.ACCESS_MASK, protectChildren bool) bool {
	const fileDeleteChild windows.ACCESS_MASK = 0x00000040
	unsafeMask := windows.ACCESS_MASK(
		windows.GENERIC_ALL |
			windows.DELETE |
			windows.WRITE_DAC |
			windows.WRITE_OWNER |
			fileDeleteChild,
	)
	if protectChildren {
		unsafeMask |= windows.GENERIC_WRITE | windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA |
			windows.FILE_WRITE_EA | windows.FILE_WRITE_ATTRIBUTES
	}
	return mask&unsafeMask != 0
}

func auditDBWindowsTrustedPrincipal(
	sid *windows.SID,
	gatewayServiceSID *windows.SID,
) bool {
	if sid == nil {
		return false
	}
	if sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) || sid.IsWellKnown(windows.WinLocalSystemSid) {
		return true
	}
	if gatewayServiceSID != nil && sid.Equals(gatewayServiceSID) {
		return true
	}
	currentUser, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err == nil && currentUser != nil && currentUser.User.Sid != nil && sid.Equals(currentUser.User.Sid) {
		return true
	}
	trustedInstaller, err := windows.StringToSid("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464")
	return err == nil && sid.Equals(trustedInstaller)
}

func auditDBWindowsPinnedGatewayServiceSID() (*windows.SID, error) {
	account := os.Getenv(managed.WindowsServiceAccountEnv)
	serviceName := os.Getenv(connector.WindowsGatewayServiceNameEnv)
	if account == "" && serviceName == "" {
		return nil, nil
	}
	if account == "" || serviceName == "" {
		return nil, errors.New(
			"audit: managed Windows gateway service identity pins are incomplete",
		)
	}
	if err := connector.ValidateWindowsManagedGatewayServiceName(serviceName); err != nil {
		return nil, fmt.Errorf("audit: invalid managed gateway service name: %w", err)
	}
	expectedAccount := `NT SERVICE\` + serviceName
	if !strings.EqualFold(account, expectedAccount) ||
		account != strings.TrimSpace(account) {
		return nil, fmt.Errorf(
			"audit: managed service account %q does not match exact gateway service %q",
			account,
			serviceName,
		)
	}
	sid, err := auditDBWindowsServiceAccountSID(account)
	if err != nil {
		return nil, fmt.Errorf(
			"audit: resolve exact managed gateway service SID: %w",
			err,
		)
	}
	if sid == nil {
		return nil, errors.New("audit: exact managed gateway service SID is unavailable")
	}
	return sid, nil
}

func auditDBWindowsSID(sid *windows.SID) string {
	if sid == nil {
		return "<nil>"
	}
	return sid.String()
}

func trustedAuditDBSystemDirectoryAlias(string, os.FileInfo) bool { return false }

// Windows mode bits are synthesized; the protected DACL is authoritative.
func auditDBModeMatches(os.FileInfo, os.FileMode) bool { return true }

// Windows FileInfo permissions are synthesized POSIX bits and do not express
// who can mutate the directory. validateAuditDBPlatformTrust already proves
// owner, protected DACL, inheritance, and every write-capable ACE.
func auditDBImmediateDirectoryModeTrusted(os.FileInfo) bool { return true }
