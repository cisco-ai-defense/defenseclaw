// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

// hookAPITokenPublishProtection is the exact self-relative owner/DACL witness
// captured from a bound token handle. The SDDL witness preserves owner SID,
// DACL protection, and exact ACE order, types, flags, masks, and principals,
// including AI/AR provenance flags that SetSecurityInfo can normalize.
// The descriptor is retained solely so an accepted witness can be applied to Stage.
type hookAPITokenPublishProtection struct {
	descriptor *windows.SECURITY_DESCRIPTOR
	owner      string
	dacl       string
	protected  bool
}

func captureHookAPITokenPublishProtectionPlatform(
	file *os.File, _ os.FileInfo,
) (hookAPITokenPublishProtection, bool, error) {
	if file == nil {
		return hookAPITokenPublishProtection{}, false, fmt.Errorf("missing bound hook API token file")
	}
	handle := windows.Handle(file.Fd())
	if err := validateAtomicTransformWindowsHandleType(handle, false); err != nil {
		return hookAPITokenPublishProtection{}, false, err
	}
	descriptor, err := windows.GetSecurityInfo(
		handle,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return hookAPITokenPublishProtection{}, false, fmt.Errorf("inspect bound hook API token security descriptor: %w", err)
	}
	if descriptor == nil {
		return hookAPITokenPublishProtection{}, false, fmt.Errorf("missing bound hook API token security descriptor")
	}
	owner, _, err := descriptor.Owner()
	if err != nil {
		return hookAPITokenPublishProtection{}, false, fmt.Errorf("inspect bound hook API token owner: %w", err)
	}
	if !hookAPIWindowsTrustedPrincipal(owner) {
		return hookAPITokenPublishProtection{}, false, fmt.Errorf(
			"owner %s is not trusted for bound hook API token", hookAPIWindowsSIDString(owner),
		)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return hookAPITokenPublishProtection{}, false, fmt.Errorf("inspect bound hook API token DACL: %w", err)
	}
	if dacl == nil {
		return hookAPITokenPublishProtection{}, false, fmt.Errorf("null Windows DACL is not trusted for bound hook API token")
	}
	if err := hookAPIRejectUntrustedWindowsWriteACEs(file.Name(), dacl, false, true); err != nil {
		return hookAPITokenPublishProtection{}, false, err
	}
	control, _, err := descriptor.Control()
	if err != nil {
		return hookAPITokenPublishProtection{}, false, fmt.Errorf("inspect bound hook API token DACL control: %w", err)
	}
	sddl := descriptor.String()
	if sddl == "" {
		return hookAPITokenPublishProtection{}, false, fmt.Errorf("convert bound hook API token security descriptor to SDDL")
	}
	exactDACL, err := hookAPITokenWindowsExactDACLFromSDDL(sddl)
	if err != nil {
		return hookAPITokenPublishProtection{}, false, err
	}
	protection := hookAPITokenPublishProtection{
		descriptor: descriptor,
		owner:      owner.String(),
		dacl:       exactDACL,
		protected:  control&windows.SE_DACL_PROTECTED != 0,
	}
	private := protection.protected && otlpWindowsRejectUntrustedReadACEs(file.Name(), dacl) == nil
	runtime.KeepAlive(descriptor)
	return protection, private, nil
}

func applyHookAPITokenPublishProtectionPlatform(
	file *os.File, protection hookAPITokenPublishProtection,
) error {
	if hookAPITokenPublishProtectionIsZero(protection) {
		return nil
	}
	owner, _, err := protection.descriptor.Owner()
	if err != nil {
		return fmt.Errorf("read authenticated hook API token owner: %w", err)
	}
	dacl, _, err := protection.descriptor.DACL()
	if err != nil {
		return fmt.Errorf("read authenticated hook API token DACL: %w", err)
	}
	if dacl == nil {
		return fmt.Errorf("read authenticated hook API token DACL: DACL is absent")
	}
	control, _, err := protection.descriptor.Control()
	if err != nil {
		return fmt.Errorf("read authenticated hook API token DACL control: %w", err)
	}
	securityInformation := windows.SECURITY_INFORMATION(
		windows.DACL_SECURITY_INFORMATION,
	)
	var ownerToSet *windows.SID
	currentDescriptor, err := windows.GetSecurityInfo(
		windows.Handle(file.Fd()), windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION,
	)
	if err != nil {
		return fmt.Errorf("inspect staged hook API token owner: %w", err)
	}
	currentOwner, _, err := currentDescriptor.Owner()
	if err != nil {
		return fmt.Errorf("read staged hook API token owner: %w", err)
	}
	if currentOwner == nil || !currentOwner.Equals(owner) {
		securityInformation |= windows.OWNER_SECURITY_INFORMATION
		ownerToSet = owner
	}
	if control&windows.SE_DACL_PROTECTED != 0 {
		securityInformation |= windows.PROTECTED_DACL_SECURITY_INFORMATION
	} else {
		securityInformation |= windows.UNPROTECTED_DACL_SECURITY_INFORMATION
	}
	if err := windows.SetSecurityInfo(
		windows.Handle(file.Fd()), windows.SE_FILE_OBJECT, securityInformation,
		ownerToSet, nil, dacl, nil,
	); err != nil {
		return fmt.Errorf("apply authenticated hook API token security descriptor: %w", err)
	}
	runtime.KeepAlive(protection.descriptor)
	runtime.KeepAlive(currentDescriptor)
	if err := windows.FlushFileBuffers(windows.Handle(file.Fd())); err != nil {
		return fmt.Errorf("flush authenticated hook API token security descriptor: %w", err)
	}
	return nil
}

func hookAPITokenPublishProtectionIsZero(protection hookAPITokenPublishProtection) bool {
	return protection.descriptor == nil && protection.owner == "" && protection.dacl == ""
}

func hookAPITokenPublishProtectionsEqual(left, right hookAPITokenPublishProtection) bool {
	return left.owner == right.owner && left.dacl == right.dacl && left.protected == right.protected
}

func hookAPITokenWindowsExactDACLFromSDDL(sddl string) (string, error) {
	daclStart, daclEnd, depth := -1, len(sddl), 0
	for index := 0; index < len(sddl); index++ {
		switch sddl[index] {
		case '(':
			depth++
		case ')':
			if depth == 0 {
				return "", fmt.Errorf("Windows hook-token security descriptor has unbalanced parentheses")
			}
			depth--
		default:
			if depth != 0 || index+1 >= len(sddl) || sddl[index+1] != ':' ||
				!strings.ContainsRune("OGDS", rune(sddl[index])) {
				continue
			}
			if sddl[index] == 'D' {
				if daclStart >= 0 {
					return "", fmt.Errorf("Windows hook-token security descriptor has duplicate top-level DACLs")
				}
				daclStart = index
				continue
			}
			if daclStart >= 0 && daclEnd == len(sddl) {
				daclEnd = index
			}
		}
	}
	if depth != 0 {
		return "", fmt.Errorf("Windows hook-token security descriptor has unbalanced parentheses")
	}
	if daclStart < 0 || daclEnd <= daclStart+1 {
		return "", fmt.Errorf("Windows hook-token security descriptor has no top-level DACL")
	}
	return sddl[daclStart:daclEnd], nil
}

func hookAPIValidateOwner(path string, _ os.FileInfo) error {
	return hookAPIValidateWindowsPathElement(path, false, true)
}

// validateHookAPITokenBoundFileCustodyPlatform applies the hook-token custody
// contract to an already-bound regular-file handle. Hook credentials differ
// from generic user-private files on Windows: managed installs intentionally
// grant the current user, LocalSystem, and Administrators access. Publication
// must retain that service-compatible DACL without broadening the stricter
// generic compare-and-swap validator used by unrelated 0600 files.
func validateHookAPITokenBoundFileCustodyPlatform(file *os.File) error {
	protection, private, err := captureHookAPITokenPublishProtectionPlatform(file, nil)
	if err != nil {
		return err
	}
	if !protection.protected {
		return fmt.Errorf("bound hook API token has an inheritable DACL")
	}
	if private {
		return nil
	}
	dacl, _, err := protection.descriptor.DACL()
	if err != nil {
		return fmt.Errorf("inspect bound hook API token DACL: %w", err)
	}
	if dacl == nil {
		return fmt.Errorf("inspect bound hook API token DACL: DACL is absent")
	}
	return otlpWindowsRejectUntrustedReadACEs(file.Name(), dacl)
}

func hookAPIValidateDirectory(path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("hook API token directory must be absolute: %q", path)
	}
	clean := filepath.Clean(path)
	protectChildren := true
	for cur := clean; ; cur = filepath.Dir(cur) {
		if err := hookAPIValidateWindowsPathElement(cur, true, protectChildren); err != nil {
			return err
		}
		protectChildren = false
		if cur == filepath.Dir(cur) {
			break
		}
	}
	return nil
}

func hookAPIValidateDirectoryElement(path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("hook API token directory must be absolute: %q", path)
	}
	return hookAPIValidateWindowsPathElement(filepath.Clean(path), true, true)
}

func hookAPIValidateWindowsPathElement(path string, wantDir, protectChildren bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	pathPtr, err := winpath.UTF16Ptr(path)
	if err != nil {
		return fmt.Errorf("encode Windows path %s: %w", path, err)
	}
	attributes, err := windows.GetFileAttributes(pathPtr)
	if err != nil {
		return fmt.Errorf("inspect Windows attributes for %s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("symlinks, junctions, and reparse points are not allowed: %s", path)
	}
	if wantDir && !info.IsDir() {
		return fmt.Errorf("expected directory: %s", path)
	}
	if !wantDir && !info.Mode().IsRegular() {
		return fmt.Errorf("expected regular file: %s", path)
	}
	extendedPath, err := winpath.Extended(path)
	if err != nil {
		return fmt.Errorf("encode extended Windows path %s: %w", path, err)
	}
	sd, err := windows.GetNamedSecurityInfo(
		extendedPath,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return fmt.Errorf("inspect Windows security descriptor for %s: %w", path, err)
	}
	if sd == nil {
		return fmt.Errorf("missing Windows security descriptor: %s", path)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return fmt.Errorf("inspect Windows owner for %s: %w", path, err)
	}
	if !hookAPIWindowsTrustedPrincipal(owner) {
		return fmt.Errorf("owner %s is not trusted for hook API token path %s", hookAPIWindowsSIDString(owner), path)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("inspect Windows DACL for %s: %w", path, err)
	}
	if dacl == nil {
		return fmt.Errorf("null Windows DACL is not trusted: %s", path)
	}
	return hookAPIRejectUntrustedWindowsWriteACEs(path, dacl, wantDir, protectChildren)
}

func hookAPIRejectUntrustedWindowsWriteACEs(path string, dacl *windows.ACL, wantDir, protectChildren bool) error {
	const (
		accessAllowedCompoundACEType       = 0x4
		accessAllowedObjectACEType         = 0x5
		accessAllowedCallbackACEType       = 0x9
		accessAllowedCallbackObjectACEType = 0xB
	)
	for i := uint16(0); i < dacl.AceCount; i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(i), &ace); err != nil {
			return fmt.Errorf("inspect Windows ACE %d for %s: %w", i, path, err)
		}
		if ace == nil {
			continue
		}
		inheritOnly := ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0
		inheritsToChildren := ace.Header.AceFlags&(windows.OBJECT_INHERIT_ACE|windows.CONTAINER_INHERIT_ACE) != 0
		if inheritOnly && (!protectChildren || !wantDir || !inheritsToChildren) {
			continue
		}
		if !hookAPIWindowsWriteLikeAccess(ace.Mask, protectChildren) {
			continue
		}
		switch ace.Header.AceType {
		case accessAllowedCompoundACEType, accessAllowedObjectACEType, accessAllowedCallbackACEType, accessAllowedCallbackObjectACEType:
			return fmt.Errorf("unsupported Windows allow ACE type 0x%x on %s", ace.Header.AceType, path)
		case windows.ACCESS_ALLOWED_ACE_TYPE:
		default:
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if hookAPIWindowsOwnerRightsPrincipal(sid) {
			continue
		}
		if inheritOnly && hookAPIWindowsCreatorOwnerTemplate(sid) {
			continue
		}
		if !protectChildren && hookAPIWindowsStockAncestorGrant(ace.Mask, sid) {
			continue
		}
		if !hookAPIWindowsTrustedPrincipal(sid) {
			return fmt.Errorf("untrusted Windows principal %s has write-like access mask 0x%x on %s", hookAPIWindowsSIDString(sid), uint32(ace.Mask), path)
		}
	}
	return nil
}

func hookAPIWindowsCreatorOwnerTemplate(sid *windows.SID) bool {
	return sid != nil && sid.IsWellKnown(windows.WinCreatorOwnerSid)
}

func hookAPIWindowsOwnerRightsPrincipal(sid *windows.SID) bool {
	return sid != nil && sid.IsWellKnown(windows.WinCreatorOwnerRightsSid)
}

func hookAPIWindowsWriteLikeAccess(mask windows.ACCESS_MASK, protectChildren bool) bool {
	const fileDeleteChild windows.ACCESS_MASK = 0x00000040
	unsafe := windows.ACCESS_MASK(
		windows.GENERIC_ALL |
			windows.GENERIC_WRITE |
			windows.DELETE |
			windows.WRITE_DAC |
			windows.WRITE_OWNER |
			windows.FILE_WRITE_EA |
			windows.FILE_WRITE_ATTRIBUTES,
	)
	if protectChildren {
		// On an ancestor directory, FILE_WRITE_DATA and FILE_APPEND_DATA
		// mean add-file and add-subdirectory. Windows drive roots commonly
		// grant add-subdirectory to Authenticated Users; without DELETE_CHILD
		// that does not permit replacing the already protected token path.
		// The immediate data/hooks directory must reject those child-creation
		// rights too. Rights that mutate the ancestor object itself remain
		// unsafe above regardless of protectChildren.
		unsafe |= windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA
	}
	return mask&(unsafe|fileDeleteChild) != 0
}

// hookAPIWindowsStockAncestorGrant reports whether mask is the grant Windows
// makes to BUILTIN\Users on roots like C:\ProgramData: add-file and
// write-EA/attributes, none of which can replace an existing child. Limited to
// that principal so an ancestor opened up to Everyone is still rejected.
func hookAPIWindowsStockAncestorGrant(mask windows.ACCESS_MASK, sid *windows.SID) bool {
	if sid == nil || !sid.IsWellKnown(windows.WinBuiltinUsersSid) {
		return false
	}
	return !managed.WindowsAncestorReplaceAccess(mask)
}

func hookAPIWindowsTrustedPrincipal(sid *windows.SID) bool {
	if sid == nil {
		return false
	}
	if sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) || sid.IsWellKnown(windows.WinLocalSystemSid) {
		return true
	}
	// Managed Windows services pin one exact virtual gateway account in their
	// administrator-owned SCM environment. Runtime token paths deliberately
	// grant that SID Modify so the gateway can mint/rotate scoped tokens. No
	// service SID exception exists in normal mode, and malformed or unresolved
	// accounts fail closed.
	if managed.IsManagedEnterprise(os.Getenv(managed.DeploymentModeEnv)) {
		serviceSID, err := managed.WindowsServiceAccountSID(os.Getenv(managed.WindowsServiceAccountEnv))
		if err == nil && serviceSID != nil && sid.Equals(serviceSID) {
			return true
		}
	}
	currentSID, err := windowsEffectiveUserSID()
	if err == nil && currentSID != nil && sid.Equals(currentSID) {
		return true
	}
	trustedInstaller, err := windows.StringToSid("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464")
	return err == nil && sid.Equals(trustedInstaller)
}

func hookAPIWindowsSIDString(sid *windows.SID) string {
	if sid == nil {
		return "<nil>"
	}
	return sid.String()
}
