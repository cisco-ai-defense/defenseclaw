//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

const windowsGuardianACLMaxPathElements = 64

var windowsEnterpriseGuardianDACLRepair = runWindowsEnterpriseGuardianDACLRepair

// repairWindowsTargetOwnedPathDACL authorizes a narrowly bounded process-token
// operation from inside the exact target-token callback. The actual content
// mutation remains on the impersonated thread; this escape is only for
// restoring the canonical DACL when the user has denied their own token.
//
// OWNER RIGHTS (S-1-3-4) can suppress an owner's implicit READ_CONTROL and
// WRITE_DAC rights. Consequently, owner-only repair is not sufficient for an
// enterprise guardian. The LocalSystem helper below uses a separate locked OS
// thread and enables backup/restore privileges only on that thread.
func repairWindowsTargetOwnedPathDACL(
	home string,
	path string,
	target *windows.SID,
	directory bool,
) error {
	if target == nil {
		return fmt.Errorf("enterprise hooks: target SID is unavailable for DACL repair")
	}
	if sameWindowsEnterprisePath(home, path) {
		return fmt.Errorf("enterprise hooks: refusing to rewrite the target profile root DACL")
	}
	if err := windowsEnterpriseEffectiveTokenCheck(target); err != nil {
		return fmt.Errorf("enterprise hooks: DACL repair requires exact target-token authorization: %w", err)
	}
	if !pathInside(home, path) && !sameWindowsEnterprisePath(home, path) {
		return fmt.Errorf("enterprise hooks: refusing DACL repair outside target home: %s", path)
	}
	return windowsEnterpriseGuardianDACLRepair(home, path, target, directory)
}

// windowsGuardianACLBuilder returns the DACL a no-follow repair applies to the
// final path element.
type windowsGuardianACLBuilder func(target *windows.SID, directory bool) (*windows.ACL, error)

func runWindowsEnterpriseGuardianDACLRepair(
	home string,
	path string,
	target *windows.SID,
	directory bool,
) error {
	return runWindowsEnterpriseGuardianDACLRepairWithACL(home, path, target, directory, windowsUserPathProtectionACL)
}

// runWindowsEnterpriseGuardianDACLRepairWithACL is the LocalSystem no-follow
// repair with an explicit final DACL (for example the managed plugin DACL).
func runWindowsEnterpriseGuardianDACLRepairWithACL(
	home string,
	path string,
	target *windows.SID,
	directory bool,
	build windowsGuardianACLBuilder,
) error {
	result := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		if err := windowsEnterpriseMutationIdentityCheck(); err != nil {
			runtime.UnlockOSThread()
			result <- fmt.Errorf("enterprise hooks: guardian DACL repair requires LocalSystem: %w", err)
			return
		}
		if err := windows.ImpersonateSelf(windows.SecurityImpersonation); err != nil {
			runtime.UnlockOSThread()
			result <- fmt.Errorf("enterprise hooks: create dedicated guardian privilege token: %w", err)
			return
		}

		var token windows.Token
		if err := windows.OpenThreadToken(
			windows.CurrentThread(),
			windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY,
			false,
			&token,
		); err != nil {
			revertErr := windows.RevertToSelf()
			if revertErr == nil {
				runtime.UnlockOSThread()
				result <- fmt.Errorf("enterprise hooks: open guardian privilege token: %w", err)
				return
			}
			result <- fmt.Errorf(
				"enterprise hooks: open guardian privilege token: %v (revert failed: %v)",
				err,
				revertErr,
			)
			return
		}

		privilegeErr := enableWindowsThreadPrivilege(token, "SeBackupPrivilege")
		if privilegeErr == nil {
			privilegeErr = enableWindowsThreadPrivilege(token, "SeRestorePrivilege")
		}
		repairErr := privilegeErr
		if repairErr == nil {
			repairErr = repairWindowsTargetOwnedPathDACLNoFollowWithACL(home, path, target, directory, build)
		}
		token.Close()

		if revertErr := windows.RevertToSelf(); revertErr != nil {
			// Do not return a still-privileged thread to the runtime pool.
			if repairErr == nil {
				result <- fmt.Errorf("enterprise hooks: revert guardian DACL privilege token: %w", revertErr)
			} else {
				result <- fmt.Errorf("%v (revert guardian DACL privilege token failed: %v)", repairErr, revertErr)
			}
			return
		}
		runtime.UnlockOSThread()
		result <- repairErr
	}()
	return <-result
}

func enableWindowsThreadPrivilege(token windows.Token, name string) error {
	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	var luid windows.LUID
	if err := windows.LookupPrivilegeValue(nil, namePtr, &luid); err != nil {
		return fmt.Errorf("enterprise hooks: look up %s: %w", name, err)
	}
	state := windows.Tokenprivileges{
		PrivilegeCount: 1,
		Privileges: [1]windows.LUIDAndAttributes{{
			Luid:       luid,
			Attributes: windows.SE_PRIVILEGE_ENABLED,
		}},
	}
	if err := windows.AdjustTokenPrivileges(token, false, &state, 0, nil, nil); err != nil {
		return fmt.Errorf("enterprise hooks: enable %s: %w", name, err)
	}
	if err := windows.GetLastError(); errors.Is(err, windows.ERROR_NOT_ALL_ASSIGNED) {
		return fmt.Errorf("enterprise hooks: guardian token does not hold %s", name)
	}
	return nil
}

// repairWindowsTargetOwnedPathDACLNoFollow walks from the already authorized
// profile root with handle-relative NtCreateFile calls. Every component is
// opened with FILE_OPEN_REPARSE_POINT and must be owned by the manifest SID.
// An attacker therefore cannot redirect LocalSystem DACL repair through a
// junction to an object outside the profile.
// repairWindowsTargetOwnedPathDACLNoFollow repairs a per-user path without
// following reparse points. The impersonated-target caller runs with the
// target's token so cannot invoke LocalSystem repair privileges; admin-
// reclaim must stay refused here. The privileged guardian caller (which
// does hold SeTakeOwnershipPrivilege + SeRestorePrivilege via
// repairWindowsTargetOwnedPathDACL and friends, not this function) is
// never routed through here, so no exported allowAdminReclaim exists
// yet - all current callers get the strict posture by construction.
func repairWindowsTargetOwnedPathDACLNoFollow(
	home string,
	path string,
	target *windows.SID,
	directory bool,
) error {
	return repairWindowsTargetOwnedPathDACLNoFollowWithACL(home, path, target, directory, windowsUserPathProtectionACL)
}

func repairWindowsTargetOwnedPathDACLNoFollowWithACL(
	home string,
	path string,
	target *windows.SID,
	directory bool,
	build windowsGuardianACLBuilder,
) error {
	if build == nil {
		return fmt.Errorf("enterprise hooks: DACL repair has no target DACL")
	}
	homeAbs, err := filepath.Abs(home)
	if err != nil {
		return err
	}
	pathAbs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	homeAbs = filepath.Clean(homeAbs)
	pathAbs = filepath.Clean(pathAbs)
	if err := validateWindowsEnterpriseProfileVolume(homeAbs); err != nil {
		return err
	}
	if sameWindowsEnterprisePath(homeAbs, pathAbs) {
		return fmt.Errorf("enterprise hooks: refusing no-follow rewrite of the target profile root DACL")
	}
	if !pathInside(homeAbs, pathAbs) && !sameWindowsEnterprisePath(homeAbs, pathAbs) {
		return fmt.Errorf("enterprise hooks: refusing no-follow DACL repair outside target home: %s", pathAbs)
	}
	rel, err := filepath.Rel(homeAbs, pathAbs)
	if err != nil {
		return err
	}
	parts := make([]string, 0, 8)
	if rel != "." {
		for _, part := range strings.Split(rel, string(filepath.Separator)) {
			if part == "" || part == "." || part == ".." || strings.ContainsAny(part, "\\/\x00") {
				return fmt.Errorf("enterprise hooks: invalid DACL repair path element %q", part)
			}
			parts = append(parts, part)
		}
	}
	if len(parts) > windowsGuardianACLMaxPathElements {
		return fmt.Errorf(
			"enterprise hooks: DACL repair path exceeds %d elements",
			windowsGuardianACLMaxPathElements,
		)
	}

	handle, err := openWindowsGuardianACLRoot(homeAbs, false)
	if err != nil {
		return err
	}
	defer func() {
		if handle != 0 {
			_ = windows.CloseHandle(handle)
		}
	}()
	if err := validateWindowsGuardianACLHandle(handle, target, true, false, true); err != nil {
		return fmt.Errorf("enterprise hooks: reject DACL repair profile root: %w", err)
	}

	for index, part := range parts {
		final := index == len(parts)-1
		child, err := openWindowsGuardianACLChild(handle, part, final, directory)
		if err != nil {
			return fmt.Errorf("enterprise hooks: open DACL repair path element %q: %w", part, err)
		}
		if err := validateWindowsGuardianACLHandle(child, target, !final || directory, final, false); err != nil {
			_ = windows.CloseHandle(child)
			return fmt.Errorf("enterprise hooks: reject DACL repair path element %q: %w", part, err)
		}
		if err := windows.CloseHandle(handle); err != nil {
			_ = windows.CloseHandle(child)
			handle = 0
			return fmt.Errorf("enterprise hooks: close DACL repair parent handle: %w", err)
		}
		handle = child
	}

	acl, err := build(target, directory)
	if err != nil {
		return err
	}
	// DACL-only repair. The round-1 bulldoze refactor removed the
	// admin-ownership-transfer branch from validateWindowsGuardianACL-
	// Handle, so this function is only reachable when the final element
	// is already target-owned. Guardian-side ownership transfer runs
	// through a different code path (repairWindowsTargetOwnedPathDACL)
	// with its own WRITE_OWNER-capable handle.
	if err := setWindowsObjectDACLNoPropagation(handle, acl, directory); err != nil {
		return fmt.Errorf("enterprise hooks: restore canonical target DACL by handle: %w", err)
	}
	return nil
}

// setWindowsObjectDACLNoPropagation replaces the protected DACL of exactly the
// object behind handle. SetSecurityInfo and SetNamedSecurityInfo also rewrite
// the inherited ACEs of every existing descendant of a directory. Managed
// descendants carry their own protected DACLs, so that walk never changed a
// managed object; it only rewrote the ACLs of the user's own files and, on a
// connector home that holds the agent's install (about 130,000 objects for
// Hermes under %LOCALAPPDATA%\hermes), made one reconcile take minutes.
//
// SetKernelObjectSecurity stores an ACL exactly as given, so the ACL is first
// put in the applied form SetSecurityInfo stores (windowsAppliedDACL); the
// resulting DACL is the one the canonical validators expect.
func setWindowsObjectDACLNoPropagation(handle windows.Handle, acl *windows.ACL, directory bool) error {
	if acl == nil {
		return errors.New("enterprise hooks: DACL update has no DACL")
	}
	applied, err := windowsAppliedDACL(acl, directory)
	if err != nil {
		return err
	}
	sd, err := windows.NewSecurityDescriptor()
	if err != nil {
		return err
	}
	if err := sd.SetDACL(applied, true, false); err != nil {
		return err
	}
	// AUTO_INHERIT_REQ asks the object manager to record the DACL as
	// auto-inherited (SDDL "PAI"), as SetSecurityInfo does; it only computes
	// this object's descriptor and never touches descendants.
	const control = windows.SE_DACL_PROTECTED | windows.SE_DACL_AUTO_INHERITED | windows.SE_DACL_AUTO_INHERIT_REQ
	if err := sd.SetControl(control, control); err != nil {
		return err
	}
	return windows.SetKernelObjectSecurity(
		handle,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		sd,
	)
}

// windowsAppliedDACL returns acl in the form SetSecurityInfo stores on a file
// object: generic rights of an effective ACE are mapped to file rights, and on
// a directory an inheritable ACE that carries generic rights becomes an
// effective ACE with the mapped rights plus an inherit-only ACE that keeps the
// generic rights for new children. Only access-allowed ACEs are supported.
func windowsAppliedDACL(acl *windows.ACL, directory bool) (*windows.ACL, error) {
	const genericRights = windows.GENERIC_ALL | windows.GENERIC_READ | windows.GENERIC_WRITE | windows.GENERIC_EXECUTE
	const inheritable = windows.OBJECT_INHERIT_ACE | windows.CONTAINER_INHERIT_ACE
	var sddl strings.Builder
	sddl.WriteString("D:P")
	add := func(flags uint8, mask windows.ACCESS_MASK, sid *windows.SID) {
		fmt.Fprintf(&sddl, "(A;%s;0x%x;;;%s)", windowsSDDLACEFlags(flags), uint32(mask), sid.String())
	}
	for index := uint32(0); index < uint32(acl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, index, &ace); err != nil {
			return nil, fmt.Errorf("enterprise hooks: inspect DACL entry %d: %w", index, err)
		}
		if ace == nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return nil, errors.New("enterprise hooks: object-only DACL update supports access-allowed entries only")
		}
		flags := ace.Header.AceFlags
		if flags&^uint8(windows.VALID_INHERIT_FLAGS) != 0 {
			return nil, fmt.Errorf("enterprise hooks: DACL entry %d has unsupported flags 0x%x", index, flags)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		mask := ace.Mask
		switch {
		case flags&windows.INHERIT_ONLY_ACE != 0:
			add(flags, mask, sid)
		case directory && flags&inheritable != 0 && mask&genericRights != 0:
			add(flags&^uint8(inheritable|windows.NO_PROPAGATE_INHERIT_ACE), mapWindowsUserPathGenericMask(mask), sid)
			add(flags|windows.INHERIT_ONLY_ACE, mask, sid)
		default:
			add(flags, mapWindowsUserPathGenericMask(mask), sid)
		}
	}
	sd, err := windows.SecurityDescriptorFromString(sddl.String())
	if err != nil {
		return nil, fmt.Errorf("enterprise hooks: build applied DACL: %w", err)
	}
	applied, _, err := sd.DACL()
	if err != nil {
		return nil, err
	}
	return applied, nil
}

func windowsSDDLACEFlags(flags uint8) string {
	var out strings.Builder
	for _, flag := range []struct {
		bit  uint8
		sddl string
	}{
		{windows.OBJECT_INHERIT_ACE, "OI"},
		{windows.CONTAINER_INHERIT_ACE, "CI"},
		{windows.NO_PROPAGATE_INHERIT_ACE, "NP"},
		{windows.INHERIT_ONLY_ACE, "IO"},
		{windows.INHERITED_ACE, "ID"},
	} {
		if flags&flag.bit != 0 {
			out.WriteString(flag.sddl)
		}
	}
	return out.String()
}

// windowsRecoverSetupRelaxedHookDirectory is replaceable in tests.
var windowsRecoverSetupRelaxedHookDirectory = recoverWindowsSetupRelaxedHookDirectory

// recoverWindowsSetupRelaxedHookDirectory restores the canonical managed DACL
// on <dataDir>\hooks when a guardian stopped between relaxing that directory
// for a connector setup and hardening it again (for example when a lifecycle
// stopped the guardian at its coverage deadline). The relaxed DACL grants only
// LocalSystem and OWNER RIGHTS, so an elevated administrator cannot read it
// and LocalSystem finds 2 ACEs instead of the canonical 7: every retire of
// that user's managed runtime generations refused, and no lifecycle action
// could recover the host.
//
// It runs on a dedicated locked thread with backup and restore privileges
// (held by LocalSystem and elevated administrators), opens the data directory
// and then its hooks child without following reparse points, requires both to
// be owned by the target SID, and rewrites only a DACL that is exactly the
// relaxed setup shape. It reports whether it changed the directory.
func recoverWindowsSetupRelaxedHookDirectory(dataDir string, target *windows.SID) (bool, error) {
	if target == nil {
		return false, errors.New("enterprise hooks: target SID is unavailable for hooks directory recovery")
	}
	if !filepath.IsAbs(dataDir) || filepath.Clean(dataDir) != dataDir {
		return false, fmt.Errorf("enterprise hooks: hooks directory recovery needs an absolute clean data directory: %s", dataDir)
	}
	type outcome struct {
		changed bool
		err     error
	}
	result := make(chan outcome, 1)
	go func() {
		runtime.LockOSThread()
		if err := windows.ImpersonateSelf(windows.SecurityImpersonation); err != nil {
			runtime.UnlockOSThread()
			result <- outcome{err: fmt.Errorf("enterprise hooks: create dedicated hooks recovery token: %w", err)}
			return
		}
		changed, err := recoverWindowsSetupRelaxedHookDirectoryPrivileged(dataDir, target)
		if revertErr := windows.RevertToSelf(); revertErr != nil {
			// Do not return a still-privileged thread to the runtime pool.
			result <- outcome{changed: changed, err: errors.Join(
				err,
				fmt.Errorf("enterprise hooks: revert hooks recovery token: %w", revertErr),
			)}
			return
		}
		runtime.UnlockOSThread()
		result <- outcome{changed: changed, err: err}
	}()
	out := <-result
	return out.changed, out.err
}

func recoverWindowsSetupRelaxedHookDirectoryPrivileged(dataDir string, target *windows.SID) (bool, error) {
	var token windows.Token
	if err := windows.OpenThreadToken(
		windows.CurrentThread(),
		windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY,
		false,
		&token,
	); err != nil {
		return false, fmt.Errorf("enterprise hooks: open hooks recovery token: %w", err)
	}
	defer token.Close()
	for _, privilege := range []string{"SeBackupPrivilege", "SeRestorePrivilege"} {
		if err := enableWindowsThreadPrivilege(token, privilege); err != nil {
			return false, err
		}
	}
	root, err := openWindowsGuardianACLRoot(dataDir, false)
	if err != nil {
		return false, err
	}
	defer windows.CloseHandle(root)
	if err := validateWindowsGuardianACLHandle(root, target, true, false, false); err != nil {
		return false, fmt.Errorf("enterprise hooks: reject managed runtime data directory %s: %w", dataDir, err)
	}
	hookDir := filepath.Join(dataDir, "hooks")
	hooks, err := openWindowsGuardianACLChild(root, "hooks", true, true)
	if err != nil {
		return false, fmt.Errorf("enterprise hooks: open %s without following: %w", hookDir, err)
	}
	defer windows.CloseHandle(hooks)
	if err := validateWindowsGuardianACLHandle(hooks, target, true, true, false); err != nil {
		return false, fmt.Errorf("enterprise hooks: reject %s: %w", hookDir, err)
	}
	sd, err := windows.GetSecurityInfo(hooks, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return false, fmt.Errorf("enterprise hooks: read DACL of %s: %w", hookDir, err)
	}
	relaxed, err := windowsSetupRelaxedDirectoryDACL(sd)
	if err != nil || !relaxed {
		return false, err
	}
	acl, err := windowsUserPathProtectionACL(target, true)
	if err != nil {
		return false, err
	}
	if err := setWindowsObjectDACLNoPropagation(hooks, acl, true); err != nil {
		return false, fmt.Errorf("enterprise hooks: restore canonical DACL on %s: %w", hookDir, err)
	}
	return true, nil
}

// windowsSetupRelaxedDirectoryDACL reports whether sd carries exactly the
// protected owner-private DACL relaxWindowsStandalonePerUserDirectory applies
// (windowsSetupRelaxedDirectorySDDL), in either ACE order.
func windowsSetupRelaxedDirectoryDACL(sd *windows.SECURITY_DESCRIPTOR) (bool, error) {
	if sd == nil {
		return false, nil
	}
	control, _, err := sd.Control()
	if err != nil {
		return false, err
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		return false, nil
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil || dacl.AceCount != 2 {
		return false, nil
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return false, err
	}
	ownerRights, err := windows.CreateWellKnownSid(windows.WinCreatorOwnerRightsSid)
	if err != nil {
		return false, err
	}
	const fullAccess windows.ACCESS_MASK = 0x001f01ff
	const inherit = windows.OBJECT_INHERIT_ACE | windows.CONTAINER_INHERIT_ACE
	sawSystem, sawOwnerRights := false, false
	for index := uint32(0); index < uint32(dacl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, index, &ace); err != nil {
			return false, err
		}
		if ace == nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE ||
			ace.Header.AceFlags != inherit || ace.Mask != fullAccess {
			return false, nil
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		switch {
		case sid.Equals(system) && !sawSystem:
			sawSystem = true
		case sid.Equals(ownerRights) && !sawOwnerRights:
			sawOwnerRights = true
		default:
			return false, nil
		}
	}
	return sawSystem && sawOwnerRights, nil
}

func openWindowsGuardianACLRoot(path string, final bool) (windows.Handle, error) {
	extended, err := winpath.Extended(path)
	if err != nil {
		return 0, err
	}
	ptr, err := windows.UTF16PtrFromString(extended)
	if err != nil {
		return 0, err
	}
	access := uint32(windows.READ_CONTROL | windows.FILE_READ_ATTRIBUTES | windows.FILE_LIST_DIRECTORY | windows.SYNCHRONIZE)
	if final {
		access |= windows.WRITE_DAC
	}
	handle, err := windows.CreateFile(
		ptr,
		access,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return 0, fmt.Errorf("enterprise hooks: open target profile root without following: %w", err)
	}
	return handle, nil
}

func openWindowsGuardianACLChild(
	parent windows.Handle,
	name string,
	final bool,
	directory bool,
) (windows.Handle, error) {
	objectName, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return 0, err
	}
	attributes := windows.OBJECT_ATTRIBUTES{
		Length:        uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})),
		RootDirectory: parent,
		ObjectName:    objectName,
		Attributes:    windows.OBJ_CASE_INSENSITIVE,
	}
	access := uint32(windows.READ_CONTROL)
	options := uint32(
		windows.FILE_OPEN_REPARSE_POINT |
			windows.FILE_OPEN_FOR_BACKUP_INTENT,
	)
	if final {
		// Target-token-only DACL repair. The caller
		// (repairWindowsTargetOwnedPathDACLNoFollow) runs under the
		// target's token, which lacks SeTakeOwnershipPrivilege and
		// SeRestorePrivilege, so we cannot (and must not) request
		// WRITE_OWNER on this handle - an ownership transfer attempt
		// would fail at SetSecurityInfo and the handle access would
		// still have requested a privilege the token doesn't hold.
		// Privileged ownership transfer runs through a different code
		// path (repairWindowsTargetOwnedPathDACL) that explicitly
		// holds the restore/takeOwnership privileges and opens its
		// handles with WRITE_OWNER there.
		access |= windows.WRITE_DAC | windows.FILE_READ_ATTRIBUTES
	} else {
		access |= windows.FILE_READ_ATTRIBUTES | windows.FILE_LIST_DIRECTORY | windows.SYNCHRONIZE
		options |= windows.FILE_DIRECTORY_FILE | windows.FILE_SYNCHRONOUS_IO_NONALERT
	}
	var handle windows.Handle
	var status windows.IO_STATUS_BLOCK
	if err := windows.NtCreateFile(
		&handle,
		access,
		&attributes,
		&status,
		nil,
		0,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		windows.FILE_OPEN,
		options,
		0,
		0,
	); err != nil {
		return 0, err
	}
	return handle, nil
}

func validateWindowsGuardianACLHandle(
	handle windows.Handle,
	target *windows.SID,
	wantDirectory bool,
	final bool,
	profileRoot bool,
) error {
	owner, err := windowsHandleOwner(handle)
	if err != nil {
		return err
	}
	ownerOK := owner != nil && owner.Equals(target)
	if profileRoot {
		ownerOK = windowsEnterpriseProfileAnchorOwner(owner, target)
	}
	if !ownerOK {
		// Admin reclaim is NOT performed on the impersonated-target path.
		// repairWindowsTargetOwnedPathDACLNoFollow (the only caller of
		// this validator) runs under the target's token, which has
		// neither SeTakeOwnershipPrivilege nor SeRestorePrivilege, so a
		// SetSecurityInfo attempting to transfer admin ownership would
		// fail - and silently "accepting" an admin-owned file as if the
		// transfer would succeed hides the drift from the guardian-side
		// repair that CAN transfer it. Keep this check strict: any owner
		// that is not the exact target SID (or, for the profile root,
		// the profile-anchor set) is fatal. Guardian-side repair runs
		// through a different path (repairWindowsTargetOwnedPathDACL)
		// where privileged ownership transfer is wired in.
		return fmt.Errorf(
			"owner SID %s is not trusted for target SID %s",
			windowsSIDString(owner),
			windowsSIDString(target),
		)
	}
	if final {
		// This query is bound to the exact no-follow handle that will receive
		// SetSecurityInfo. SeBackupPrivilege plus FILE_OPEN_FOR_BACKUP_INTENT
		// permits the metadata read even when a hostile target DACL denies
		// FILE_READ_ATTRIBUTES. Never rewrite the shared security descriptor
		// of an attacker-created hard link.
		var info windows.ByHandleFileInformation
		if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
			return fmt.Errorf("inspect final DACL repair handle: %w", err)
		}
		if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return fmt.Errorf("final path element is a reparse point")
		}
		isDirectory := info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0
		if isDirectory != wantDirectory {
			if wantDirectory {
				return fmt.Errorf("expected directory")
			}
			return fmt.Errorf("expected regular file")
		}
		if !isDirectory && info.NumberOfLinks != 1 {
			return fmt.Errorf(
				"%w (final DACL repair handle has %d links)",
				errWindowsManagedHardlink,
				info.NumberOfLinks,
			)
		}
		return nil
	}
	attributes, err := windowsQuarantineHandleAttributes(handle)
	if err != nil {
		return err
	}
	if attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("intermediate path element is a reparse point")
	}
	isDirectory := attributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0
	if isDirectory != wantDirectory {
		if wantDirectory {
			return fmt.Errorf("expected directory")
		}
		return fmt.Errorf("expected regular file")
	}
	return nil
}
