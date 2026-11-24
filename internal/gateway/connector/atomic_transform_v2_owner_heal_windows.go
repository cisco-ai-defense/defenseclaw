// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"golang.org/x/sys/windows"
)

// atomicTransformV2OwnerHealBeforeFileOpen, when set by a test, runs on the
// privileged repair thread after the folder checks and before the config is
// opened: the window in which a path swap would have to land (GAP-1651).
var atomicTransformV2OwnerHealBeforeFileOpen func()

// healAtomicTransformV2ConfigLeftToAdmin gives the account back its own agent
// config when a LocalSystem or Administrators writer left that file owned by
// itself in a folder whose DACL grants the account access only as owner
// (GAP-1651). The guardian's setup shape for a per-user agent folder,
// D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;OW), is such a folder: a file a privileged
// writer creates there inherits OWNER RIGHTS full control for that writer and
// nothing for the account, so every later edit made as the account (the
// guardian's impersonated route-only render, a native OTLP removal) failed at
// its first open with a bare "Access is denied", and verify stayed 1603.
//
// It runs only when the account itself cannot open the file, the process may
// repair managed objects (elevated installer or LocalSystem guardian), the
// effective user is an ordinary account, the folder is owned by that account
// and carries exactly that guardian setup DACL (alone or with the gateway
// service read grant the hook enumerator adds to every agent folder it
// inventories, GAP-1827), and the file, a single-link regular file reached
// without reparse points, is owned by LocalSystem, Administrators or
// TrustedInstaller and has only the ACEs it inherited from that folder
// (GAP-1672). The file DACL is the provenance: a file the account moved in
// from elsewhere keeps its own DACL (a SYSTEM-only file keeps its protected
// one), and the account cannot re-propagate inheritance onto a file it has
// no WRITE_DAC on, so only a file a privileged writer created in a folder of
// that shape qualifies. The folder check is not provenance (the account owns
// the folder and can set it to that shape); it is kept so that a folder whose
// current DACL is not the guardian shape, or carries a grant other than the
// gateway read grant, is never healed in (GAP-1759, GAP-1827).
// It then makes the
// account the owner and adds an explicit full-control entry for it, keeping
// every other entry and the file's inheritance state; the transaction's own
// protection convergence then gives the file its private DACL. Anything else
// is left alone and the transaction reports the original error.
//
// The folder that is checked is the folder the file is opened in: the folder
// handle is held without delete sharing, so it cannot be renamed or replaced
// by a junction while the heal runs, its final path must be the expected
// folder, and the file is opened relative to that handle with no reparse
// processing. A path-based second open would let the account swap the folder
// (or an ancestor) for a junction between the two and be handed any
// SYSTEM-owned file.
func healAtomicTransformV2ConfigLeftToAdmin(path string) error {
	if !atomicTransformV2ConfigAccessDenied(path) {
		return nil
	}
	user, err := windowsEffectiveUserSID()
	if err != nil || user == nil || managed.IsWindowsTrustedAdminOwner(user) {
		return nil
	}
	if err := atomicTransformValidateNoReparsePathPlatform(path); err != nil {
		return nil
	}
	folder, name := filepath.Dir(path), filepath.Base(path)
	var previous *windows.SID
	repairErr := runWindowsManagedPrivilegedRepair(func() error {
		// FILE_LIST_DIRECTORY makes the open take part in share checks (an
		// open for attributes and READ_CONTROL only does not), so leaving out
		// FILE_SHARE_DELETE really refuses a rename or delete of the folder.
		dir, err := openWindowsManagedRepairHandleShared(folder, true,
			windows.READ_CONTROL|windows.FILE_LIST_DIRECTORY,
			windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE)
		if err != nil {
			return err
		}
		defer windows.CloseHandle(dir)
		if !atomicTransformV2HealFolderIsExpected(dir, folder) {
			// The handle reached some other folder: leave everything alone.
			return nil
		}
		dirSecurity, err := windows.GetSecurityInfo(dir, windows.SE_FILE_OBJECT,
			windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			return err
		}
		dirOwner, _, err := dirSecurity.Owner()
		if err != nil || dirOwner == nil || !dirOwner.Equals(user) {
			// Not the account's own folder: never hand a file in it over.
			return nil
		}
		gateway, err := atomicTransformV2HealGatewaySID()
		if err != nil {
			return err
		}
		relaxed, serviceRead, err := managed.IsWindowsSetupRelaxedAgentDirectoryDACL(dirSecurity, gateway)
		if err != nil || !relaxed {
			// Not the guardian setup shape: the denial has another cause.
			return nil
		}
		if atomicTransformV2OwnerHealBeforeFileOpen != nil {
			atomicTransformV2OwnerHealBeforeFileOpen()
		}
		handle, err := openAtomicTransformV2HealFileInFolder(dir, name,
			windows.READ_CONTROL|windows.WRITE_OWNER|windows.WRITE_DAC)
		if err != nil {
			return err
		}
		defer windows.CloseHandle(handle)
		security, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT,
			windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			return err
		}
		owner, _, err := security.Owner()
		if err != nil || owner == nil || !managed.IsWindowsTrustedAdminOwner(owner) {
			return nil
		}
		if made, err := managed.IsWindowsSetupRelaxedAgentChildFileDACL(security, gateway, serviceRead); err != nil || !made {
			// Not a file a privileged writer created in this folder (moved
			// in, or given its own DACL): never hand it over.
			return nil
		}
		control, _, err := security.Control()
		if err != nil {
			return err
		}
		dacl, _, err := security.DACL()
		if err != nil {
			return err
		}
		granted, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
			AccessPermissions: 0x001F01FF, // file all access
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       windows.NO_INHERITANCE,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_USER,
				TrusteeValue: windows.TrusteeValueFromSID(user),
			},
		}}, dacl)
		if err != nil {
			return err
		}
		inheritance := windows.SECURITY_INFORMATION(windows.UNPROTECTED_DACL_SECURITY_INFORMATION)
		if control&windows.SE_DACL_PROTECTED != 0 {
			inheritance = windows.PROTECTED_DACL_SECURITY_INFORMATION
		}
		if err := windows.SetSecurityInfo(handle, windows.SE_FILE_OBJECT,
			windows.OWNER_SECURITY_INFORMATION, user, nil, nil, nil); err != nil {
			return fmt.Errorf("set the account as owner: %w", err)
		}
		if err := windows.SetSecurityInfo(handle, windows.SE_FILE_OBJECT,
			windows.DACL_SECURITY_INFORMATION|inheritance, nil, nil, granted, nil); err != nil {
			return fmt.Errorf("grant the account full control: %w", err)
		}
		previous = owner
		return nil
	})
	if errors.Is(repairErr, errWindowsManagedRepairUnprivileged) {
		return nil
	}
	if repairErr != nil {
		return fmt.Errorf("give config %s back to account %s: %w", path, user.String(), repairErr)
	}
	if previous != nil {
		emitManagedResilience(managed.MarkerRepair, path,
			fmt.Sprintf("gave the account back its config, which %s owned with no access for the account", previous.String()),
			map[string]string{"sid": user.String()})
	}
	return nil
}

// atomicTransformV2HealGatewaySID is the service SID of the gateway, whose
// enumerator read grant a relaxed agent folder may carry (GAP-1827).
func atomicTransformV2HealGatewaySID() (*windows.SID, error) {
	return windows.StringToSid(managed.WindowsServiceSIDString(managed.StandaloneWindowsGatewaySvc))
}

// atomicTransformV2HealFolderIsExpected reports whether the held folder
// handle's final path is the expected folder, compared case-insensitively
// with short names expanded. A junction swapped into an ancestor before the
// folder open resolves to its target and fails the match.
func atomicTransformV2HealFolderIsExpected(dir windows.Handle, expected string) bool {
	final, err := atomicTransformFinalPathByHandle(dir)
	if err != nil {
		return false
	}
	want := filepath.Clean(expected)
	if long, err := atomicTransformV2LongPathName(want); err == nil {
		want = long
	}
	return strings.EqualFold(final, want)
}

func atomicTransformV2LongPathName(path string) (string, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return "", err
	}
	buffer := make([]uint16, windows.MAX_PATH)
	for {
		length, err := windows.GetLongPathName(name, &buffer[0], uint32(len(buffer)))
		if err != nil {
			return "", err
		}
		if length < uint32(len(buffer)) {
			return filepath.Clean(windows.UTF16ToString(buffer[:length])), nil
		}
		buffer = make([]uint16, length+1)
	}
}

// openAtomicTransformV2HealFileInFolder opens name inside the held folder
// with backup intent and no reparse processing, so the privileged repair
// thread reaches the file regardless of its DACL and only through that
// folder. It applies the same shape checks as openWindowsManagedRepairHandle.
func openAtomicTransformV2HealFileInFolder(dir windows.Handle, name string, access uint32) (windows.Handle, error) {
	attributes, err := atomicTransformBoundObjectAttributesForHandle(dir, name, nil)
	if err != nil {
		return 0, err
	}
	var handle windows.Handle
	var status windows.IO_STATUS_BLOCK
	if err := windows.NtCreateFile(
		&handle,
		access|windows.FILE_READ_ATTRIBUTES,
		attributes,
		&status,
		nil,
		0,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		windows.FILE_OPEN,
		windows.FILE_NON_DIRECTORY_FILE|windows.FILE_OPEN_REPARSE_POINT|windows.FILE_OPEN_FOR_BACKUP_INTENT,
		0,
		0,
	); err != nil {
		return 0, err
	}
	if err := validateWindowsManagedRepairHandleShape(handle, false); err != nil {
		_ = windows.CloseHandle(handle)
		return 0, fmt.Errorf("%s: %w", name, err)
	}
	return handle, nil
}

// atomicTransformV2ConfigAccessDenied reports whether the effective user is
// refused a plain read of an existing path, without following a final
// reparse point.
func atomicTransformV2ConfigAccessDenied(path string) bool {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return false
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err == nil {
		_ = windows.CloseHandle(handle)
		return false
	}
	return errors.Is(err, windows.ERROR_ACCESS_DENIED)
}
