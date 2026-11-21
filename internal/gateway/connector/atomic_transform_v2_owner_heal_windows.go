// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"errors"
	"fmt"
	"path/filepath"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"golang.org/x/sys/windows"
)

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
// and the file, a single-link regular file reached without reparse points, is
// owned by LocalSystem, Administrators or TrustedInstaller. It then makes the
// account the owner and adds an explicit full-control entry for it, keeping
// every other entry and the file's inheritance state; the transaction's own
// protection convergence then gives the file its private DACL. Anything else
// is left alone and the transaction reports the original error.
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
	var previous *windows.SID
	repairErr := runWindowsManagedPrivilegedRepair(func() error {
		dir, err := openWindowsManagedRepairHandle(filepath.Dir(path), true, windows.READ_CONTROL)
		if err != nil {
			return err
		}
		defer windows.CloseHandle(dir)
		dirSecurity, err := windows.GetSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
		if err != nil {
			return err
		}
		dirOwner, _, err := dirSecurity.Owner()
		if err != nil || dirOwner == nil || !dirOwner.Equals(user) {
			// Not the account's own folder: never hand a file in it over.
			return nil
		}
		handle, err := openWindowsManagedRepairHandle(path, false,
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
