//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"fmt"
	"os"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

func setEnterpriseHookAuthorizationOwnership(path string) error {
	owner, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return err
	}
	serviceSID, err := enterpriseWindowsGatewayServiceSID()
	if err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	servicePermissions := windows.ACCESS_MASK(windows.GENERIC_READ)
	if info.IsDir() {
		servicePermissions |= windows.GENERIC_EXECUTE
	}
	return setEnterpriseWindowsManagedProtection(path, owner, serviceSID, servicePermissions, info.IsDir())
}

func setEnterpriseHookGuardianStateOwnership(path string) error {
	return setEnterpriseHookAuthorizationOwnership(path)
}

// repairEnterpriseHookGuardianLedgerObjectPlatform re-stamps one guardian
// ledger object to its canonical owner and DACL. Only the LocalSystem
// guardian or an elevated installer reaches this path. Structure stays fatal:
// a reparse point anywhere on the path, a hard-linked file, or an owner
// outside SYSTEM, Administrators and TrustedInstaller is never adopted,
// because any of those could hand the protected ledger to someone else.
func repairEnterpriseHookGuardianLedgerObjectPlatform(path string, directory bool) error {
	if err := enterpriseWindowsReparseChainCheck(path); err != nil {
		return fmt.Errorf("refusing unsafe hook guardian ledger path: %w", err)
	}
	if !directory {
		links, err := enterpriseWindowsLedgerLinkCount(path)
		if err != nil {
			return err
		}
		if links != 1 {
			return errors.New("hook guardian ledger file has more than one hard link")
		}
	}
	owner, err := enterpriseWindowsManagedPathOwner(path)
	if err != nil {
		return fmt.Errorf("inspect hook guardian ledger owner: %w", err)
	}
	if !enterpriseWindowsRuntimeRepairOwnerTrusted(owner, nil) {
		ownerSID := "<nil>"
		if owner != nil {
			ownerSID = owner.String()
		}
		return fmt.Errorf("hook guardian ledger owner is not trusted: %s", ownerSID)
	}
	return enterprisehooks.RunWithWindowsOwnerRestorePrivilege(func() error {
		return enterpriseHookAuthorizationOwnershipSetter(path)
	})
}

func enterpriseWindowsLedgerLinkCount(path string) (uint32, error) {
	extended, err := winpath.Extended(path)
	if err != nil {
		return 0, err
	}
	name, err := windows.UTF16PtrFromString(extended)
	if err != nil {
		return 0, err
	}
	handle, err := windows.CreateFile(
		name,
		windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS,
		0,
	)
	if err != nil {
		return 0, fmt.Errorf("open hook guardian ledger file: %w", err)
	}
	defer windows.CloseHandle(handle)
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return 0, fmt.Errorf("inspect hook guardian ledger file: %w", err)
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return 0, errors.New("hook guardian ledger file is a reparse point")
	}
	return info.NumberOfLinks, nil
}
