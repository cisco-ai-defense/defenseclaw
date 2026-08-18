// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

var (
	enterpriseWindowsReparseChainCheck = winpath.RejectReparseChain
	enterpriseWindowsProtectionWriter  = setEnterpriseWindowsManagedProtection
)

func validateEnterpriseHookScopedTokenLocation(dataDir, connectorName string) error {
	path, err := connector.HookAPITokenFilePath(dataDir, connectorName)
	if err != nil {
		return err
	}
	return validateEnterpriseWindowsTokenLocation(dataDir, path, "hook token")
}

func alignEnterpriseHookScopedTokenOwner(dataDir, connectorName string) error {
	path, err := connector.HookAPITokenFilePath(dataDir, connectorName)
	if err != nil {
		return err
	}
	return alignEnterpriseWindowsTokenOwner(dataDir, path, "hook token")
}

func validateEnterpriseOTLPTokenLocation(dataDir string, scope connector.OTLPPathTokenScope) error {
	path, err := connector.OTLPPathTokenFilePath(dataDir, scope)
	if err != nil {
		return err
	}
	return validateEnterpriseWindowsTokenLocation(dataDir, path, "OTLP token")
}

func alignEnterpriseOTLPTokenOwner(dataDir string, scope connector.OTLPPathTokenScope) error {
	path, err := connector.OTLPPathTokenFilePath(dataDir, scope)
	if err != nil {
		return err
	}
	return alignEnterpriseWindowsTokenOwner(dataDir, path, "OTLP token")
}

func validateEnterpriseWindowsTokenLocation(dataDir, path, label string) error {
	if err := managed.ValidateTrustedRuntimeDir(dataDir, "managed data_dir"); err != nil {
		return fmt.Errorf("enterprise hooks: %w", err)
	}
	dir := filepath.Dir(path)
	if _, err := os.Lstat(dir); err == nil {
		if err := managed.ValidateTrustedRuntimeDir(dir, label+" directory"); err != nil {
			return fmt.Errorf("enterprise hooks: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if _, err := os.Lstat(path); err == nil {
		if err := managed.ValidateTrustedFilePath(path, label); err != nil {
			return fmt.Errorf("enterprise hooks: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	return nil
}

func alignEnterpriseWindowsTokenOwner(dataDir, path, label string) error {
	if err := enterpriseWindowsReparseChainCheck(path); err != nil {
		return fmt.Errorf("enterprise hooks: refusing unsafe %s path: %w", label, err)
	}
	owner, err := enterpriseWindowsPathOwner(dataDir)
	if err != nil {
		return fmt.Errorf("enterprise hooks: inspect managed data_dir owner: %w", err)
	}
	if err := enterpriseWindowsProtectionWriter(filepath.Dir(path), owner, true); err != nil {
		return fmt.Errorf("enterprise hooks: harden %s directory: %w", label, err)
	}
	if err := enterpriseWindowsProtectionWriter(path, owner, false); err != nil {
		return fmt.Errorf("enterprise hooks: harden %s: %w", label, err)
	}
	return validateEnterpriseWindowsTokenLocation(dataDir, path, label)
}

func enterpriseWindowsPathOwner(path string) (*windows.SID, error) {
	extended, err := winpath.Extended(path)
	if err != nil {
		return nil, err
	}
	sd, err := windows.GetNamedSecurityInfo(extended, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return nil, err
	}
	owner, _, err := sd.Owner()
	return owner, err
}

func setEnterpriseWindowsManagedProtection(path string, owner *windows.SID, directory bool) error {
	if owner == nil {
		return fmt.Errorf("managed owner SID is unavailable")
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return err
	}
	administrators, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return err
	}
	inheritance := uint32(windows.NO_INHERITANCE)
	if directory {
		inheritance = windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT
	}
	entries := []windows.EXPLICIT_ACCESS{}
	for _, sid := range []*windows.SID{owner, system, administrators} {
		entries = append(entries, windows.EXPLICIT_ACCESS{
			AccessPermissions: windows.GENERIC_ALL,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       inheritance,
			Trustee:           windows.TRUSTEE{TrusteeForm: windows.TRUSTEE_IS_SID, TrusteeType: windows.TRUSTEE_IS_USER, TrusteeValue: windows.TrusteeValueFromSID(sid)},
		})
	}
	acl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		return err
	}
	pathPtr, err := winpath.UTF16Ptr(path)
	if err != nil {
		return err
	}
	flags := uint32(windows.FILE_FLAG_OPEN_REPARSE_POINT)
	if directory {
		flags |= windows.FILE_FLAG_BACKUP_SEMANTICS
	}
	handle, err := windows.CreateFile(
		pathPtr,
		windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL|windows.WRITE_DAC|windows.WRITE_OWNER|windows.SYNCHRONIZE,
		windows.FILE_SHARE_READ,
		nil,
		windows.OPEN_EXISTING,
		flags,
		0,
	)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(handle)

	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return err
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("refusing to apply ACL to a reparse point")
	}
	isDirectory := info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0
	if isDirectory != directory {
		return fmt.Errorf("managed path type changed while applying ACL")
	}
	if err := windows.SetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, owner, nil, nil, nil); err != nil {
		return err
	}
	return windows.SetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
}
