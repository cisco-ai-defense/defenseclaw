// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

var (
	enterpriseWindowsReparseChainCheck = winpath.RejectReparseChain
	enterpriseWindowsProtectionWriter  = setEnterpriseWindowsManagedProtection
	enterpriseWindowsManagedPathOwner  = enterpriseWindowsPathOwner
	enterpriseWindowsGatewaySID        = enterpriseWindowsGatewayServiceSID
)

// repairEnterpriseHookManagedRuntimePlatform repairs only the gateway's
// service-writable runtime directory. AVC owns the shared Cisco tree above it
// and can re-apply that product's ACL template after DefenseClaw installation;
// the LocalSystem guardian is the only component allowed to restore the
// DefenseClaw leaf contract before a virtual-account gateway starts.
//
// The fast path is validation-only, so a healthy runtime does not generate a
// filesystem/ACL event on every guardian reconcile. Repair is allowed only
// when the current object is a real directory with a trusted owner. A
// user-owned or reparse-point path remains a hard failure; it is never adopted.
func repairEnterpriseHookManagedRuntimePlatform(path, serviceAccount string) error {
	if strings.TrimSpace(serviceAccount) == "" {
		return nil
	}

	// Healthy installations must remain no-write.
	if err := managed.ValidateTrustedServiceRuntimeDir(
		path,
		"managed data_dir",
		serviceAccount,
	); err == nil {
		return nil
	}

	// Never follow or adopt a junction, symlink, mount point, or other reparse
	// chain when applying privileged ACLs.
	if err := enterpriseWindowsReparseChainCheck(path); err != nil {
		return fmt.Errorf("refusing unsafe managed data_dir: %w", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("inspect managed data_dir: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("managed data_dir is not a directory")
	}

	owner, err := enterpriseWindowsManagedPathOwner(path)
	if err != nil {
		return fmt.Errorf("inspect managed data_dir owner: %w", err)
	}

	serviceSID, err := enterpriseWindowsGatewaySID()
	if err != nil {
		return err
	}

	if !enterpriseWindowsRuntimeRepairOwnerTrusted(owner, serviceSID) {
		ownerSID := "<nil>"
		if owner != nil {
			ownerSID = owner.String()
		}
		return fmt.Errorf("managed data_dir owner is not trusted: %s", ownerSID)
	}

	// Go through the shared runtime-protection helper so the owner/restore
	// privilege is held for the write. A directory owned by TrustedInstaller or
	// by the gateway service SID cannot have its owner and primary group reset
	// without it, and ACL drift that stripped WRITE_OWNER would otherwise fail
	// the open itself.
	if err := setEnterpriseWindowsRuntimeProtection(path, owner, serviceSID, true); err != nil {
		return fmt.Errorf("repair managed data_dir ACL: %w", err)
	}

	return nil
}

// enterpriseWindowsRuntimeRepairOwnerTrusted reports whether a drifted managed
// runtime directory may be repaired in place. Only installer-owned objects
// (LocalSystem, Administrators, TrustedInstaller) and the gateway's own service
// SID qualify; a user-owned directory is never adopted, because repairing it
// would hand a protected ACL to whoever won the race to create it.
func enterpriseWindowsRuntimeRepairOwnerTrusted(
	owner, serviceSID *windows.SID,
) bool {
	if owner == nil || !owner.IsValid() {
		return false
	}

	trustedInstaller, _ := windows.StringToSid(
		"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
	)

	if owner.IsWellKnown(windows.WinLocalSystemSid) ||
		owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) ||
		(trustedInstaller != nil && owner.Equals(trustedInstaller)) {
		return true
	}

	return serviceSID != nil && owner.Equals(serviceSID)
}

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
	serviceAccount := os.Getenv(managed.WindowsServiceAccountEnv)
	if err := managed.ValidateTrustedServiceRuntimeDir(dataDir, "managed data_dir", serviceAccount); err != nil {
		return fmt.Errorf("enterprise hooks: %w", err)
	}
	dir := filepath.Dir(path)
	if _, err := os.Lstat(dir); err == nil {
		if err := managed.ValidateTrustedServiceRuntimeDir(dir, label+" directory", serviceAccount); err != nil {
			return fmt.Errorf("enterprise hooks: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if _, err := os.Lstat(path); err == nil {
		if err := managed.ValidateTrustedServiceRuntimeFilePath(path, label, serviceAccount); err != nil {
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
	serviceSID, err := enterpriseWindowsGatewayServiceSID()
	if err != nil {
		return err
	}
	if err := setEnterpriseWindowsRuntimeProtection(filepath.Dir(path), owner, serviceSID, true); err != nil {
		return fmt.Errorf("enterprise hooks: harden %s directory: %w", label, err)
	}
	if err := setEnterpriseWindowsRuntimeProtection(path, owner, serviceSID, false); err != nil {
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

func enterpriseWindowsGatewayServiceSID() (*windows.SID, error) {
	account := os.Getenv(managed.WindowsServiceAccountEnv)
	if account == "" {
		return nil, fmt.Errorf(
			"enterprise hooks: %s must pin the gateway NT SERVICE account",
			managed.WindowsServiceAccountEnv,
		)
	}
	sid, err := managed.WindowsServiceAccountSID(account)
	if err != nil {
		return nil, fmt.Errorf("enterprise hooks: resolve gateway service SID: %w", err)
	}
	if sid == nil {
		return nil, fmt.Errorf("enterprise hooks: gateway service SID is unavailable")
	}
	return sid, nil
}

func setEnterpriseWindowsRuntimeProtection(path string, owner, serviceSID *windows.SID, directory bool) error {
	const serviceModify = windows.GENERIC_READ |
		windows.GENERIC_WRITE |
		windows.GENERIC_EXECUTE |
		windows.DELETE
	return enterprisehooks.RunWithWindowsOwnerRestorePrivilege(func() error {
		return enterpriseWindowsProtectionWriter(path, owner, serviceSID, serviceModify, directory)
	})
}

func setEnterpriseWindowsManagedProtection(
	path string,
	owner *windows.SID,
	serviceSID *windows.SID,
	servicePermissions windows.ACCESS_MASK,
	directory bool,
) error {
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
	entries := make([]windows.EXPLICIT_ACCESS, 0, 4)
	for _, sid := range []*windows.SID{owner, system, administrators} {
		entries = append(entries, windows.EXPLICIT_ACCESS{
			AccessPermissions: windows.GENERIC_ALL,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       inheritance,
			Trustee:           windows.TRUSTEE{TrusteeForm: windows.TRUSTEE_IS_SID, TrusteeType: windows.TRUSTEE_IS_USER, TrusteeValue: windows.TrusteeValueFromSID(sid)},
		})
	}
	if serviceSID != nil && servicePermissions != 0 {
		entries = append(entries, windows.EXPLICIT_ACCESS{
			AccessPermissions: servicePermissions,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       inheritance,
			Trustee:           windows.TRUSTEE{TrusteeForm: windows.TRUSTEE_IS_SID, TrusteeType: windows.TRUSTEE_IS_USER, TrusteeValue: windows.TrusteeValueFromSID(serviceSID)},
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
	// Set owner + primary group in a single call so the file's canonical
	// descriptor matches the AdminFile/AdminDirectory SDDL contract
	// (O:BAG:BA...) validated by validateWindowsTargetsManifestObject.
	// Windows otherwise leaves the group as whatever default it defers to
	// (commonly "None" / current-user primary group), which causes
	// downstream group-match checks to fail with
	// "hook guardian manifest object has noncanonical group" — the
	// exact symptom that broke uninstall of the managed hook contract
	// cleanup receipt.
	if err := windows.SetSecurityInfo(
		handle, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION,
		owner, administrators, nil, nil,
	); err != nil {
		return err
	}
	return windows.SetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
}
