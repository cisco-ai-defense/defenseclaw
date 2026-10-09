// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/sys/windows"
)

// Amp and OpenCode load every file in their user plugin folder, and that
// folder is on their managed footprint: Amp's holds DefenseClaw's whole-file
// plugin (defenseclaw.ts), so the guardian keeps it at its exact protected
// DACL, and the enumerator left both folders out. The gateway service had
// no access there, so the managed watcher logged "Access is denied" every
// poll and never scanned a plugin the user added (GAP-0958).
//
// The exact DACL of these two folders therefore admits one more entry: the
// read grant the enumerator gives the gateway service on every other skill
// and plugin folder (inventoryReadACE), for NT SERVICE\DefenseClawGateway
// only. It is read, list, traverse and read-attributes, inherited by the
// user's plugins. It holds no write, append, delete, delete-child, WRITE_DAC
// or WRITE_OWNER right, so the gateway can neither change, rename, remove
// nor add a file in the folder. DefenseClaw's plugin and its lock carry
// their own protected DACLs and do not inherit it. The entry is optional:
// the guardian accepts the folder with or without it and never adds it, the
// enumerator adds it, and the uninstall revokes it.
var windowsGatewayReadablePluginRoots = []string{
	`.config\amp\plugins`,
	`.config\opencode\plugins`,
}

// windowsGatewayReadablePluginRoot reports whether path is the plugin folder
// of Amp or OpenCode in a user profile.
func windowsGatewayReadablePluginRoot(path string) bool {
	clean := strings.ToLower(filepath.Clean(path))
	for _, rel := range windowsGatewayReadablePluginRoots {
		if strings.HasSuffix(clean, `\`+strings.ToLower(rel)) {
			return true
		}
	}
	return false
}

// windowsGatewayPluginRootReadSID is the service SID of the standalone
// gateway service, derived from its name.
var windowsGatewayPluginRootReadSID = sync.OnceValues(func() (*windows.SID, error) {
	return windows.StringToSid(windowsServiceSIDString(productionGatewayServiceName))
})

// windowsGatewayPluginRootAppliedACEs is the read grant as Windows stores it
// on a folder: the mapped rights on the folder itself and an inherit-only
// entry that keeps the generic rights for its children.
func windowsGatewayPluginRootAppliedACEs() []windowsUserPathAppliedACE {
	sid, err := windowsGatewayPluginRootReadSID()
	if err != nil {
		return nil
	}
	return []windowsUserPathAppliedACE{
		{sid: sid, mask: mapWindowsUserPathGenericMask(inventoryReadACE.mask)},
		{sid: sid, mask: inventoryReadACE.mask, flags: uint8(inventoryReadACE.inheritance) | windows.INHERIT_ONLY_ACE},
	}
}

// ensureGatewayPluginRootReadACEPinned adds the gateway read grant to the
// Amp or OpenCode plugin folder home\rel of target. The folder must be a
// plain directory the target owns, opened without following links, and
// carry exactly the guardian's protected DACL; otherwise it is left for the
// guardian to restore and granted on a later cycle. The new DACL is the
// guardian's canonical DACL plus the grant, still protected.
func ensureGatewayPluginRootReadACEPinned(home, rel string, sid, target *windows.SID) (inventoryDACLResult, error) {
	gateway, err := windowsGatewayPluginRootReadSID()
	if err != nil || sid == nil || target == nil || !sid.Equals(gateway) {
		return inventoryDACLSkippedMissing, err
	}
	path := filepath.Join(home, rel)
	if !windowsGatewayReadablePluginRoot(path) {
		return inventoryDACLSkippedMissing, nil
	}
	handle, err := openInventoryDACLHandle(home, rel)
	if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
		return inventoryDACLSkippedMissing, nil
	}
	if err != nil {
		return inventoryDACLSkippedMissing, err
	}
	defer windows.CloseHandle(handle)
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return inventoryDACLSkippedMissing, err
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		return inventoryDACLSkippedMissing, nil
	}
	protected := func() (bool, *windows.ACL, error) {
		sd, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			return false, nil, fmt.Errorf("get DACL: %w", err)
		}
		owner, _, err := sd.Owner()
		if err != nil || owner == nil || !owner.Equals(target) {
			return false, nil, nil
		}
		dacl, _, err := sd.DACL()
		if err != nil || dacl == nil {
			return false, nil, nil
		}
		return validateWindowsUserPathProtectionACL(path, sd, dacl, target, true) == nil, dacl, nil
	}
	ok, dacl, err := protected()
	if err != nil || !ok {
		return inventoryDACLSkippedMissing, err
	}
	if daclContainsInventoryReadACE(dacl, sid) {
		return inventoryDACLAlreadyPresent, nil
	}
	canonical, err := windowsUserPathCanonicalACEs(target, true)
	if err != nil {
		return inventoryDACLSkippedMissing, err
	}
	canonical = append(canonical, windowsUserPathCanonicalACE{sid: sid, mask: inventoryReadACE.mask, inheritance: inventoryReadACE.inheritance})
	entries := make([]windows.EXPLICIT_ACCESS, 0, len(canonical))
	for _, item := range canonical {
		entries = append(entries, windows.EXPLICIT_ACCESS{
			AccessPermissions: item.mask,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       item.inheritance,
			Trustee: windows.TRUSTEE{TrusteeForm: windows.TRUSTEE_IS_SID, TrusteeType: windows.TRUSTEE_IS_USER,
				TrusteeValue: windows.TrusteeValueFromSID(item.sid)},
		})
	}
	acl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		return inventoryDACLSkippedMissing, fmt.Errorf("build plugin folder DACL: %w", err)
	}
	// SetSecurityInfo also gives the plugins already in the folder the
	// inherited grant; DefenseClaw's own plugin keeps its protected DACL.
	if err := windows.SetSecurityInfo(handle, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		return inventoryDACLSkippedMissing, fmt.Errorf("set DACL: %w", err)
	}
	if ok, dacl, err := protected(); err != nil || !ok || !daclContainsInventoryReadACE(dacl, sid) {
		return inventoryDACLSkippedMissing, errors.Join(errors.New("plugin folder DACL is not the guardian DACL plus the gateway read grant"), err)
	}
	return inventoryDACLGranted, nil
}
