// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

// Attributes cleared on DefenseClaw's own files. ReadOnly makes a replace or
// a write open fail with access denied that has nothing to do with the ACL;
// System and Hidden mark the file as something else's. Lock files are created
// hidden, so Hidden is left on them.
const (
	windowsManagedPolicyStateAttributes = windows.FILE_ATTRIBUTE_READONLY | windows.FILE_ATTRIBUTE_HIDDEN |
		windows.FILE_ATTRIBUTE_SYSTEM
	windowsManagedPolicyLockAttributes = windows.FILE_ATTRIBUTE_READONLY | windows.FILE_ATTRIBUTE_SYSTEM
)

// windowsManagedPolicySelfHealFile is one DefenseClaw-owned file in a machine
// policy folder.
type windowsManagedPolicySelfHealFile struct {
	name         string
	userReadable bool
	// clear is the attribute set cleared on the file.
	clear uint32
	// exact holds the file at the exact machine-file descriptor its writer
	// stamps. Otherwise (hooks.json, which keeps a descriptor that existed
	// before DefenseClaw) it is re-stamped only when an untrusted principal
	// can write or owns it.
	exact bool
	// marker: the file only exists while DefenseClaw manages the connector.
	marker bool
}

// windowsManagedPolicySelfHealFolder is one machine policy folder and the
// DefenseClaw files in it.
type windowsManagedPolicySelfHealFolder struct {
	path string
	// exact holds the folder at the exact protected descriptor (Cursor's
	// transaction requires it). Otherwise the folder, shared with the vendor,
	// keeps its descriptor unless an untrusted principal can write or owns
	// it, as the installer and the policy transactions treat it.
	exact bool
	files []windowsManagedPolicySelfHealFile
}

// windowsManagedPolicySelfHealFolders resolves the Claude Code, Codex and
// Cursor policy folders. A folder whose location cannot be resolved is left
// out.
func windowsManagedPolicySelfHealFolders() []windowsManagedPolicySelfHealFolder {
	selector := []windowsManagedPolicySelfHealFile{
		{name: windowsManagedRuntimeSelectorFile, userReadable: true, clear: windowsManagedPolicyStateAttributes, exact: true, marker: true},
		{name: windowsManagedRuntimeSelectorLockFile, clear: windowsManagedPolicyLockAttributes, exact: true},
	}
	var folders []windowsManagedPolicySelfHealFolder
	if policyPath, err := windowsClaudeManagedPolicyPath(); err == nil {
		folders = append(folders, windowsManagedPolicySelfHealFolder{
			path: filepath.Dir(policyPath),
			files: append([]windowsManagedPolicySelfHealFile{
				{name: windowsClaudeManagedPolicyFile, userReadable: true, exact: true},
				{name: windowsClaudeManagedStateFile, userReadable: true, clear: windowsManagedPolicyStateAttributes, exact: true, marker: true},
				{name: windowsClaudeManagedLockFile, clear: windowsManagedPolicyLockAttributes, exact: true},
			}, selector...),
		})
	}
	if requirementsPath, err := windowsCodexMachineRequirementsPath(); err == nil {
		// The Codex state and lock share the Claude leaf names; the Codex
		// writer makes all three user-readable.
		folders = append(folders, windowsManagedPolicySelfHealFolder{
			path: filepath.Dir(requirementsPath),
			files: append([]windowsManagedPolicySelfHealFile{
				{name: filepath.Base(requirementsPath), userReadable: true, exact: true},
				{name: windowsClaudeManagedStateFile, userReadable: true, clear: windowsManagedPolicyStateAttributes, exact: true, marker: true},
				{name: windowsClaudeManagedLockFile, userReadable: true, clear: windowsManagedPolicyLockAttributes, exact: true},
			}, selector...),
		})
	}
	if paths, err := windowsCursorManagedPaths(); err == nil {
		folders = append(folders, windowsManagedPolicySelfHealFolder{
			path:  paths.Root,
			exact: true,
			files: append([]windowsManagedPolicySelfHealFile{
				{name: filepath.Base(paths.Hooks), userReadable: true},
				{name: filepath.Base(paths.Adapter), userReadable: true, exact: true},
				{name: filepath.Base(paths.State), userReadable: true, clear: windowsManagedPolicyStateAttributes, exact: true, marker: true},
				{name: filepath.Base(paths.Receipt), clear: windowsManagedPolicyStateAttributes, exact: true, marker: true},
				{name: filepath.Base(paths.Lock), clear: windowsManagedPolicyLockAttributes, exact: true},
			}, selector...),
		})
	}
	return folders
}

// RepairWindowsManagedPolicyArtifacts keeps the Claude Code, Codex and Cursor
// policy folders and DefenseClaw's own files in them at their canonical
// protection, for the LocalSystem hook guardian's every pass. A folder is
// touched only while DefenseClaw manages that connector (its state or
// selector file is present), and only DefenseClaw's own files in it are
// examined; vendor files are never opened. Each object is read first and
// written only when it drifted: restrictive attributes are cleared from
// DefenseClaw's lock and state files, and owner and DACL are re-stamped
// through the no-follow, owner-checked writers the policy transactions use.
// Every repair is logged once with MarkerRepair; anything that cannot be
// repaired is logged once and left for the transactions to judge. Nothing
// here returns an error, and one object never stops the others.
func RepairWindowsManagedPolicyArtifacts() {
	if managed.WindowsCurrentProcessIsGatewayService() {
		return
	}
	if err := requireWindowsEnterpriseAdministrator(); err != nil {
		return
	}
	for _, folder := range windowsManagedPolicySelfHealFolders() {
		repairWindowsManagedPolicySelfHealFolder(folder)
	}
}

func repairWindowsManagedPolicySelfHealFolder(folder windowsManagedPolicySelfHealFolder) {
	info, err := os.Lstat(folder.path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return
	}
	managedConnector := false
	for _, file := range folder.files {
		if file.marker && windowsPathExists(filepath.Join(folder.path, file.name)) {
			managedConnector = true
			break
		}
	}
	if !managedConnector {
		return
	}
	if err := rejectWindowsReparseChain(folder.path); err != nil {
		reportWindowsManagedPolicySelfHeal(managed.MarkerBoundary, folder.path, err)
		return
	}
	check := windowsManagedPolicyLeafTrust(managed.ObjectInstallDirectory)
	if folder.exact {
		check = validateWindowsManagedPolicyDirectoryDescriptor
	}
	if check(folder.path) != nil {
		if err := repairWindowsManagedPolicyFolder(folder.path, check); err != nil {
			reportWindowsManagedPolicySelfHeal(managed.MarkerAccept, folder.path, err)
		} else {
			reportWindowsManagedPolicySelfHeal("", folder.path, nil)
		}
	} else {
		reportWindowsManagedPolicySelfHeal("", folder.path, nil)
	}
	for _, file := range folder.files {
		repairWindowsManagedPolicySelfHealFile(filepath.Join(folder.path, file.name), file)
	}
}

func repairWindowsManagedPolicySelfHealFile(path string, file windowsManagedPolicySelfHealFile) {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return
	}
	if err := rejectWindowsReparseChain(path); err != nil {
		reportWindowsManagedPolicySelfHeal(managed.MarkerBoundary, path, err)
		return
	}
	clearWindowsManagedPolicyFileAttributes(path, file.clear)
	check := windowsManagedPolicyLeafTrust(managed.ObjectInstallFile)
	if file.exact {
		userReadable := file.userReadable
		check = func(path string) error {
			return validateWindowsManagedMachineFileDescriptor(path, userReadable)
		}
	}
	if check(path) == nil {
		reportWindowsManagedPolicySelfHeal("", path, nil)
		return
	}
	if _, err := repairWindowsManagedMachineFile(path, file.userReadable, check); err != nil {
		reportWindowsManagedPolicySelfHeal(managed.MarkerAccept, path, err)
		return
	}
	reportWindowsManagedPolicySelfHeal("", path, nil)
}

// windowsManagedPolicyLeafTrust judges only the object's own descriptor: it
// fails when an untrusted principal can write the object or owns it, and
// accepts every other drift. Ancestors are not walked, so drift above the
// policy folder never makes a repaired leaf look unrepaired.
func windowsManagedPolicyLeafTrust(kind managed.ObjectKind) func(string) error {
	return func(path string) error {
		result, err := managed.AssessCanonical(path, kind, managed.CanonicalOptions{Quiet: true})
		if err != nil {
			return err
		}
		if result.Outcome == managed.CanonicalBoundary {
			return fmt.Errorf("enterprise hooks: an untrusted principal can write or owns %s: %s",
				path, strings.Join(result.Drift, "; "))
		}
		return nil
	}
}

// clearWindowsManagedPolicyFileAttributes clears mask from an existing
// DefenseClaw file. The caller has already refused a reparse point on the
// path; only the attributes change.
func clearWindowsManagedPolicyFileAttributes(path string, mask uint32) {
	if mask == 0 {
		return
	}
	pointer, err := winpath.UTF16Ptr(path)
	if err != nil {
		return
	}
	attributes, err := windows.GetFileAttributes(pointer)
	if err != nil || attributes&mask == 0 || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return
	}
	remaining := attributes &^ mask
	if remaining == 0 {
		remaining = windows.FILE_ATTRIBUTE_NORMAL
	}
	if err := windows.SetFileAttributes(pointer, remaining); err != nil {
		reportWindowsManagedPolicySelfHeal(managed.MarkerAccept, path+"#attributes",
			fmt.Errorf("clear file attributes 0x%x: %w", attributes&mask, err))
		return
	}
	reportWindowsManagedPolicySelfHeal("", path+"#attributes", nil)
	managed.EmitResilienceEvent(managed.MarkerRepair, map[string]string{
		"path":   path,
		"reason": fmt.Sprintf("cleared file attributes 0x%x on a DefenseClaw lock or state file", attributes&mask),
	})
}

// windowsManagedPolicySelfHealReported holds the last unrepaired finding per
// object, so a guardian tick does not repeat a finding that has not changed.
var windowsManagedPolicySelfHealReported sync.Map

// reportWindowsManagedPolicySelfHeal logs an unrepaired finding once per
// object and change. An empty marker records that the object is healthy
// again, so the same finding returning later is logged again.
func reportWindowsManagedPolicySelfHeal(marker, key string, err error) {
	if marker == "" || err == nil {
		windowsManagedPolicySelfHealReported.Delete(key)
		return
	}
	path := strings.TrimSuffix(key, "#attributes")
	line := marker + "\x00" + err.Error()
	if previous, loaded := windowsManagedPolicySelfHealReported.Swap(key, line); loaded && previous == line {
		return
	}
	managed.EmitResilienceEvent(marker, map[string]string{
		"path":   path,
		"reason": "machine policy object drift was not repaired: " + err.Error(),
	})
}
