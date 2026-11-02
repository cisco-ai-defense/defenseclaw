// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

// The guardian's self-heal steps. Overridable by tests.
var (
	enterpriseWindowsManagedInstallRepair         = managed.RepairWindowsManagedInstall
	enterpriseWindowsManagedPolicyArtifactsRepair = enterprisehooks.RepairWindowsManagedPolicyArtifacts
	enterpriseWindowsManagedServiceSecurityRepair = managed.RepairWindowsManagedServiceSecurity
)

// enterpriseHookOwnerTransferAllowed reports whether the guardian's self-heal
// may take ownership of an existing object at path from a principal outside
// the trusted set. It is only consulted for objects DefenseClaw created and
// already holds (the state root's folders and records, data_dir, the guardian
// ledger, the token folders), and only inside the platform installer's tree,
// where a standard user cannot create objects: a foreign owner there is drift
// (a backup restore, a helpdesk takeown), not a planted object. Paths where
// an object may be created by someone else first keep refusing it, and
// TrustStrictAncestorsEnv restores the refusal everywhere.
//
// Membership in the installer tree alone is not enough: every existing
// ancestor from the object's parent up to and including the installer root
// it sits under must itself be installer-owned (a trusted owner, no reparse
// point). If a standard user managed to create a folder in the chain before
// the installer locked it, everything below is theirs and is never adopted.
func enterpriseHookOwnerTransferAllowed(path string) bool {
	if strings.TrimSpace(path) == "" || managed.TrustStrictAncestors() ||
		!managed.PlatformInstallerOwnedPath(path) {
		return false
	}
	clean := filepath.Clean(path)
	root := enterpriseHookInstallerRootFor(clean)
	if root == "" {
		return false
	}
	for dir := clean; !strings.EqualFold(dir, root); {
		parent := filepath.Dir(dir)
		if parent == dir {
			return false
		}
		dir = parent
		owner, reparse, exists, err := enterpriseHookAncestorOwnerLookup(dir)
		if err != nil {
			return false
		}
		if !exists {
			continue
		}
		if reparse || !managed.IsWindowsTrustedAdminOwner(owner) {
			return false
		}
	}
	return true
}

// enterpriseHookInstallerRootFor returns the platform installer root that
// path is at or below, or "" when there is none.
func enterpriseHookInstallerRootFor(path string) string {
	for _, root := range managed.PlatformInstallerOwnedRoots() {
		root = filepath.Clean(root)
		if strings.EqualFold(path, root) ||
			strings.HasPrefix(strings.ToLower(path), strings.ToLower(strings.TrimRight(root, `\`)+`\`)) {
			return root
		}
	}
	return ""
}

// enterpriseHookAncestorOwnerLookup reads an ancestor's owner and whether it
// is a reparse point, without following one. A missing ancestor reports
// exists=false. Overridable by tests.
var enterpriseHookAncestorOwnerLookup = func(path string) (*windows.SID, bool, bool, error) {
	extended, err := winpath.Extended(path)
	if err != nil {
		return nil, false, false, err
	}
	name, err := windows.UTF16PtrFromString(extended)
	if err != nil {
		return nil, false, false, err
	}
	attributes, err := windows.GetFileAttributes(name)
	if err != nil {
		if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
			return nil, false, false, nil
		}
		return nil, false, false, err
	}
	if attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return nil, true, true, nil
	}
	owner, err := enterpriseWindowsPathOwner(path)
	if err != nil {
		return nil, false, true, err
	}
	return owner, false, true, nil
}

// repairEnterpriseHookManagedInstallPlatform keeps the rest of the managed
// installation at the installer's canonical protection on every Guardian
// pass, so permission drift that arrives after Setup (a GPO security
// template, an EDR ACL stamp, a helpdesk icacls, a ReadOnly attribute, a
// hardened service descriptor) heals without anyone running Setup Repair:
//
//   - the install tree (InstallRoot, bin and its executables, libexec and the
//     installer module, the IPC folder) and StateRoot's managed folders and
//     records, through managed.RepairWindowsManagedInstall;
//   - the Claude Code, Codex and Cursor policy folders and DefenseClaw's own
//     files in them, through enterprisehooks.RepairWindowsManagedPolicyArtifacts;
//   - the SCM descriptor and registry key of the four services, through
//     managed.RepairWindowsManagedServiceSecurity.
//
// Every object is read first and written only when it drifted, each step and
// each object stands alone, and every repair is logged once. Nothing here
// fails the reconcile. It stays out of the way while an installer lifecycle
// transaction is pending, so it never races Setup.
func repairEnterpriseHookManagedInstallPlatform() {
	if cfg == nil || !managed.IsManagedEnterprise(cfg.DeploymentMode) ||
		managed.WindowsCurrentProcessIsGatewayService() {
		return
	}
	if !enterpriseHookNoLifecycleTransactionPending(cfg.DataDir) {
		return
	}
	executable, _ := os.Executable()
	programFiles, _ := winpath.TrustedProgramFiles()
	programData, _ := winpath.TrustedProgramData()
	if layout, ok := enterpriseHookManagedInstallLayout(
		executable, cfg.DataDir, enterpriseHookManifest, programFiles, programData,
	); ok {
		// The state root's folders and records are DefenseClaw's own, so a
		// foreign owner there is adopted; the install tree keeps the refusal.
		stateLayout := managed.ManagedInstallLayout{StateRoot: layout.StateRoot}
		layout.StateRoot = ""
		_ = enterpriseWindowsManagedInstallRepair(layout, managed.CanonicalOptions{})
		_ = enterpriseWindowsManagedInstallRepair(stateLayout, managed.CanonicalOptions{
			AllowUntrustedOwnerTransfer: enterpriseHookOwnerTransferAllowed(stateLayout.StateRoot),
		})
	}
	enterpriseWindowsManagedPolicyArtifactsRepair()
	_ = enterpriseWindowsManagedServiceSecurityRepair(managed.ManagedServiceNames(
		os.Getenv(enterpriseHookGatewayServiceNameEnv),
		os.Getenv(enterpriseHookServiceNameEnv),
	))
}
