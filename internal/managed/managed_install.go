// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"path/filepath"
	"strings"
)

// ManagedInstallLayout names the installed tree and the state records the
// hook guardian keeps at their canonical protection between installer
// actions. Empty fields are skipped. The objects and kinds mirror the
// installer module's Set-DefenseClawManagedAcls; the gateway data objects and
// the guardian ledger are repaired by their own helpers and are not listed.
type ManagedInstallLayout struct {
	// InstallRoot holds bin and libexec.
	InstallRoot string
	// StateRoot holds etc, install, hook-guardian, cmid-broker and logs.
	StateRoot string
	// IPCDirectory is the gateway's IPC socket folder. Set it only when the
	// folder belongs to this installation.
	IPCDirectory string
	// Standalone lists the lock files the standalone profile creates lazily
	// inside StateRoot. The Secure Client profile leaves it false and keeps
	// the objects it listed before (GAP-0766).
	Standalone bool
}

// targets expands the layout into the ordered object list, parents before
// children. Only objects the installer stamps are listed: nothing else in
// these folders is touched.
func (layout ManagedInstallLayout) targets() []managedDataTarget {
	var targets []managedDataTarget
	addTarget := func(content bool, kind ObjectKind, parts ...string) {
		for _, part := range parts {
			if strings.TrimSpace(part) == "" {
				return
			}
		}
		targets = append(targets, managedDataTarget{
			path: filepath.Clean(filepath.Join(parts...)), kind: kind, content: content,
		})
	}
	add := func(kind ObjectKind, parts ...string) { addTarget(false, kind, parts...) }
	// addContent lists a file whose bytes a trust decision reads. The two
	// logs are written by the services and never read as policy, so they
	// keep the plain repair.
	addContent := func(kind ObjectKind, parts ...string) { addTarget(true, kind, parts...) }
	if root := layout.InstallRoot; strings.TrimSpace(root) != "" {
		bin := filepath.Join(root, "bin")
		libexec := filepath.Join(root, "libexec")
		add(ObjectServiceInstallDirectory, root)
		add(ObjectServiceInstallDirectory, bin)
		add(ObjectInstallDirectory, libexec)
		add(ObjectServiceInstallFile, bin, "defenseclaw-gateway.exe")
		for _, name := range []string{"defenseclaw-hook.exe", "defenseclaw-cmid-broker.exe", "defenseclaw.exe"} {
			add(ObjectInstallFile, bin, name)
		}
		for _, name := range []string{"install-enterprise.ps1", "DefenseClawEnterprise.psm1"} {
			add(ObjectInstallFile, libexec, name)
		}
	}
	add(ObjectManagedIPCDirectory, layout.IPCDirectory)
	if root := layout.StateRoot; strings.TrimSpace(root) != "" {
		add(ObjectStateDirectory, root)
		add(ObjectConfigDirectory, root, "etc")
		add(ObjectAdminDirectory, root, "hook-guardian")
		add(ObjectAdminDirectory, root, "install")
		add(ObjectAuthorizationDirectory, root, "cmid-broker")
		add(ObjectLogDirectory, root, "logs")
		add(ObjectAdminDirectory, root, "logs", "guardian")
		add(ObjectAdminDirectory, root, "logs", "cmid-broker")
		addContent(ObjectConfigFile, root, "etc", "config.yaml")
		if layout.Standalone {
			// The config writer's lock sits beside the config and is created
			// lazily; an untrusted write entry on it would let any account
			// hold the lock (GAP-0766). Its bytes are never read, so it is
			// not content.
			add(ObjectConfigFile, root, "etc", "config.yaml.lock")
		}
		addContent(ObjectAdminFile, root, "hook-guardian", "targets.yaml")
		for _, name := range []string{
			"deployment.json",
			"agent-application-control-attestation.json",
			"codex-requirements-ownership.json",
			"codex-requirements-acl-backup.json",
			"managed-hooks-teardown-journal.json",
			"managed-hooks-lifecycle-journal.json",
		} {
			addContent(ObjectAdminFile, root, "install", name)
		}
		add(ObjectAdminFile, root, "logs", "guardian", "hook-guardian.log")
		add(ObjectAdminFile, root, "logs", "cmid-broker", "cmid-broker.log")
	}
	return targets
}

// RepairWindowsManagedInstall runs EnsureCanonical over every object in
// layout and returns one result per object, in the order handled. Only the
// owner and DACL are ever written, never file contents, and a folder's
// descriptor is written without propagating to its children. A canonical
// object is only read; a missing one is skipped. One object's failure never
// stops the others. Only a privileged component may call it; inside the
// gateway service it degrades to a read-only assessment. On other platforms
// every result is CanonicalUnsupported.
//
// On standalone (StandaloneRefusesContentDrift) a content file that an
// untrusted principal can write or owns, or that the strict trust walk
// refuses, is not repaired: it is reported as a boundary finding and left
// as it is, so every reader keeps refusing it until Setup /ensure writes a
// fresh file. A repair would restore the descriptor over bytes that account
// may have changed (GAP-0561). ACL-only drift that gave no untrusted
// principal write (an extra read entry, inheritance) is still repaired.
// A managed folder (the state root, etc, hook-guardian, install, the broker,
// logs, the IPC folder) that an untrusted principal can write or owns is
// refused the same way: an account that could change it may have put or
// replaced objects in it, and a repair would erase the evidence before
// Setup or /verify sees it (g582 review 2 S4). Secure Client keeps the repair.
func RepairWindowsManagedInstall(layout ManagedInstallLayout, opts CanonicalOptions) []CanonicalResult {
	targets := layout.targets()
	if !windowsDescriptorPlatform() {
		return unsupportedCanonicalResults(targets)
	}
	refuseContentDrift := managedInstallRefusesContentDrift()
	results := make([]CanonicalResult, 0, len(targets))
	for _, target := range targets {
		if target.content && refuseContentDrift {
			if refused, ok := refuseStandaloneContentRepair(target, opts); ok {
				results = append(results, refused)
				continue
			}
		}
		if target.kind.Directory() && refuseContentDrift {
			if refused, ok := refuseStandaloneFolderRepair(target, opts); ok {
				results = append(results, refused)
				continue
			}
		}
		standaloneRepairAfterCheck(target.path)
		targetOpts := opts
		targetOpts.inPlaceOutOfClass = !target.content && !target.kind.Directory()
		result, err := EnsureCanonical(target.path, target.kind, targetOpts)
		if err == nil && result.Outcome != CanonicalBoundary && !target.kind.Directory() {
			// ReadOnly, Hidden or System set by a user or a hardening tool
			// stops the next managed write, so the guardian clears them too.
			// Only after the structural check and descriptor repair accepted
			// the object; the repair may restore FILE_WRITE_ATTRIBUTES.
			clearManagedFileRestrictiveAttributes(target.path)
		}
		results = append(results, result)
	}
	return results
}

// managedInstallRefusesContentDrift is StandaloneRefusesContentDrift; tests
// replace it.
var managedInstallRefusesContentDrift = StandaloneRefusesContentDrift

// standaloneRepairAfterCheck runs between a standalone read-only check and the
// repair of the same object; tests replace it to change the object in between
// (g582 review 6 S1). The repair judges the object again on its own handle.
var standaloneRepairAfterCheck = func(string) {}

// standaloneContentRepairRefusal is the recovery step logged with a refused
// content file.
var standaloneContentRepairRefusal = "not repaired in place on a standalone install, because an account " +
	"that could write this file may have changed it: from an elevated PowerShell prompt run `" + WindowsSetupCommand("/ensure") +
	"` so Setup writes a fresh file, then `" + WindowsAdminCommand("enterprise", "windows", "verify", "--profile", "standalone") +
	"` (GAP-0561). " + WindowsSetupSource

// standaloneFolderRepairRefusal is the recovery step logged with a refused
// managed folder.
const standaloneFolderRepairRefusal = "not repaired in place on a standalone install, because an account that " +
	"could change this folder may have put or replaced files in it: from an elevated prompt remove that entry " +
	"(icacls \"<folder>\" /remove:g *<SID>), or give the folder back to Administrators " +
	"(icacls \"<folder>\" /setowner *S-1-5-32-544), check what is in it, then run Setup /ensure and Setup /verify (GAP-0561)"

// refuseStandaloneFolderRepair reads a managed folder's descriptor without
// writing. When an untrusted principal can write or owns it, it logs the
// boundary finding with the way out and returns the result and true; the
// caller must then not repair it, whatever AllowUntrustedOwnerTransfer says.
// Trusted-only drift, a missing or a structurally bad folder returns false
// and takes the normal path.
func refuseStandaloneFolderRepair(target managedDataTarget, opts CanonicalOptions) (CanonicalResult, bool) {
	quiet := opts
	quiet.Quiet = true
	result, err := AssessCanonical(target.path, target.kind, quiet)
	if err != nil {
		// A reparse point, a hard link or an object of the wrong type is
		// reported as it is and never reaches the repair (g582 review 5 L1).
		reportCanonicalResult(result, opts)
		return result, true
	}
	if result.Outcome != CanonicalBoundary {
		return CanonicalResult{}, false
	}
	result.RepairError = standaloneFolderRepairRefusal
	reportCanonicalResult(result, opts)
	return result, true
}

// standaloneDataPathRepairRefusal is the recovery step logged with a refused
// gateway data file (a token, a database, the log).
const standaloneDataPathRepairRefusal = "not repaired in place on a standalone install, because an account that " +
	"could write this file may have changed it: from an elevated prompt remove that entry " +
	"(icacls \"<path>\" /remove:g *<SID>), or give it back to Administrators (icacls \"<path>\" /setowner *S-1-5-32-544), " +
	"check it, then run Setup /ensure and Setup /verify (GAP-0561)"

// refuseStandaloneDataPathRepair is refuseStandaloneFolderRepair for every
// managed data object: a folder or file an untrusted principal can write or
// owns is a boundary finding, logged with the way out, and not repaired.
func refuseStandaloneDataPathRepair(target managedDataTarget, opts CanonicalOptions) (CanonicalResult, bool) {
	if target.kind.Directory() {
		return refuseStandaloneFolderRepair(target, opts)
	}
	quiet := opts
	quiet.Quiet = true
	result, err := AssessCanonical(target.path, target.kind, quiet)
	if err != nil {
		reportCanonicalResult(result, opts)
		return result, true
	}
	if result.Outcome != CanonicalBoundary {
		return CanonicalResult{}, false
	}
	result.RepairError = standaloneDataPathRepairRefusal
	reportCanonicalResult(result, opts)
	return result, true
}

// refuseStandaloneContentRepair reads target's descriptor without writing.
// When an untrusted principal can write or owns the file, or the strict
// trust walk refuses it, it logs the boundary finding with the Setup step
// and returns the result and true; the caller must then not repair it. A
// missing, canonical or structurally bad object returns false and takes the
// normal path, which reports it.
func refuseStandaloneContentRepair(target managedDataTarget, opts CanonicalOptions) (CanonicalResult, bool) {
	quiet := opts
	quiet.Quiet = true
	result, err := AssessCanonical(target.path, target.kind, quiet)
	if err != nil {
		reportCanonicalResult(result, opts)
		return result, true
	}
	switch result.Outcome {
	case CanonicalBoundary:
		result.RepairError = standaloneContentRepairRefusal
	case CanonicalAccepted:
		strictErr := ValidateTrustedFilePath(target.path, string(target.kind))
		if strictErr == nil {
			return CanonicalResult{}, false
		}
		result.Outcome = CanonicalBoundary
		result.RepairError = standaloneContentRepairRefusal + ": " + strictErr.Error()
	default:
		return CanonicalResult{}, false
	}
	reportCanonicalResult(result, opts)
	return result, true
}
