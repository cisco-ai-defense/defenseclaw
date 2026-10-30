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
}

// targets expands the layout into the ordered object list, parents before
// children. Only objects the installer stamps are listed: nothing else in
// these folders is touched.
func (layout ManagedInstallLayout) targets() []managedDataTarget {
	var targets []managedDataTarget
	add := func(kind ObjectKind, parts ...string) {
		for _, part := range parts {
			if strings.TrimSpace(part) == "" {
				return
			}
		}
		targets = append(targets, managedDataTarget{path: filepath.Clean(filepath.Join(parts...)), kind: kind})
	}
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
		add(ObjectConfigFile, root, "etc", "config.yaml")
		add(ObjectAdminFile, root, "hook-guardian", "targets.yaml")
		for _, name := range []string{
			"deployment.json",
			"agent-application-control-attestation.json",
			"codex-requirements-ownership.json",
			"codex-requirements-acl-backup.json",
			"managed-hooks-teardown-journal.json",
		} {
			add(ObjectAdminFile, root, "install", name)
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
func RepairWindowsManagedInstall(layout ManagedInstallLayout, opts CanonicalOptions) []CanonicalResult {
	targets := layout.targets()
	results := make([]CanonicalResult, 0, len(targets))
	for _, target := range targets {
		result, _ := EnsureCanonical(target.path, target.kind, opts)
		results = append(results, result)
	}
	return results
}
