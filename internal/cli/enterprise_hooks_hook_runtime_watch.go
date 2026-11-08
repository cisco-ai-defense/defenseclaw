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
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// The files in the hook runtime folder that the hook guardian watches for a
// hold: exactly the ones a hook start opens to read. Nothing else in the
// folder is watched, and in particular not the lock files the Setup program
// and the command line take with no sharing for a whole transaction
// (.defenseclaw-enrollment.lock, .defenseclaw-managed-runtime-selector.lock),
// not the .defenseclaw-policy-*.tmp files their writers create beside the
// files, and not the relax records: DefenseClaw's own writers hold those, the
// hook never opens them, and ending such a hold would break the
// writer's lock or write a tamper row for DefenseClaw's own run.
// A name is added here only with the chain of code that makes a hook start
// read it (windowsHookRuntimeFiles, checked by a test against the source).

// windowsHookRuntimeConnectors are the per-user connector folders of the hook
// runtime folder whose enrollment and selector a hook start reads: the cases
// of ResolveWindowsManagedHookRuntime that resolve per user. Amp is not among
// them: its hook does not resolve a runtime there.
var windowsHookRuntimeConnectors = []string{"antigravity", "copilot", "devin", "hermes", "kiro", "opencode"}

// windowsHookReadHop is one step of the path from the hook binary to the open
// of a file: the declaration Decl in File (relative to internal/) mentions
// Uses, which is the next step's declaration or, at the last step, the
// constant that holds the file name.
type windowsHookReadHop struct {
	File string
	Decl string
	Uses string
}

// windowsHookRuntimeFile is one watched name: directly in the hook runtime
// folder, or, with PerConnector, in each connector folder of
// windowsHookRuntimeConnectors. NameFile and NameConst say where the name is
// declared; Path is the chain of code from the hook command to that constant.
type windowsHookRuntimeFile struct {
	Name         string
	PerConnector bool
	NameFile     string
	NameConst    string
	Path         []windowsHookReadHop
}

// windowsHookManagedRuntimeHops are the first steps of every runtime read of
// a managed hook start: the hook command prepares the managed runtime, which
// calls the resolver.
var windowsHookManagedRuntimeHops = []windowsHookReadHop{
	{"cli/hook.go", "newHookCmd", "prepareEnterpriseManagedHookRuntime"},
	{"cli/hook_trusted_state_windows.go", "prepareEnterpriseManagedHookRuntime", "enterpriseManagedRuntimeResolver"},
	{"cli/hook_trusted_state_windows.go", "enterpriseManagedRuntimeResolver", "ResolveWindowsManagedHookRuntime"},
}

// windowsHookRuntimeFiles is the allow-list. The paths are written relative to
// the hook runtime folder (C:\ProgramData\Cisco\DefenseClaw-HookRuntime).
var windowsHookRuntimeFiles = []windowsHookRuntimeFile{
	{
		// The public machine policy summary: the foreign-hook guard of every
		// managed hook call loads it and fails the call closed when it cannot.
		Name:      "machine-policy.json",
		NameFile:  "enterprisepolicy/paths.go",
		NameConst: "PublicPolicyFileName",
		Path: []windowsHookReadHop{
			{"cli/hook_foreign_guard_host.go", "applyHostEnterpriseForeignHookGuard", "applyEnterpriseForeignHookGuard"},
			{"cli/hook_foreign_guard.go", "applyEnterpriseForeignHookGuard", "hookForeignGuardSummaryPath"},
			{"cli/hook_foreign_guard.go", "hookForeignGuardSummaryPath", "PublicPolicyPathFor"},
			{"enterprisepolicy/standalone.go", "PublicPolicyPathFor", "PublicPolicyFileName"},
		},
	},
	{
		// The hot-config closure marker: the standalone hook reads it before it
		// accepts a generation's outage-open mode.
		Name:      ".defenseclaw-hot-config-undo-closed",
		NameFile:  "enterprisehooks/windows_standalone_hook_closure_windows.go",
		NameConst: "windowsStandaloneHookClosureFile",
		Path: []windowsHookReadHop{
			{"cli/hook.go", "newHookCmd", "prepareEnterpriseManagedHookRuntime"},
			{"cli/hook_trusted_state_windows.go", "prepareEnterpriseManagedHookRuntime", "windowsStandaloneHooksHeldClosed"},
			{"cli/hook_trusted_state_windows.go", "windowsStandaloneHooksHeldClosed", "WindowsStandaloneHooksHeldClosed"},
			{"enterprisehooks/windows_standalone_hook_closure_windows.go", "WindowsStandaloneHooksHeldClosed", "windowsStandaloneHookClosureHeldClosed"},
			{"enterprisehooks/windows_standalone_hook_closure_windows.go", "windowsStandaloneHookClosureHeldClosed", "windowsStandaloneHookClosurePath"},
			{"enterprisehooks/windows_standalone_hook_closure_windows.go", "windowsStandaloneHookClosurePath", "windowsStandaloneHookClosureFile"},
		},
	},
	{
		// <connector>\enrollment.json: the machine enrollment that names the
		// calling SID; no other file is trusted before it.
		Name:         "enrollment.json",
		PerConnector: true,
		NameFile:     "enterprisehooks/peruser_managed_windows.go",
		NameConst:    "windowsPerUserManagedEnrollmentFile",
		Path: append(append([]windowsHookReadHop{}, windowsHookManagedRuntimeHops...),
			windowsHookReadHop{"enterprisehooks/managed_runtime_windows.go", "ResolveWindowsManagedHookRuntime", "resolveWindowsPerUserManagedHookRuntime"},
			windowsHookReadHop{"enterprisehooks/peruser_managed_windows.go", "resolveWindowsPerUserManagedHookRuntime", "readWindowsPerUserManagedEnrollment"},
			windowsHookReadHop{"enterprisehooks/peruser_managed_windows.go", "readWindowsPerUserManagedEnrollment", "windowsPerUserManagedEnrollmentFile"}),
	},
	{
		// <connector>\.defenseclaw-managed-runtime-selector.state: the selector
		// that pins the account's runtime generation.
		Name:         ".defenseclaw-managed-runtime-selector.state",
		PerConnector: true,
		NameFile:     "enterprisehooks/managed_runtime_generation_windows.go",
		NameConst:    "windowsManagedRuntimeSelectorFile",
		Path: append(append([]windowsHookReadHop{}, windowsHookManagedRuntimeHops...),
			windowsHookReadHop{"enterprisehooks/managed_runtime_windows.go", "ResolveWindowsManagedHookRuntime", "resolveWindowsPerUserManagedHookRuntime"},
			windowsHookReadHop{"enterprisehooks/peruser_managed_windows.go", "resolveWindowsPerUserManagedHookRuntime", "windowsManagedRuntimeGenerationResolve"},
			windowsHookReadHop{"enterprisehooks/managed_runtime_generation_integration_windows.go", "windowsManagedRuntimeGenerationResolve", "ResolveWindowsManagedRuntimeGeneration"},
			windowsHookReadHop{"enterprisehooks/managed_runtime_generation.go", "ResolveWindowsManagedRuntimeGeneration", "resolveWindowsManagedRuntimeGenerationPlatform"},
			windowsHookReadHop{"enterprisehooks/managed_runtime_generation_windows.go", "resolveWindowsManagedRuntimeGenerationPlatform", "readWindowsManagedRuntimeSelector"},
			windowsHookReadHop{"enterprisehooks/managed_runtime_generation_windows.go", "readWindowsManagedRuntimeSelector", "windowsManagedRuntimeSelectorPath"},
			windowsHookReadHop{"enterprisehooks/managed_runtime_generation_windows.go", "windowsManagedRuntimeSelectorPath", "windowsManagedRuntimeSelectorPathResolver"},
			windowsHookReadHop{"enterprisehooks/managed_runtime_generation_windows.go", "windowsManagedRuntimeSelectorPathResolver", "defaultWindowsManagedRuntimeSelectorPath"},
			windowsHookReadHop{"enterprisehooks/managed_runtime_generation_windows.go", "defaultWindowsManagedRuntimeSelectorPath", "windowsManagedRuntimeSelectorFile"}),
	},
}

// windowsHookRuntimeWatchList lists the allow-listed files that exist in the
// hook runtime folder dir, as regular files that are not links, in sorted
// order. It does not walk the folder: a name that is not in
// windowsHookRuntimeFiles is never listed, whatever the folder holds. At most
// 2 + 2*len(windowsHookRuntimeConnectors) files can be listed.
func windowsHookRuntimeWatchList(dir string) []string {
	if strings.TrimSpace(dir) == "" {
		return nil
	}
	base := filepath.Clean(dir)
	var files []string
	for _, entry := range windowsHookRuntimeFiles {
		folders := []string{base}
		if entry.PerConnector {
			folders = folders[:0]
			for _, name := range windowsHookRuntimeConnectors {
				folder := filepath.Join(base, name)
				if info, err := os.Lstat(folder); err == nil && info.IsDir() && info.Mode()&os.ModeSymlink == 0 {
					folders = append(folders, folder)
				}
			}
		}
		for _, folder := range folders {
			path := filepath.Join(folder, entry.Name)
			if info, err := os.Lstat(path); err == nil && info.Mode().IsRegular() {
				files = append(files, path)
			}
		}
	}
	sort.Strings(files)
	return files
}
