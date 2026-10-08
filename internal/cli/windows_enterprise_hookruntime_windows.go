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
	"os"
	"sort"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// Every enrolled user's hook reads the machine policy summary in
// C:\ProgramData\Cisco\DefenseClaw-HookRuntime and refuses it when a
// standard user can write the folder or when Users cannot read it. Both
// drifts failed every user closed with enterprise_machine_policy_summary_
// untrusted while status and verify said ok, and repair did not put the
// Users read entry back (GAP-0927, GAP-0929).

// Seams for tests.
var (
	windowsEnterpriseHookRuntimeDir = func() (string, error) {
		layout, err := managed.StandaloneWindowsLayout()
		return layout.HookRuntimeDir, err
	}
	windowsEnterpriseInspectPublicDir = enterprisepolicy.InspectWindowsPublicDir
	windowsEnterpriseRepairPublicDir  = enterprisepolicy.RepairWindowsPublicDir
)

// windowsEnterpriseHookRuntimeDrift returns the hook runtime folder and how
// its access differs from DefenseClaw's, or "" when it does not (or the
// folder is not there yet).
func windowsEnterpriseHookRuntimeDrift() (string, string) {
	dir, err := windowsEnterpriseHookRuntimeDir()
	if err != nil || strings.TrimSpace(dir) == "" {
		return "", ""
	}
	if _, err := os.Lstat(dir); err != nil {
		return dir, ""
	}
	drift, err := windowsEnterpriseInspectPublicDir(dir)
	if err != nil {
		return dir, dir + ": DefenseClaw could not read its permissions (" + err.Error() + "), so every user's hook may refuse the machine policy summary in it"
	}
	if !drift.Drifted() {
		return dir, ""
	}
	return dir, windowsEnterpriseHookRuntimeDriftMessage(dir, drift)
}

func windowsEnterpriseHookRuntimeDriftMessage(dir string, drift enterprisepolicy.WindowsPublicDirDrift) string {
	var parts, removals []string
	if drift.Owner != "" {
		parts = append(parts, "it is owned by "+windowsPrincipalLabel(drift.Owner)+", not Administrators")
	}
	sids := make([]string, 0, len(drift.Extra))
	for sid := range drift.Extra {
		sids = append(sids, sid)
	}
	sort.Strings(sids)
	for _, sid := range sids {
		parts = append(parts, windowsPrincipalLabel(sid)+" holds "+windowsAccessMaskWords(drift.Extra[sid])+
			", write access only SYSTEM and Administrators may hold there")
		if sid != "S-1-5-32-545" {
			removals = append(removals, "*"+sid)
		}
	}
	if drift.UsersReadMissing {
		parts = append(parts, "the "+windowsPrincipalLabel("S-1-5-32-545")+" read and execute entry is missing, so standard users cannot read the machine policy summary")
	}
	fix := `icacls "` + dir + `" /setowner *S-1-5-32-544 and icacls "` + dir + `" /inheritance:r /grant:r *S-1-5-18:(OI)(CI)F *S-1-5-32-544:(OI)(CI)F *S-1-5-32-545:(OI)(CI)RX`
	if len(removals) != 0 {
		fix += " /remove:g " + strings.Join(removals, " ")
	}
	return dir + ": " + strings.Join(parts, "; ") +
		". Every enrolled user's agent hook refuses the machine policy summary in it (enterprise_machine_policy_summary_untrusted) and fails closed." +
		" Fix: run " + windowsEnterpriseAdminCommand("repair") + ", which writes the folder's permissions back, or " + fix
}

// applyWindowsEnterpriseHookRuntimeAccess fails status and verify on a
// drifted hook runtime folder.
func applyWindowsEnterpriseHookRuntimeAccess(result *enterprisestatus.Result) {
	if _, problem := windowsEnterpriseHookRuntimeDrift(); problem != "" {
		result.AddError("machine_policy_summary_untrusted", problem)
	}
}

// repairWindowsEnterpriseHookRuntimeAccess writes the hook runtime folder's
// owner and access list back before a repair, and says so.
func repairWindowsEnterpriseHookRuntimeAccess() string {
	dir, problem := windowsEnterpriseHookRuntimeDrift()
	if problem == "" {
		return ""
	}
	if err := windowsEnterpriseRepairPublicDir(dir); err != nil {
		return ""
	}
	return "re-applied the permissions of " + dir + " (SYSTEM and Administrators full control, BUILTIN\\Users read and execute)"
}
