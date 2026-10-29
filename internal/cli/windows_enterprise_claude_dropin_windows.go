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
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// DefenseClaw's Claude Code drop-in (managed-settings.d\90-defenseclaw.json)
// is its own file; the guardian puts it back when it is changed. With the
// guardian stopped, verify said only not_ready and never named a hook entry
// an administrator removed, and the repair verify advised refused the file as
// an administrator edit (lifecycle_error, 1603), so the documented recovery
// could not finish (GAP-2336). Status and verify now report the drift, and an
// elevated repair puts the drop-in back before anything reads it.

// Seams for tests.
var (
	windowsEnterpriseClaudeDropInDrift   = enterprisehooks.WindowsClaudeManagedPolicyDrift
	windowsEnterpriseClaudeDropInRestore = enterprisehooks.RestoreWindowsClaudeManagedPolicyDrift
)

func windowsEnterpriseClaudeDropInDriftMessage(path string, removed bool) string {
	what := "was changed outside DefenseClaw (it no longer matches the copy DefenseClaw wrote)"
	if removed {
		what = "was removed outside DefenseClaw"
	}
	return "DefenseClaw's Claude Code machine policy drop-in " + path + " " + what +
		", so Claude Code may run without some DefenseClaw hooks. A running hook guardian puts it back at its next pass." +
		" Fix: run " + windowsEnterpriseAdminCommand("repair") + " (or reconcile); keep your own settings in another managed-settings.d file"
}

// applyWindowsEnterpriseClaudeDropInDrift fails status and verify while the
// drop-in differs from DefenseClaw's record.
func applyWindowsEnterpriseClaudeDropInDrift(result *enterprisestatus.Result) {
	if path, removed := windowsEnterpriseClaudeDropInDrift(); path != "" {
		result.AddError("machine_policy_incomplete", windowsEnterpriseClaudeDropInDriftMessage(path, removed))
	}
}

// repairWindowsEnterpriseClaudeDropIn puts the drop-in back from its
// ownership record before a repair, and says so.
func repairWindowsEnterpriseClaudeDropIn() string {
	path, _ := windowsEnterpriseClaudeDropInDrift()
	if path == "" {
		return ""
	}
	if restored, err := windowsEnterpriseClaudeDropInRestore(); err != nil || !restored {
		return ""
	}
	return "put back DefenseClaw's Claude Code machine policy drop-in " + path + ", which was changed or removed outside DefenseClaw"
}
