// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import "testing"

// GAP-1801 (a), RV-W111D2: the Setup preflight admitted any HKLM Claude Code
// value with a hooks table (deferring it to enrolment, which has the hook
// executable), so a non-merging value whose hooks name no DefenseClaw hook
// passed the preflight and was refused only at enrolment, after Setup had
// changed the machine. A table that names no DefenseClaw hook cannot be
// DefenseClaw's matrix: the preflight refuses it at once, naming the fix. A
// table that names a DefenseClaw hook still defers to enrolment.
func TestGAP1801PreflightRefusesAHooksTableThatNamesNoDefenseClawHook(t *testing.T) {
	label := `HKLM\SOFTWARE\Policies\ClaudeCode\Settings`
	foreign := `{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"C:\\Tools\\audit-hook.exe"}]}]}}`
	if err := ClaudeCodeOSAdminPolicyPreflight(foreign, label); err == nil {
		t.Fatal("the preflight admitted a non-merging HKLM hooks table that names no DefenseClaw hook")
	}
	ours := `{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"\"C:\\Program Files\\Cisco\\DefenseClaw\\bin\\defenseclaw-hook.exe\" claudecode"}]}]}}`
	if err := ClaudeCodeOSAdminPolicyPreflight(ours, label); err != nil {
		t.Fatalf("a hooks table naming the DefenseClaw hook must defer to enrolment: %v", err)
	}
	if err := ClaudeCodeOSAdminPolicyPreflight(`{"managedSourcesBehavior":"merge","wslInheritsWindowsSettings":false}`, label); err != nil {
		t.Fatalf("source-control keys only: %v", err)
	}
}
