// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import "testing"

// GAP-0890 r2: privileges_required is the code of the error, so its message
// does not repeat it ("privileges_required: privileges_required: ...").
func TestWindowsEnterpriseTrimHeldCodePrefixDropsTheRepeatedPrivilegesRequiredCode(t *testing.T) {
	const detail = "Access to the path 'C:\\ProgramData\\Cisco\\DefenseClaw\\x' is denied. Run the same uninstall as SYSTEM"
	message := "privileges_required: " + detail
	if got := windowsEnterpriseMessageCode(message, "lifecycle_error"); got != "privileges_required" {
		t.Fatalf("code = %q, want privileges_required", got)
	}
	if got := windowsEnterpriseTrimHeldCodePrefix("privileges_required", message); got != detail {
		t.Fatalf("message = %q, want %q", got, detail)
	}
	for _, code := range []string{"uninstall_in_use", "lifecycle_error"} {
		if got := windowsEnterpriseTrimHeldCodePrefix(code, code+": same"); got != code+": same" {
			t.Fatalf("%s message was changed: %q", code, got)
		}
	}
}

// GAP-0994 merge: the codes the module puts at the start of a message are all
// trimmed from it, the Codex holds, privileges_required, untrusted_record
// (GAP-0602) and guardian_state_held (GAP-0967); another code keeps its text.
func TestWindowsEnterpriseTrimHeldCodePrefixDropsEveryCodeTheModulePrefixes(t *testing.T) {
	for _, code := range []string{
		"codex_state_held", "codex_requirements_held", "privileges_required", "untrusted_record", "guardian_state_held",
	} {
		const detail = "the detail of the refusal"
		if got := windowsEnterpriseTrimHeldCodePrefix(code, code+": "+detail); got != detail {
			t.Fatalf("%s: message = %q, want %q", code, got, detail)
		}
	}
	if got := windowsEnterpriseTrimHeldCodePrefix("codex_state_unsettled", "codex_state_unsettled: same"); got != "codex_state_unsettled: same" {
		t.Fatalf("a code that is not trimmed was changed: %q", got)
	}
}
