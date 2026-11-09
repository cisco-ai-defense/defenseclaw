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
