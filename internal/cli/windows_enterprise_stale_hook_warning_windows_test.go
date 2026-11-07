// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// GAP-0761: a vendor policy file the uninstall kept because another account
// can change it is named once in the result, with what the agent does with a
// hook whose program is gone and the way to clean it, and not as a file to
// "leave in place".
func TestUninstallResultNamesAKeptVendorFileWithAStaleHook(t *testing.T) {
	file := `C:\ProgramData\opencode\opencode.json`
	entries, err := json.Marshal([]string{
		file + ": " + enterprisepolicy.StaleHookKept + file + ": untrusted Windows principal S-1-5-32-545 has write-like access mask 0x1301bf",
		file + ": " + enterprisepolicy.StaleHookKept + "a second report of the same file",
		`C:\ProgramData\Cursor\hooks.json: kept: pending Cursor registration`,
	})
	if err != nil {
		t.Fatal(err)
	}
	result := &enterprisestatus.Result{Action: "uninstall"}
	addWindowsEnterpriseMachineStateWarning(result, &windowsEnterpriseInstallerReport{MachineStateRemaining: entries})
	var stale, kept int
	for _, warning := range result.Warnings {
		switch warning.Code {
		case "vendor_policy_hook_left":
			stale++
			for _, want := range []string{"1 vendor policy file(s)", file, "byte for byte", "defenseclaw-hook.exe", "blocked until they are gone", "Fix command"} {
				if !strings.Contains(warning.Message, want) {
					t.Fatalf("warning %q lacks %q", warning.Message, want)
				}
			}
			if strings.Contains(warning.Message, "leave them in place") {
				t.Fatalf("a stale hook is not a file to leave in place: %q", warning.Message)
			}
		case "machine_state_kept":
			kept++
			if strings.Contains(warning.Message, "opencode.json") {
				t.Fatalf("the stale-hook file is reported as kept on purpose: %q", warning.Message)
			}
		}
	}
	if stale != 1 || kept != 1 {
		t.Fatalf("warnings = %+v; want one stale-hook warning and one kept-on-purpose warning", result.Warnings)
	}
}
