// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import "testing"

// GAP-1034: only Claude Code, Codex and Cursor are judged, an empty SID and a
// process that is not the standalone service claim nothing, and a SID the
// machine policy does not register is the unregistered refusal, not pending.
// The selector half (no entry is pending, an entry is not) is proven natively
// on the machine files by the g1026 r2 cells.
func TestWindowsManagedRuntimePendingForSID(t *testing.T) {
	const sid = "S-1-5-21-1-2-3-1001"
	previousStandalone, previousRegistered := windowsEnterpriseStandaloneProcess, windowsMachinePolicyRegisteredSIDs
	previousExe := windowsEnterpriseHookExecutable
	t.Cleanup(func() {
		windowsEnterpriseStandaloneProcess, windowsMachinePolicyRegisteredSIDs = previousStandalone, previousRegistered
		windowsEnterpriseHookExecutable = previousExe
	})
	windowsEnterpriseStandaloneProcess = func() bool { return true }
	windowsEnterpriseHookExecutable = func() (string, error) { return `C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw-hook.exe`, nil }
	registered := map[string]bool{sid: true}
	windowsMachinePolicyRegisteredSIDs = func(string, string) (map[string]bool, error) { return registered, nil }
	for _, name := range []string{"copilot", "hermes", "opencode", "amp", ""} {
		if WindowsManagedRuntimePendingForSID(name, sid) {
			t.Fatalf("%q is not a machine-hook connector", name)
		}
	}
	if WindowsManagedRuntimePendingForSID("codex", " ") {
		t.Fatal("an empty SID is pending")
	}
	windowsEnterpriseStandaloneProcess = func() bool { return false }
	if WindowsManagedRuntimePendingForSID("codex", sid) {
		t.Fatal("a process that is not the standalone service claimed pending")
	}
	windowsEnterpriseStandaloneProcess = func() bool { return true }
	registered = map[string]bool{"S-1-5-21-1-2-3-1999": true}
	if WindowsManagedRuntimePendingForSID("codex", sid) {
		t.Fatal("a SID the policy does not register is the unregistered refusal, not pending")
	}
}
