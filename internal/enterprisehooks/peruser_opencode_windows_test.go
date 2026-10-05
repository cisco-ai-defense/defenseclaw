// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"path/filepath"
	"strings"
	"testing"
)

// Once OpenCode's machine policy is in force the managed plugin runs the
// hook binary for every user, so OpenCode rows install only the per-user
// runtime (like Copilot) and exempt users keep their rows. Without it they
// stay on the per-user plugin route. Removal always takes the per-user path,
// which also removes a plugin left from that route.
func TestWindowsOpenCodeRowsFollowItsMachinePolicy(t *testing.T) {
	previous := windowsOpenCodeMachinePolicyInForce
	t.Cleanup(func() { windowsOpenCodeMachinePolicyInForce = previous })
	for _, inForce := range []bool{false, true} {
		windowsOpenCodeMachinePolicyInForce = func() bool { return inForce }
		for _, name := range []string{"opencode", "OpenCode"} {
			if got := windowsStandaloneRuntimeOnlyInstall(name); got != inForce {
				t.Fatalf("in force=%t: %s runtime-only install = %t", inForce, name, got)
			}
			if got := windowsStandaloneMachinePolicyConnector(name); got != inForce {
				t.Fatalf("in force=%t: %s machine policy connector = %t", inForce, name, got)
			}
		}
		if !windowsStandaloneRuntimeOnlyInstall("copilot") || !windowsStandaloneMachinePolicyConnector("copilot") {
			t.Fatal("Copilot is always a runtime-only machine policy connector")
		}
		for _, name := range []string{"amp", "devin", "hermes", "antigravity"} {
			if windowsStandaloneRuntimeOnlyInstall(name) || windowsStandaloneMachinePolicyConnector(name) {
				t.Fatalf("%s has no machine policy route", name)
			}
		}
		if windowsStandaloneRuntimeOnlyConnector("opencode") {
			t.Fatal("OpenCode removal must stay on the per-user path")
		}
	}
}

// The machine policy check comes from the CLI (enterprisepolicy imports
// this package). OpenCode leaves the per-user route only in the standalone
// process and only while that check reports the policy in force; its
// runtime-only rows bind to the managed config the check names.
func TestWindowsOpenCodeMachinePolicyCheck(t *testing.T) {
	previousProcess := windowsEnterpriseStandaloneProcess
	t.Cleanup(func() {
		windowsEnterpriseStandaloneProcess = previousProcess
		SetWindowsOpenCodeMachinePolicy(nil)
	})
	const config = `C:\ProgramData\opencode\opencode.json`
	windowsEnterpriseStandaloneProcess = func() bool { return true }
	SetWindowsOpenCodeMachinePolicy(nil)
	if windowsOpenCodeMachinePolicyInForce() {
		t.Fatal("without a check OpenCode stays on the per-user route")
	}
	if _, err := windowsRuntimeOnlyPolicyPath("opencode"); err == nil {
		t.Fatal("without a check there is no OpenCode policy path")
	}
	inForce := true
	SetWindowsOpenCodeMachinePolicy(func() (string, bool) { return config, inForce })
	if !windowsOpenCodeMachinePolicyInForce() {
		t.Fatal("the check reports the policy in force")
	}
	if path, err := windowsRuntimeOnlyPolicyPath("opencode"); err != nil || path != config {
		t.Fatalf("OpenCode runtime-only policy = %q, %v; want %s", path, err, config)
	}
	inForce = false
	if windowsOpenCodeMachinePolicyInForce() {
		t.Fatal("a policy no longer in force must return OpenCode to the per-user route")
	}
	inForce = true
	windowsEnterpriseStandaloneProcess = func() bool { return false }
	if windowsOpenCodeMachinePolicyInForce() {
		t.Fatal("a non-standalone process never routes OpenCode rows to runtime-only")
	}
	SetWindowsOpenCodeMachinePolicy(func() (string, bool) { return `opencode.json`, true })
	if _, err := windowsRuntimeOnlyPolicyPath("opencode"); err == nil {
		t.Fatal("a relative OpenCode policy path was accepted")
	}
}

// The hook binary resolves OpenCode's per-user managed runtime like the other
// hook-binary per-user connectors; Amp stays unsupported.
func TestWindowsManagedHookRuntimeResolvesOpenCode(t *testing.T) {
	executable := filepath.Join(t.TempDir(), "defenseclaw-hook.exe")
	if _, err := ResolveWindowsManagedHookRuntime(executable, "opencode"); err != nil &&
		strings.Contains(err.Error(), "unsupported Windows managed connector") {
		t.Fatalf("OpenCode is not resolved: %v", err)
	}
	if _, err := ResolveWindowsManagedHookRuntime(executable, "amp"); err == nil ||
		!strings.Contains(err.Error(), "unsupported Windows managed connector") {
		t.Fatalf("Amp must stay unsupported: %v", err)
	}
}
