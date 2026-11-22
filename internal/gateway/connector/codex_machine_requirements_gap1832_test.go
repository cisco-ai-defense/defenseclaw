// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"strings"
	"testing"
)

// GAP-1832: the test for DefenseClaw content in a requirements.toml found
// without the machine policy lock is broad under hooks (every command form a
// release renders, any spelling of -EncodedCommand) and leaves the
// administrator's text and policy outside hooks alone.
func TestGAP1832RequirementsMayHoldDefenseClaw(t *testing.T) {
	opts := standaloneWindowsCodexMachineOptions()
	rendered, changed, err := reconcileWindowsCodexRequirements([]byte("# IT\n"), opts, false)
	if err != nil || !changed {
		t.Fatalf("render: changed=%v err=%v", changed, err)
	}
	stopHook := func(command string) string {
		return "[[hooks.Stop]]\n[[hooks.Stop.hooks]]\ntype = \"command\"\ncommand = '" + command + "'\n"
	}
	encoded := powershellEncodedCommand("& 'E:\\x\\DefenseClaw\\run.cmd'")
	for name, tc := range map[string]struct {
		raw  string
		want bool
	}{
		"comments":                 {"# IT policy\n# keep\n", false},
		"empty":                    {"", false},
		"isolation keys":           {"allow_managed_hooks_only = true\n[features]\nhooks = true\n", false},
		"admin hook":               {stopHook(`C:\IT\audit.exe`), false},
		"admin policy names it":    {"[rules]\ndeny = ['defenseclaw uninstall']\n[defenseclaw]\nx = 1\n", false},
		"non-ASCII before -enc":    {stopHook("\u023a-EncodedCommand \u023a\u0130 x"), false},
		"rendered standalone":      {string(rendered), true},
		"managed dir":              {"[hooks]\nwindows_managed_dir = 'C:\\x'\n", true},
		"hooks state":              {"[hooks]\nstate = 'x'\n", true},
		"image name":               {stopHook(`D:\a\DEFENSECLAW-HOOK.EXE --diag`), true},
		"encoded command":          {stopHook("powershell -EncodedCommand " + encoded), true},
		"abbreviated encoded":      {stopHook("pwsh -enc \"" + encoded + "\""), true},
		"non-ASCII then encoded":   {stopHook("\u023a\u0130 -EncodedCommand " + encoded), true},
		"unbound render":           {stopHook(windowsCodexManagedHookCommand(`C:\P\X\bin\defenseclaw-hook.exe`)), true},
		"call-operator render":     {stopHook(legacyCallOperatorWindowsCodexManagedHookCommand(`C:\P\X\bin\defenseclaw-hook.exe`)), true},
		"bridge render":            {stopHook(bridgeWindowsCodexBoundManagedHookCommand(`C:\P\X\bin\defenseclaw-hook.exe`, "Stop", opts.HookContractID)), true},
		"key names it under hooks": {"[hooks.defenseclaw]\nx = 1\n", true},
		"unparseable":              {"[hooks\n", true},
	} {
		if strings.Contains(tc.raw, "\x00") {
			t.Fatalf("%s: bad fixture", name)
		}
		if got := windowsCodexRequirementsMayHoldDefenseClaw([]byte(tc.raw)); got != tc.want {
			t.Errorf("%s: got %v, want %v", name, got, tc.want)
		}
	}
}
