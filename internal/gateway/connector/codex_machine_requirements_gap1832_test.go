// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import "testing"

// GAP-1832: the unlocked-requirements ownership test is broad: only plainly
// administrator-authored text reports false.
func TestGAP1832RequirementsMayHoldDefenseClaw(t *testing.T) {
	opts := standaloneWindowsCodexMachineOptions()
	rendered, changed, err := reconcileWindowsCodexRequirements([]byte("# IT\n"), opts, false)
	if err != nil || !changed {
		t.Fatalf("render: changed=%v err=%v", changed, err)
	}
	for name, tc := range map[string]struct {
		raw  string
		want bool
	}{
		"comments":        {"# IT policy\n# keep\n", false},
		"empty":           {"", false},
		"isolation keys":  {"allow_managed_hooks_only = true\n[features]\nhooks = true\n", false},
		"admin hook":      {"[[hooks.PreToolUse]]\nmatcher = \"Bash\"\n[[hooks.PreToolUse.hooks]]\ntype = \"command\"\ncommand = 'C:\\IT\\audit.exe'\n", false},
		"rendered":        {string(rendered), true},
		"managed dir":     {"[hooks]\nwindows_managed_dir = 'C:\\x'\n", true},
		"hooks state":     {"[hooks]\nstate = 'x'\n", true},
		"image name":      {"[x]\ny = 'C:\\a\\DEFENSECLAW-HOOK.EXE'\n", true},
		"product key":     {"[defenseclaw]\nx = 1\n", true},
		"encoded command": {"[x]\ny = 'powershell -EncodedCommand " + powershellEncodedCommand("defenseclaw status") + "'\n", true},
		"unparseable":     {"[hooks\n", true},
	} {
		if got := windowsCodexRequirementsMayHoldDefenseClaw([]byte(tc.raw), opts.HookBinary); got != tc.want {
			t.Errorf("%s: got %v, want %v", name, got, tc.want)
		}
	}
}
