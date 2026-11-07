// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import "testing"

// The Windows hook adapters are the hook script names with .ps1 for .sh.
// A purge that runs on a Windows account must own every one of them, or the
// adapter stays behind (a read-only copy included).
func TestManagedUserStateFileOwnsTheWindowsAdapterOfEveryHookScript(t *testing.T) {
	for _, scripts := range connectorHookScripts {
		for _, script := range scripts {
			sh := "hooks/" + script
			ps1 := sh[:len(sh)-len(".sh")] + ".ps1"
			if !ManagedUserStateFile(sh) {
				t.Errorf("%s is a hook script and is not owned", sh)
			}
			if !ManagedUserStateFile(ps1) {
				t.Errorf("%s is the Windows adapter of %s and is not owned", ps1, sh)
			}
		}
	}
	for _, rel := range []string{"hooks/devin-hook.ps1", "hooks/codex-hook.ps1", "hooks/claude-code-hook.ps1"} {
		if !ManagedUserStateFile(rel) {
			t.Errorf("%s is not owned", rel)
		}
	}
}

// Benign twin: a PowerShell file that is no hook adapter is the account own.
func TestManagedUserStateFileKeepsPowerShellFilesThatAreNotHookAdapters(t *testing.T) {
	for _, rel := range []string{
		"hooks/personal.ps1", "hooks/unknown-hook.ps1", "hooks/devin-hook.ps1.bak",
		"hooks/amp-plugin.ps1", "hooks/sub/devin-hook.ps1", "devin-hook.ps1", "logs/devin-hook.ps1",
	} {
		if ManagedUserStateFile(rel) {
			t.Errorf("%s is owned but is not a DefenseClaw hook adapter", rel)
		}
	}
}
