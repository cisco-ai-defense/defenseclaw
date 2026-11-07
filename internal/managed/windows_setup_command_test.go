// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package managed

import "testing"

// cowork-1-0-8 GAP-0095: the Setup a hint names runs from the folder that
// holds it, in PowerShell, with every argument quoted by the one renderer.
func TestWindowsSetupCommand(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"/repair", "JSON=1"}, `& '.\DefenseClawSetup-Enterprise-Standalone-x64.exe' /repair JSON=1`},
		{[]string{"/ensure", "CONFIG=<config.yaml>", "JSON=1"}, `& '.\DefenseClawSetup-Enterprise-Standalone-x64.exe' /ensure 'CONFIG=<config.yaml>' JSON=1`},
		{[]string{"/uninstall", "FORCE=1", "PURGE=1", "JSON=1"}, `& '.\DefenseClawSetup-Enterprise-Standalone-x64.exe' /uninstall FORCE=1 PURGE=1 JSON=1`},
		{nil, `& '.\DefenseClawSetup-Enterprise-Standalone-x64.exe'`},
	} {
		if got := WindowsSetupCommand(tc.args...); got != tc.want {
			t.Errorf("WindowsSetupCommand(%q) = %s, want %s", tc.args, got, tc.want)
		}
	}
}
