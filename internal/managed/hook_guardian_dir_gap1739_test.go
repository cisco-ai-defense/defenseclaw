// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"errors"
	"testing"
)

// rel-1-0-10:GAP-1739: without DEFENSECLAW_HOOK_GUARDIAN_AUTH_DIR (an
// administrator shell), the Windows standalone data directory resolves to the
// hook-guardian-state directory its PowerShell lifecycle creates beside it,
// not to a runtime-hook-guardian that does not exist. Any other data
// directory, and a machine with no trusted roots, keeps <data_dir>-hook-guardian.
func TestHookGuardianAuthorizationDirFollowsTheWindowsStandaloneLayout(t *testing.T) {
	layout, err := StandaloneWindowsLayoutForRoots(`C:\Program Files`, `C:\ProgramData`)
	if err != nil {
		t.Fatal(err)
	}
	if layout.GuardianAuthDir != `C:\ProgramData\Cisco\DefenseClaw\hook-guardian-state` {
		t.Fatalf("the layout must name the directory the PowerShell module creates: %q", layout.GuardianAuthDir)
	}
	saved := standaloneWindowsAuthLayout
	t.Cleanup(func() { standaloneWindowsAuthLayout = saved })
	standaloneWindowsAuthLayout = func() (StandaloneLayout, error) { return layout, nil }
	for _, tc := range []struct{ dataDir, want string }{
		{layout.DataDir, layout.GuardianAuthDir},
		{layout.DataDir + `\`, layout.GuardianAuthDir},
		{`c:\programdata\cisco\defenseclaw\RUNTIME`, layout.GuardianAuthDir},
		{`C:\Users\alice\.defenseclaw`, `C:\Users\alice\.defenseclaw-hook-guardian`},
		{`D:\ProgramData\Cisco\DefenseClaw\runtime`, `D:\ProgramData\Cisco\DefenseClaw\runtime-hook-guardian`},
	} {
		if got := hookGuardianAuthorizationDirFor("windows", tc.dataDir); got != tc.want {
			t.Errorf("windows %q: got %q, want %q", tc.dataDir, got, tc.want)
		}
	}
	if got := hookGuardianAuthorizationDirFor("linux", layout.DataDir); got != layout.DataDir+"-hook-guardian" {
		t.Errorf("only goos windows reads the Windows layout: got %q", got)
	}
	standaloneWindowsAuthLayout = func() (StandaloneLayout, error) { return StandaloneLayout{}, errors.New("no registration") }
	if got := hookGuardianAuthorizationDirFor("windows", layout.DataDir); got != layout.DataDir+"-hook-guardian" {
		t.Errorf("without trusted roots the suffix stays: got %q", got)
	}
}
