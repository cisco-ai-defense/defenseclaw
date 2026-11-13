// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import "testing"

const (
	hookImageTestBin        = `C:\Program Files\Cisco\DefenseClaw\bin`
	hookImageTestTransition = hookImageTestBin + `\defenseclaw-hook.exe`
	hookImageTestLaunch     = hookImageTestBin + `\hooks\0123456789abcdef\defenseclaw-hook.exe`
	hookImageTestOlder      = hookImageTestBin + `\hooks\aaaaaaaaaaaaaaaa\defenseclaw-hook.exe`
	hookImageTestOtherRoot  = `C:\Program Files\Cisco\Other\bin\hooks\0123456789abcdef\defenseclaw-hook.exe`
)

func TestSameWindowsManagedHookImage(t *testing.T) {
	for _, tc := range []struct {
		recorded, hook string
		family, exact  bool
	}{
		{hookImageTestLaunch, hookImageTestLaunch, true, true},
		// A session that read its command before the upgrade.
		{hookImageTestLaunch, hookImageTestOlder, true, true},
		{hookImageTestLaunch, hookImageTestTransition, true, true},
		{hookImageTestTransition, hookImageTestLaunch, true, true},
		// The same file spelled in another case: the path comparison, not
		// the exact one.
		{hookImageTestLaunch, `C:\PROGRAM FILES\Cisco\DefenseClaw\bin\hooks\0123456789abcdef\defenseclaw-hook.exe`, true, false},
		{hookImageTestLaunch, hookImageTestOtherRoot, false, false},
		{hookImageTestLaunch, hookImageTestBin + `\hooks\aaaaaaaaaaaaaaaa\defenseclaw-hook-guard.exe`, false, false},
		{hookImageTestLaunch, `C:\Users\Public\defenseclaw-hook.exe`, false, false},
	} {
		if got := sameWindowsManagedHookImage(tc.recorded, tc.hook); got != tc.family {
			t.Errorf("sameWindowsManagedHookImage(%q, %q) = %v, want %v", tc.recorded, tc.hook, got, tc.family)
		}
		if got := sameWindowsManagedHookImageExact(tc.recorded, tc.hook); got != tc.exact {
			t.Errorf("sameWindowsManagedHookImageExact(%q, %q) = %v, want %v", tc.recorded, tc.hook, got, tc.exact)
		}
	}
}

// The selector the guardian published after an upgrade names the new launch
// image; a hook an older session starts from the earlier launch folder or the
// transition image resolves the same selection, another install's does not.
func TestManagedRuntimeSelectorAdmitsAnEarlierImageOfTheSameInstall(t *testing.T) {
	entry := windowsManagedRuntimeSelectorTarget{
		Connector:      "claudecode",
		SID:            "S-1-5-21-1-2-3-1001",
		DataDir:        `C:\Users\someone\.defenseclaw`,
		HookExecutable: hookImageTestLaunch,
	}
	for hook, want := range map[string]bool{
		hookImageTestLaunch:     true,
		hookImageTestOlder:      true,
		hookImageTestTransition: true,
		hookImageTestOtherRoot:  false,
		hookImageTestBin + `\hooks\.staging-0123456789abcdef\defenseclaw-hook.exe`: false,
	} {
		err := validateWindowsManagedRuntimeSelectorTargetAgainstResolve(entry, WindowsManagedRuntimeGenerationResolveOptions{
			Connector:      entry.Connector,
			TargetSID:      entry.SID,
			DataDir:        entry.DataDir,
			HookExecutable: hook,
		})
		if (err == nil) != want {
			t.Errorf("resolve from %q: err = %v, want admitted %v", hook, err, want)
		}
	}
}
