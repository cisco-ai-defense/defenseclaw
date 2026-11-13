// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

const (
	hookImageTestBin        = `C:\Program Files\DefenseClaw\bin`
	hookImageTestTransition = hookImageTestBin + `\defenseclaw-hook.exe`
	hookImageTestLaunch     = hookImageTestBin + `\hooks\0123456789abcdef\defenseclaw-hook.exe`
	hookImageTestOlder      = hookImageTestBin + `\hooks\aaaaaaaaaaaaaaaa\defenseclaw-hook.exe`
)

// hookImageCodexOptions is the standalone layout of one hook image: the
// managed directory is the image's own folder (GAP-0751).
func hookImageCodexOptions(hook string) WindowsCodexMachineRequirementsOptions {
	opts := standaloneWindowsCodexMachineOptions()
	opts.HookBinary = hook
	opts.ManagedDir = hook[:strings.LastIndex(hook, `\`)]
	return opts
}

func hookImageCodexGroups(t *testing.T, raw []byte, event string) []interface{} {
	t.Helper()
	cfg, err := parseWindowsCodexRequirements(raw)
	if err != nil {
		t.Fatal(err)
	}
	hooks, _ := cfg["hooks"].(map[string]interface{})
	groups, _ := hooks[event].([]interface{})
	return groups
}

// The groups an earlier release of this install wrote for the transition
// image, or for an earlier launch folder, are DefenseClaw's own once the
// current hook is a launch image of the same bin; another install's are not.
func TestWindowsCodexOwnedHookGroupAcceptsAnEarlierImageOfTheSameBin(t *testing.T) {
	current := hookImageCodexOptions(hookImageTestLaunch)
	for name, tc := range map[string]struct {
		hook  string
		owned bool
	}{
		"transition image (1.0.9 layout)": {hookImageTestTransition, true},
		"earlier launch folder":           {hookImageTestOlder, true},
		"current launch image":            {hookImageTestLaunch, true},
		"another install root":            {`C:\Program Files\Other\bin\hooks\0123456789abcdef\defenseclaw-hook.exe`, false},
		"a copy outside bin":              {`C:\Tools\defenseclaw-hook.exe`, false},
	} {
		t.Run(name, func(t *testing.T) {
			prior, _, err := reconcileWindowsCodexRequirements(nil, hookImageCodexOptions(tc.hook), true)
			if err != nil {
				t.Fatal(err)
			}
			groups := hookImageCodexGroups(t, prior, "PreToolUse")
			if len(groups) == 0 {
				t.Fatal("prior requirements have no PreToolUse group")
			}
			for _, group := range groups {
				if got := windowsCodexOwnedHookGroup(group, "PreToolUse", current.HookBinary); got != tc.owned {
					t.Fatalf("windowsCodexOwnedHookGroup(%s) = %v, want %v", tc.hook, got, tc.owned)
				}
			}
		})
	}
}

// The upgrade that moves the launch image replaces this install's groups and
// windows_managed_dir: every event runs the current image once, never both.
func TestReconcileWindowsCodexRequirementsMovesToTheLaunchImage(t *testing.T) {
	current := hookImageCodexOptions(hookImageTestLaunch)
	for _, prior := range []string{hookImageTestTransition, hookImageTestOlder} {
		t.Run(prior, func(t *testing.T) {
			before, _, err := reconcileWindowsCodexRequirements(nil, hookImageCodexOptions(prior), true)
			if err != nil {
				t.Fatal(err)
			}
			after, _, err := reconcileWindowsCodexRequirements(before, current, true)
			if err != nil {
				t.Fatalf("reconcile over the earlier image's requirements: %v", err)
			}
			if err := verifyWindowsCodexRequirementsBytes(after, current); err != nil {
				t.Fatalf("reconciled requirements do not verify for the launch image: %v", err)
			}
			for _, group := range windowsCodexMachineProfileGroups(current) {
				groups := hookImageCodexGroups(t, after, group.eventType)
				if len(groups) != 1 {
					t.Fatalf("%s has %d groups after the move, want 1", group.eventType, len(groups))
				}
			}
			if strings.Contains(string(after), strings.ReplaceAll(prior, `\`, `\\`)) {
				t.Fatalf("the earlier image is still named:\n%s", after)
			}
		})
	}
}

// Another install's managed directory is still the administrator's: the
// launch-folder family covers one bin only.
func TestReconcileWindowsCodexRequirementsRefusesAnotherInstallsDirectory(t *testing.T) {
	other := hookImageCodexOptions(`C:\Program Files\Other\bin\defenseclaw-hook.exe`)
	before, _, err := reconcileWindowsCodexRequirements(nil, other, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := reconcileWindowsCodexRequirements(before, hookImageCodexOptions(hookImageTestLaunch), true); err == nil ||
		!strings.Contains(err.Error(), "conflicts with protected managed directory") {
		t.Fatalf("reconcile over another install's directory = %v, want the conflict refusal", err)
	}
}

func TestWindowsCodexOwnManagedDirIsOneBinsFamily(t *testing.T) {
	current := hookImageCodexOptions(hookImageTestLaunch)
	for dir, want := range map[string]bool{
		hookImageTestBin: true,
		hookImageTestBin + `\hooks\aaaaaaaaaaaaaaaa`: true,
		hookImageTestBin + `\hooks\0123456789abcdef`: true,
		hookImageTestBin + `\hooks`:                  false,
		`C:\Program Files\Other\bin`:                 false,
	} {
		if got := windowsCodexOwnManagedDir(dir, current); got != want {
			t.Errorf("windowsCodexOwnManagedDir(%q) = %v, want %v", dir, got, want)
		}
	}
	secureClient := current
	secureClient.SecureClient = true
	if windowsCodexOwnManagedDir(hookImageTestBin, secureClient) {
		t.Fatal("Secure Client widened its exact managed-directory comparison")
	}
}

// An administrator hook that names any image of this install keeps the
// binary removal unsafe, as one naming the 1.0.9 bin did.
func TestWindowsCodexOwnedPathReferenceCountCoversTheInstallBin(t *testing.T) {
	current := hookImageCodexOptions(hookImageTestLaunch)
	raw := []byte("[hooks]\n[[hooks.Stop]]\n[[hooks.Stop.hooks]]\ntype = \"command\"\ncommand = '" + hookImageTestTransition + " --audit'\n")
	count, err := windowsCodexOwnedPathReferenceCount(raw, current)
	if err != nil || count == 0 {
		t.Fatalf("reference count = %d, %v; want the transition image counted", count, err)
	}
}

func TestWindowsCodexStandaloneHookContractForEveryImageOfTheBin(t *testing.T) {
	layout := managed.StandaloneLayout{GOOS: "windows", BinDir: hookImageTestBin}
	for hook, want := range map[string]bool{
		hookImageTestTransition: true,
		hookImageTestLaunch:     true,
		hookImageTestOlder:      true,
		hookImageTestBin + `\hooks\aaaaaaaaaaaaaaaa\defenseclaw-hook-guard.exe`:  false,
		`C:\Program Files\Other\bin\hooks\0123456789abcdef\defenseclaw-hook.exe`: false,
	} {
		if got := windowsCodexStandaloneHookContractFor(layout, hook) != ""; got != want {
			t.Errorf("windowsCodexStandaloneHookContractFor(%q) bound = %v, want %v", hook, got, want)
		}
	}
}
