// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// newWindowsCodexMachineGuardFixtureForTest lays out the Codex machine policy
// under temporary roots, with the administrator's own requirements file. It
// returns the options and the hook binary.
func newWindowsCodexMachineGuardFixtureForTest(t *testing.T, requirements []byte) WindowsCodexMachineRequirementsOptions {
	t.Helper()
	if adminErr := requireWindowsCodexMachineAdministrator(); adminErr != nil {
		t.Skipf("reconcile requires an elevated Administrator or LocalSystem token: %v", adminErr)
	}
	programData := t.TempDir()
	stateRoot := t.TempDir()
	policyDir := filepath.Join(programData, "OpenAI", "Codex")
	managedDir := filepath.Join(stateRoot, "bin")
	installDir := filepath.Join(stateRoot, "install")
	for _, dir := range []string{policyDir, managedDir, installDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	hook := filepath.Join(managedDir, "defenseclaw-hook.exe")
	if err := os.WriteFile(hook, []byte("MZ"), 0o755); err != nil {
		t.Fatal(err)
	}
	previousProgramData, previousDir, previousFile, previousVolume := windowsCodexMachineProgramData,
		windowsCodexMachineTrustedDirCheck, windowsCodexMachineTrustedFileCheck, windowsCodexMachineVolumeCheck
	t.Cleanup(func() {
		windowsCodexMachineProgramData, windowsCodexMachineTrustedDirCheck = previousProgramData, previousDir
		windowsCodexMachineTrustedFileCheck, windowsCodexMachineVolumeCheck = previousFile, previousVolume
	})
	windowsCodexMachineProgramData = func() (string, error) { return programData, nil }
	windowsCodexMachineTrustedDirCheck = func(string, string) error { return nil }
	windowsCodexMachineTrustedFileCheck = func(string, string) error { return nil }
	windowsCodexMachineVolumeCheck = func(string) error { return nil }
	opts := WindowsCodexMachineRequirementsOptions{
		RequirementsPath:   filepath.Join(policyDir, "requirements.toml"),
		ManagedStatePath:   filepath.Join(policyDir, windowsCodexManagedStateFile),
		ManagedDir:         managedDir,
		HookBinary:         hook,
		OwnershipPath:      filepath.Join(installDir, "codex-requirements-ownership.json"),
		GatewayAddr:        "127.0.0.1:18000",
		GatewayServiceName: "DefenseClawGateway",
		CodexTargetEnabled: true,
		HookContractID:     WindowsCodexManagedHookContract(hook),
	}
	if requirements != nil {
		if err := os.WriteFile(opts.RequirementsPath, requirements, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return opts
}

// prependWindowsCodexRequirementForTest is an administrator's save: it adds
// one top-level requirement to the file as it is now, in place.
func prependWindowsCodexRequirementForTest(t *testing.T, path, key string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append([]byte(key+" = true\n"), data...), 0o600); err != nil {
		t.Fatal(err)
	}
}

// saveWhileWindowsCodexPublishesForTest runs save each time DefenseClaw
// checks the requirements file while its ownership intent is pending: that is,
// after the reconcile read and merged the file and before it replaced it.
// save reports whether to keep saving.
func saveWhileWindowsCodexPublishesForTest(t *testing.T, opts WindowsCodexMachineRequirementsOptions, save func() bool) {
	t.Helper()
	previous := windowsCodexMachineTrustedFileCheck
	saving := true
	windowsCodexMachineTrustedFileCheck = func(path, label string) error {
		if saving && strings.EqualFold(path, opts.RequirementsPath) {
			if data, err := os.ReadFile(opts.OwnershipPath); err == nil {
				if state, err := parseWindowsCodexMachineOwnership(data); err == nil && state.Pending {
					saving = save()
				}
			}
		}
		return previous(path, label)
	}
	t.Cleanup(func() { windowsCodexMachineTrustedFileCheck = previous })
}

func requireWindowsCodexGuardForTest(t *testing.T, opts WindowsCodexMachineRequirementsOptions, want []WindowsCodexManagedRuntimeTarget, keys ...string) []byte {
	t.Helper()
	registry, err := ResolveWindowsCodexManagedRuntimeRegistry(opts.HookBinary)
	if err != nil || !registry.Active || !slices.Equal(registry.Targets, want) {
		t.Fatalf("guard: %+v (want targets %v) err=%v", registry, want, err)
	}
	if _, err := VerifyWindowsCodexMachineRequirements(opts); err != nil {
		t.Fatalf("the guard does not verify: %v", err)
	}
	requirements, err := os.ReadFile(opts.RequirementsPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range keys {
		if !bytes.Contains(requirements, []byte(key)) {
			t.Fatalf("requirements lost the administrator's %q:\n%s", key, requirements)
		}
	}
	if contains, err := windowsCodexRequirementsContainExactManagedHook(requirements, opts); err != nil || !contains {
		t.Fatalf("requirements lack the exact managed hooks: %v", err)
	}
	return requirements
}

const windowsCodexOperatorRequirementForTest = "allowed_sandbox_modes = [\"read-only\"]\n"

// Configured Codex with no enrolled account publishes the machine guard by
// reconciling requirements.toml. An administrator who adds a requirement after
// the reconcile read the file must keep it: the merge is published only over
// the file it was made from, and otherwise runs again on the newer file. The
// ownership record then names the newer file as the preimage, so uninstall
// gives the administrator back both requirements.
func TestWindowsCodexMachineReconcileKeepsAConcurrentRequirement(t *testing.T) {
	opts := newWindowsCodexMachineGuardFixtureForTest(t, []byte(windowsCodexOperatorRequirementForTest))
	saveWhileWindowsCodexPublishesForTest(t, opts, func() bool {
		prependWindowsCodexRequirementForTest(t, opts.RequirementsPath, "admin_concurrent")
		return false
	})
	if report, err := ReconcileWindowsCodexMachineRequirements(opts); err != nil || !report.OK {
		t.Fatalf("reconcile: %+v err=%v", report, err)
	}
	requireWindowsCodexGuardForTest(t, opts, []WindowsCodexManagedRuntimeTarget{}, "allowed_sandbox_modes", "admin_concurrent")
	data, err := os.ReadFile(opts.OwnershipPath)
	if err != nil {
		t.Fatal(err)
	}
	ownership, err := parseWindowsCodexMachineOwnership(data)
	if err != nil || ownership.Pending || !bytes.Contains(ownership.Preimage, []byte("admin_concurrent")) {
		t.Fatalf("ownership does not record the administrator's saved file as the preimage: %+v err=%v", ownership, err)
	}
	if report, err := RemoveWindowsCodexMachineRequirements(opts); err != nil || !report.OK {
		t.Fatalf("remove: %+v err=%v", report, err)
	}
	restored, err := os.ReadFile(opts.RequirementsPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"allowed_sandbox_modes", "admin_concurrent"} {
		if !bytes.Contains(restored, []byte(key)) {
			t.Fatalf("uninstall lost the administrator's %q:\n%s", key, restored)
		}
	}
}

// The same for a repair of an installed guard, empty or enrolled: the
// administrator's concurrent requirement stays, the enrollment stays, and the
// ownership record stays the one the install wrote.
func TestWindowsCodexMachineRepairKeepsAConcurrentRequirement(t *testing.T) {
	alice := WindowsCodexManagedRuntimeTarget{SID: "S-1-5-21-111-222-333-1001", DataDir: `C:\Users\alice\.defenseclaw`}
	for _, enrolled := range []bool{false, true} {
		t.Run(map[bool]string{false: "empty", true: "Alice"}[enrolled], func(t *testing.T) {
			opts := newWindowsCodexMachineGuardFixtureForTest(t, []byte(windowsCodexOperatorRequirementForTest))
			if _, err := ReconcileWindowsCodexMachineRequirements(opts); err != nil {
				t.Fatalf("install the configured guard: %v", err)
			}
			want := []WindowsCodexManagedRuntimeTarget{}
			if enrolled {
				want = []WindowsCodexManagedRuntimeTarget{alice}
				if err := PublishWindowsCodexManagedRuntimeTargets(opts, want); err != nil {
					t.Fatal(err)
				}
			}
			installed, err := os.ReadFile(opts.OwnershipPath)
			if err != nil {
				t.Fatal(err)
			}
			// Damage: the managed hooks are gone.
			if err := os.WriteFile(opts.RequirementsPath, []byte(windowsCodexOperatorRequirementForTest), 0o600); err != nil {
				t.Fatal(err)
			}
			saveWhileWindowsCodexPublishesForTest(t, opts, func() bool {
				prependWindowsCodexRequirementForTest(t, opts.RequirementsPath, "admin_concurrent")
				return false
			})
			if report, err := ReconcileWindowsCodexMachineRequirements(opts); err != nil || !report.OK {
				t.Fatalf("repair: %+v err=%v", report, err)
			}
			requireWindowsCodexGuardForTest(t, opts, want, "allowed_sandbox_modes", "admin_concurrent")
			data, err := os.ReadFile(opts.OwnershipPath)
			if err != nil {
				t.Fatal(err)
			}
			before, err := parseWindowsCodexMachineOwnership(installed)
			if err != nil {
				t.Fatal(err)
			}
			after, err := parseWindowsCodexMachineOwnership(data)
			if err != nil || after.Pending || !bytes.Equal(after.Preimage, before.Preimage) || after.PreimageExisted != before.PreimageExisted {
				t.Fatalf("the repair changed the install's ownership preimage: %+v err=%v", after, err)
			}
		})
	}
}

// An administrator who keeps saving: the reconcile gives up after a bounded
// number of merges, keeps the last save, leaves the ownership record as it
// read it, and the next quiet reconcile publishes the guard with every save.
func TestWindowsCodexMachineReconcileStopsAgainstAWriterThatNeverStops(t *testing.T) {
	opts := newWindowsCodexMachineGuardFixtureForTest(t, []byte(windowsCodexOperatorRequirementForTest))
	saves := 0
	saveWhileWindowsCodexPublishesForTest(t, opts, func() bool {
		saves++
		prependWindowsCodexRequirementForTest(t, opts.RequirementsPath, fmt.Sprintf("admin_save_%d", saves))
		return saves < 100
	})
	report, err := ReconcileWindowsCodexMachineRequirements(opts)
	if err == nil || report.OK || !strings.Contains(err.Error(), "changed concurrently") {
		t.Fatalf("reconcile against a writer that never stops: %+v err=%v", report, err)
	}
	if saves < 2 || saves > 8 {
		t.Fatalf("the reconcile merged %d times; want a small bounded number of retries", saves)
	}
	last := []byte(fmt.Sprintf("admin_save_%d", saves))
	if data, err := os.ReadFile(opts.RequirementsPath); err != nil || !bytes.Contains(data, last) || !bytes.Contains(data, []byte("allowed_sandbox_modes")) {
		t.Fatalf("the reconcile did not keep the last save (err %v):\n%s", err, data)
	}
	if _, err := os.Lstat(opts.OwnershipPath); !os.IsNotExist(err) {
		t.Fatalf("a stopped first install left an ownership record: %v", err)
	}
	windowsCodexMachineTrustedFileCheck = func(string, string) error { return nil }
	if report, err := ReconcileWindowsCodexMachineRequirements(opts); err != nil || !report.OK {
		t.Fatalf("quiet reconcile: %+v err=%v", report, err)
	}
	keys := []string{"allowed_sandbox_modes"}
	for save := 1; save <= saves; save++ {
		keys = append(keys, fmt.Sprintf("admin_save_%d", save))
	}
	requireWindowsCodexGuardForTest(t, opts, []WindowsCodexManagedRuntimeTarget{}, keys...)
}
