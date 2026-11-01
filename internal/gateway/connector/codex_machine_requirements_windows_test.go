// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestNormalizeWindowsCodexManagedRuntimeTargetsAcceptsEntraID(t *testing.T) {
	const entraSID = "S-1-12-1-1111111111-2222222222-3333333333-4000000000"
	dataDir := filepath.Clean(`C:\Users\entra-user\.defenseclaw`)
	targets, err := normalizeWindowsCodexManagedRuntimeTargets([]WindowsCodexManagedRuntimeTarget{{
		SID: entraSID, DataDir: dataDir,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 1 || targets[0].SID != entraSID || targets[0].DataDir != dataDir {
		t.Fatalf("Codex targets = %+v, want Microsoft Entra ID target", targets)
	}
}

func TestResolveWindowsCodexManagedRuntimeRegistryCleanAbsenceIsNoop(t *testing.T) {
	programData := t.TempDir()
	originalProgramData := windowsCodexMachineProgramData
	t.Cleanup(func() { windowsCodexMachineProgramData = originalProgramData })
	windowsCodexMachineProgramData = func() (string, error) { return programData, nil }

	registry, err := ResolveWindowsCodexManagedRuntimeRegistry(
		filepath.Join(programData, "DefenseClaw", "bin", "defenseclaw-hook.exe"),
	)
	if err != nil {
		t.Fatalf("resolve clean absence: %v", err)
	}
	if registry.Active || len(registry.Targets) != 0 {
		t.Fatalf("clean absence unexpectedly activated managed runtime: %+v", registry)
	}
	lockPath := filepath.Join(
		programData,
		"OpenAI",
		"Codex",
		windowsCodexManagedLockFile,
	)
	if _, err := os.Lstat(lockPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("clean absence created a machine policy lock: %v", err)
	}
}

func TestResolveWindowsCodexManagedRuntimeRegistryWaitsForMachinePolicyLock(t *testing.T) {
	programData := t.TempDir()
	policyDir := filepath.Join(programData, "OpenAI", "Codex")
	if err := os.MkdirAll(policyDir, 0o755); err != nil {
		t.Fatalf("create policy directory: %v", err)
	}
	requirementsPath := filepath.Join(policyDir, "requirements.toml")
	statePath := filepath.Join(policyDir, windowsCodexManagedStateFile)
	lockPath := filepath.Join(policyDir, windowsCodexManagedLockFile)
	for path, body := range map[string][]byte{
		requirementsPath: []byte("invalid = true\n"),
		statePath:        []byte("{}\n"),
		lockPath:         nil,
	} {
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatalf("write fixture %s: %v", path, err)
		}
	}

	originalProgramData := windowsCodexMachineProgramData
	originalTrustedDirCheck := windowsCodexMachineTrustedDirCheck
	originalTrustedFileCheck := windowsCodexMachineTrustedFileCheck
	t.Cleanup(func() {
		windowsCodexMachineProgramData = originalProgramData
		windowsCodexMachineTrustedDirCheck = originalTrustedDirCheck
		windowsCodexMachineTrustedFileCheck = originalTrustedFileCheck
	})
	windowsCodexMachineProgramData = func() (string, error) { return programData, nil }
	windowsCodexMachineTrustedDirCheck = func(string, string) error { return nil }
	windowsCodexMachineTrustedFileCheck = func(string, string) error { return nil }

	heldLock, heldOverlapped, err := acquireWindowsCodexMachineFileLock(lockPath)
	if err != nil {
		t.Fatalf("hold machine policy lock: %v", err)
	}
	released := false
	release := func() error {
		if released {
			return nil
		}
		released = true
		if err := windows.UnlockFileEx(heldLock, 0, 1, 0, heldOverlapped); err != nil {
			_ = windows.CloseHandle(heldLock)
			return err
		}
		return windows.CloseHandle(heldLock)
	}
	t.Cleanup(func() { _ = release() })

	lockAttempted := make(chan struct{})
	var signalLockAttempt sync.Once
	windowsCodexMachineTrustedFileCheck = func(path, _ string) error {
		if strings.EqualFold(path, lockPath) {
			signalLockAttempt.Do(func() { close(lockAttempted) })
		}
		return nil
	}
	resolved := make(chan error, 1)
	resolverDone := make(chan struct{})
	go func() {
		defer close(resolverDone)
		_, resolveErr := ResolveWindowsCodexManagedRuntimeRegistry(
			filepath.Join(programData, "DefenseClaw", "bin", "defenseclaw-hook.exe"),
		)
		resolved <- resolveErr
	}()
	// Registered AFTER the hook-restoring cleanup so t.Cleanup runs it FIRST
	// (LIFO order): a leaked resolver goroutine would otherwise still hold
	// windowsCodexMachineProcessMu and race the hook restore, turning a single
	// clean assertion failure into a package-wide timeout.
	t.Cleanup(func() {
		_ = release()
		// 30s deadline: the previous 15s value flakes on GitHub-hosted
		// Windows runners under load. The resolver still returns on
		// the order of tens of milliseconds when the lock releases;
		// the extra budget is purely runner-scheduling slack, not a
		// signal that a real deadlock is being tolerated.
		select {
		case <-resolverDone:
		case <-time.After(30 * time.Second):
			t.Error("resolver goroutine did not finish; it still holds windowsCodexMachineProcessMu")
		}
	})

	select {
	case <-lockAttempted:
	case err := <-resolved:
		_ = release()
		t.Fatalf("resolver returned before attempting the policy lock: %v", err)
	case <-time.After(2 * time.Second):
		_ = release()
		t.Fatal("resolver did not attempt the machine policy lock")
	}
	select {
	case err := <-resolved:
		_ = release()
		t.Fatalf("resolver bypassed the held machine policy lock: %v", err)
	case <-time.After(100 * time.Millisecond):
	}

	if err := release(); err != nil {
		t.Fatalf("release machine policy lock: %v", err)
	}
	select {
	case err := <-resolved:
		if err == nil {
			t.Fatal("resolver unexpectedly accepted intentionally invalid policy fixtures")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("resolver did not continue after the machine policy lock was released")
	}
}

// ProgramData is only valid as an ancestor: stock Windows grants BUILTIN\Users
// mask 0x116 there, which the leaf rule rejects.
func TestValidateWindowsCodexMachineLayoutChecksProgramDataOnlyAsAncestor(t *testing.T) {
	programData := t.TempDir()
	stateRoot := t.TempDir()
	policyDir := filepath.Join(programData, "OpenAI", "Codex")
	managedDir := filepath.Join(stateRoot, "bin")
	installDir := filepath.Join(stateRoot, "install")
	for _, dir := range []string{policyDir, managedDir, installDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("create %s: %v", dir, err)
		}
	}

	originalProgramData := windowsCodexMachineProgramData
	originalTrustedDirCheck := windowsCodexMachineTrustedDirCheck
	originalTrustedFileCheck := windowsCodexMachineTrustedFileCheck
	originalVolumeCheck := windowsCodexMachineVolumeCheck
	t.Cleanup(func() {
		windowsCodexMachineProgramData = originalProgramData
		windowsCodexMachineTrustedDirCheck = originalTrustedDirCheck
		windowsCodexMachineTrustedFileCheck = originalTrustedFileCheck
		windowsCodexMachineVolumeCheck = originalVolumeCheck
	})

	var checkedDirs []string
	windowsCodexMachineProgramData = func() (string, error) { return programData, nil }
	windowsCodexMachineVolumeCheck = func(string) error { return nil }
	windowsCodexMachineTrustedFileCheck = func(string, string) error { return nil }
	windowsCodexMachineTrustedDirCheck = func(path, _ string) error {
		checkedDirs = append(checkedDirs, path)
		return nil
	}

	// Only the paths reaching the leaf check are asserted; the hook binary read
	// that follows the loop is out of scope.
	_ = validateWindowsCodexMachineLayout(WindowsCodexMachineRequirementsOptions{
		RequirementsPath:   filepath.Join(policyDir, "requirements.toml"),
		ManagedStatePath:   filepath.Join(policyDir, windowsCodexManagedStateFile),
		ManagedDir:         managedDir,
		HookBinary:         filepath.Join(managedDir, "defenseclaw-hook.exe"),
		OwnershipPath:      filepath.Join(installDir, "codex-requirements-ownership.json"),
		GatewayAddr:        "127.0.0.1:18000",
		GatewayServiceName: "DefenseClawGateway",
	})

	for _, dir := range checkedDirs {
		if strings.EqualFold(dir, programData) {
			t.Fatalf("ProgramData was leaf-checked; this rejects every stock Windows host: %v", checkedDirs)
		}
	}
	for _, want := range []string{policyDir, managedDir, installDir} {
		found := false
		for _, dir := range checkedDirs {
			if strings.EqualFold(dir, want) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("leaf check lost coverage of %s: %v", want, checkedDirs)
		}
	}
}

// A deployment with no enrolled Codex target has no machine-policy directory.
func TestRemoveWindowsCodexMachineRequirementsAcceptsAbsentPolicyDirectory(t *testing.T) {
	programData := t.TempDir()
	stateRoot := t.TempDir()
	policyDir := filepath.Join(programData, "OpenAI", "Codex")
	managedDir := filepath.Join(stateRoot, "bin")
	installDir := filepath.Join(stateRoot, "install")
	for _, dir := range []string{managedDir, installDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("create %s: %v", dir, err)
		}
	}

	originalProgramData := windowsCodexMachineProgramData
	t.Cleanup(func() { windowsCodexMachineProgramData = originalProgramData })
	windowsCodexMachineProgramData = func() (string, error) { return programData, nil }

	opts := WindowsCodexMachineRequirementsOptions{
		RequirementsPath:   filepath.Join(policyDir, "requirements.toml"),
		ManagedStatePath:   filepath.Join(policyDir, windowsCodexManagedStateFile),
		ManagedDir:         managedDir,
		HookBinary:         filepath.Join(managedDir, "defenseclaw-hook.exe"),
		OwnershipPath:      filepath.Join(installDir, "codex-requirements-ownership.json"),
		GatewayAddr:        "127.0.0.1:18000",
		GatewayServiceName: "DefenseClawGateway",
	}
	if adminErr := requireWindowsCodexMachineAdministrator(); adminErr != nil {
		t.Skipf("removal requires an elevated Administrator or LocalSystem token: %v", adminErr)
	}
	report, err := RemoveWindowsCodexMachineRequirements(opts)
	if err != nil {
		t.Fatalf("remove with an absent policy directory: %v", err)
	}
	if !report.OK || !report.SafeToRemoveBinary ||
		!report.ManagedStateRemovedOrAbsent ||
		report.SurvivingOwnedPathReferences != 0 {
		t.Fatalf("absent Codex policy did not report a clean removal: %+v", report)
	}
	// PowerShell rejects any disposition outside its allow list.
	if report.Disposition != "ownership_absent" {
		t.Fatalf("unexpected removal disposition %q", report.Disposition)
	}
	if _, err := os.Lstat(policyDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("removal created the Codex machine-policy directory: %v", err)
	}
}

// A configured Codex guard owns DefenseClaw's managed hooks in
// requirements.toml and the protected runtime registry, which keeps the
// enrollment. Reconcile rebuilds a missing or changed requirements file and a
// stale registry around that enrollment, for an empty enrollment as for an
// enrolled one, and keeps an administrator's own requirements. A deleted
// registry is the enrollment record itself: it comes back empty, the account
// stays refused, and exact publication re-enrolls it from the manifest.
func TestWindowsCodexMachineGuardArtifactRepairTable(t *testing.T) {
	if adminErr := requireWindowsCodexMachineAdministrator(); adminErr != nil {
		t.Skipf("reconcile requires an elevated Administrator or LocalSystem token: %v", adminErr)
	}
	alice := WindowsCodexManagedRuntimeTarget{SID: "S-1-5-21-111-222-333-1001", DataDir: `C:\Users\alice\.defenseclaw`}
	const operatorRequirement = "allowed_sandbox_modes = [\"read-only\"]\n"
	damages := []struct {
		name         string
		apply        func(t *testing.T, opts WindowsCodexMachineRequirementsOptions)
		keepsTargets bool
		keepsOwn     bool
	}{
		{name: "requirements missing", keepsTargets: true, apply: func(t *testing.T, opts WindowsCodexMachineRequirementsOptions) {
			if err := os.Remove(opts.RequirementsPath); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "requirements replaced", keepsTargets: true, keepsOwn: true, apply: func(t *testing.T, opts WindowsCodexMachineRequirementsOptions) {
			if err := os.WriteFile(opts.RequirementsPath, []byte(operatorRequirement), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "managed hook changed", keepsTargets: true, apply: func(t *testing.T, opts WindowsCodexMachineRequirementsOptions) {
			data, err := os.ReadFile(opts.RequirementsPath)
			if err != nil {
				t.Fatal(err)
			}
			// The managed commands launch the hook through the system
			// cmd.exe (GAP-1908); make each of them exit 0 instead.
			edited := strings.ReplaceAll(string(data), " /d /v:off /c \"", " /d /v:off /c exit 0 & rem \"")
			if edited == string(data) {
				t.Fatalf("fixture: requirements name no managed hook binary to change:\n%s", data)
			}
			if err := os.WriteFile(opts.RequirementsPath, []byte(edited), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "registry stale", keepsTargets: true, apply: func(t *testing.T, opts WindowsCodexMachineRequirementsOptions) {
			data, err := os.ReadFile(opts.ManagedStatePath)
			if err != nil {
				t.Fatal(err)
			}
			state, err := parseWindowsCodexManagedRuntimeState(data)
			if err != nil {
				t.Fatal(err)
			}
			state.RequirementsSHA256 = strings.Repeat("0", windowsCodexSHA256HexLength)
			body, err := marshalWindowsCodexManagedRuntimeState(state)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(opts.ManagedStatePath, body, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "registry missing", apply: func(t *testing.T, opts WindowsCodexMachineRequirementsOptions) {
			if err := os.Remove(opts.ManagedStatePath); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, enrolled := range []bool{false, true} {
		for _, damage := range damages {
			t.Run(map[bool]string{false: "empty", true: "Alice"}[enrolled]+"/"+damage.name, func(t *testing.T) {
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
				registry, err := ResolveWindowsCodexManagedRuntimeRegistry(hook)
				if err != nil || !registry.Active || !slices.Equal(registry.Targets, want) {
					t.Fatalf("fixture guard: %+v err=%v", registry, err)
				}
				damage.apply(t, opts)
				if registry, err := ResolveWindowsCodexManagedRuntimeRegistry(hook); err == nil && registry.Active &&
					slices.Equal(registry.Targets, want) {
					t.Fatal("the damaged guard appeared healthy")
				}
				if report, err := ReconcileWindowsCodexMachineRequirements(opts); err != nil || !report.OK {
					t.Fatalf("rebuild: %+v err=%v", report, err)
				}
				if !damage.keepsTargets {
					want = []WindowsCodexManagedRuntimeTarget{}
				}
				registry, err = ResolveWindowsCodexManagedRuntimeRegistry(hook)
				if err != nil || !registry.Active || !slices.Equal(registry.Targets, want) {
					t.Fatalf("rebuilt guard: %+v (want targets %v) err=%v", registry, want, err)
				}
				if _, err := VerifyWindowsCodexMachineRequirements(opts); err != nil {
					t.Fatalf("the rebuilt guard does not verify: %v", err)
				}
				requirements, err := os.ReadFile(opts.RequirementsPath)
				if err != nil {
					t.Fatal(err)
				}
				if damage.keepsOwn && !strings.Contains(string(requirements), "allowed_sandbox_modes") {
					t.Fatal("the rebuild dropped the administrator's own requirement")
				}
				// The edited entries no longer carry DefenseClaw's exact command,
				// so, like an administrator's own hooks, they stay; the exact
				// managed hooks are back beside them.
				if contains, err := windowsCodexRequirementsContainExactManagedHook(requirements, opts); err != nil || !contains {
					t.Fatalf("the rebuilt requirements lack the exact managed hooks: %v", err)
				}
				if report, err := ReconcileWindowsCodexMachineRequirements(opts); err != nil || report.Changed {
					t.Fatalf("second repair of a healthy guard: %+v err=%v", report, err)
				}
			})
		}
	}
}
