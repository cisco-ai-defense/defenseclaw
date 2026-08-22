// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

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
