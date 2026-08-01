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
	go func() {
		_, resolveErr := ResolveWindowsCodexManagedRuntimeRegistry(
			filepath.Join(programData, "DefenseClaw", "bin", "defenseclaw-hook.exe"),
		)
		resolved <- resolveErr
	}()

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
