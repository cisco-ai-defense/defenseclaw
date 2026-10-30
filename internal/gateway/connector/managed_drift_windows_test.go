// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"golang.org/x/sys/windows"
)

func captureManagedResilienceEvents(t *testing.T) *[]string {
	t.Helper()
	original := managed.ReportResilienceEvent
	t.Cleanup(func() { managed.ReportResilienceEvent = original })
	markers := &[]string{}
	managed.ReportResilienceEvent = func(marker string, _ map[string]string) {
		*markers = append(*markers, marker)
	}
	return markers
}

func stubWindowsCodexMachineFileChecks(t *testing.T, strict, structure func(string, string) error, canRepair bool) {
	t.Helper()
	originalStrict := windowsCodexMachineTrustedFileCheck
	originalStructure := windowsCodexMachineStructureFileCheck
	originalCanRepair := windowsManagedCanRepair
	t.Cleanup(func() {
		windowsCodexMachineTrustedFileCheck = originalStrict
		windowsCodexMachineStructureFileCheck = originalStructure
		windowsManagedCanRepair = originalCanRepair
	})
	windowsCodexMachineTrustedFileCheck = strict
	windowsCodexMachineStructureFileCheck = structure
	windowsManagedCanRepair = func() bool { return canRepair }
}

func TestEnsureWindowsCodexMachineFileTrustAcceptsPermissionDriftForHook(t *testing.T) {
	path := filepath.Join(t.TempDir(), "requirements.toml")
	if err := os.WriteFile(path, []byte("x = 1\n"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	t.Setenv(managed.TrustStrictAncestorsEnv, "")
	markers := captureManagedResilienceEvents(t)
	stubWindowsCodexMachineFileChecks(t,
		func(string, string) error { return errors.New("owner S-1-5-21-1-2-3-500 is not trusted") },
		func(string, string) error { return nil },
		false,
	)
	if err := ensureWindowsCodexMachineFileTrust(path, "Codex machine requirements", true); err != nil {
		t.Fatalf("permission drift on a standard-user read = %v, want accepted", err)
	}
	if len(*markers) != 1 {
		t.Fatalf("resilience events = %v, want exactly one", *markers)
	}
}

func TestEnsureWindowsCodexMachineFileTrustKeepsStructureFatal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "requirements.toml")
	structural := errors.New("reparse points are not allowed")
	stubWindowsCodexMachineFileChecks(t,
		func(string, string) error { return errors.New("drift") },
		func(string, string) error { return structural },
		true,
	)
	if err := ensureWindowsCodexMachineFileTrust(path, "Codex machine requirements", true); !errors.Is(err, structural) {
		t.Fatalf("structural failure = %v, want %v", err, structural)
	}
}

func TestEnsureWindowsCodexMachineFileTrustStrictModeStaysFatal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "requirements.toml")
	if err := os.WriteFile(path, []byte("x = 1\n"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	t.Setenv(managed.TrustStrictAncestorsEnv, "1")
	verdict := errors.New("untrusted Windows principal has write-like access")
	stubWindowsCodexMachineFileChecks(t,
		func(string, string) error { return verdict },
		func(string, string) error { return nil },
		false,
	)
	if err := ensureWindowsCodexMachineFileTrust(path, "Codex machine requirements", true); !errors.Is(err, verdict) {
		t.Fatalf("strict-mode drift = %v, want %v", err, verdict)
	}
}

func TestClearWindowsManagedReadOnlyRestoresAttribute(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	if err := os.Chmod(path, 0o400); err != nil {
		t.Fatalf("set ReadOnly: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) })
	captureManagedResilienceEvents(t)

	restore, err := clearWindowsManagedReadOnly(path)
	if err != nil {
		t.Fatalf("clear ReadOnly: %v", err)
	}
	if err := os.WriteFile(path, []byte("{\"a\":1}\n"), 0o600); err != nil {
		t.Fatalf("write after clearing ReadOnly: %v", err)
	}
	if err := restore(); err != nil {
		t.Fatalf("restore ReadOnly: %v", err)
	}
	ptr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	attributes, err := windows.GetFileAttributes(ptr)
	if err != nil {
		t.Fatalf("read attributes: %v", err)
	}
	if attributes&windows.FILE_ATTRIBUTE_READONLY == 0 {
		t.Fatal("ReadOnly attribute was not restored")
	}

	missing := filepath.Join(t.TempDir(), "absent.json")
	restore, err = clearWindowsManagedReadOnly(missing)
	if err != nil || restore() != nil {
		t.Fatalf("missing file must be a no-op: %v", err)
	}
}

func TestWindowsManagedDescriptorModelSeesInheritedEntries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lock")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	model, err := windowsManagedPathDescriptorModel(path, false)
	if err != nil {
		t.Fatalf("read descriptor model: %v", err)
	}
	user, err := windowsEffectiveUserSID()
	if err != nil {
		t.Fatal(err)
	}
	drift := classifyManagedDrift(model, windowsManagedTargetRuntimeDriftPolicy(user))
	if drift.Canonical {
		t.Fatal("a temp file with an inherited DACL classified canonical")
	}
	if !drift.Inherited && !drift.Unprotected {
		t.Fatalf("drift %q does not report inheritance", drift.Reason())
	}
}

func TestEnsureWindowsManagedLockProtectionAcceptsDriftWithoutPrivilege(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json.lock")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	t.Setenv(managed.TrustStrictAncestorsEnv, "")
	originalCanRepair := windowsManagedCanRepair
	t.Cleanup(func() { windowsManagedCanRepair = originalCanRepair })
	windowsManagedCanRepair = func() bool { return false }
	markers := captureManagedResilienceEvents(t)

	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	user, err := windowsEffectiveUserSID()
	if err != nil {
		t.Fatal(err)
	}
	lock := windowsManagedLockRepair{
		Label:  "managed lock",
		Path:   path,
		Handle: windows.Handle(file.Fd()),
		Validate: func(h windows.Handle) error {
			return validateWindowsManagedFileLockHandleForTarget(h, user)
		},
		Canonical: func() (*windows.SECURITY_DESCRIPTOR, error) {
			return windowsManagedFileLockSecurityDescriptorForTarget(user)
		},
		Policy: windowsManagedTargetRuntimeDriftPolicy(user),
	}
	if err := ensureWindowsManagedLockProtection(lock); err != nil {
		t.Fatalf("inherited lock DACL without privilege = %v, want accepted", err)
	}
	if len(*markers) != 1 {
		t.Fatalf("resilience events = %v, want one accept", *markers)
	}

	t.Setenv(managed.TrustStrictAncestorsEnv, "1")
	if err := ensureWindowsManagedLockProtection(lock); err == nil {
		t.Fatal("strict mode accepted a drifted lock")
	}
}
