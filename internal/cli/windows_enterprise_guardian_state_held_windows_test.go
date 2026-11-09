// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// GAP-0967: a guardian state file a program holds open is found before a
// lifecycle run changes anything, and named with its holder; a file only the
// guardian touches for a moment is not a hold.
func TestWindowsEnterpriseGuardianStateHeld(t *testing.T) {
	authDir := t.TempDir()
	dataDir := t.TempDir()
	layout := managed.StandaloneLayout{GuardianAuthDir: authDir, DataDir: dataDir}
	for _, name := range []string{"protected_targets.json", "activation.json"} {
		if err := os.WriteFile(filepath.Join(authDir, name), []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dataDir, hookGuardianStateFile), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(authDir, "claude-mcp"), 0o700); err != nil {
		t.Fatal(err)
	}
	previousOpen, previousWait, previousHolders := windowsEnterpriseGuardianStateOpenForDelete, windowsEnterpriseGuardianStateProbeWait, windowsEnterpriseGuardianStateHolders
	t.Cleanup(func() {
		windowsEnterpriseGuardianStateOpenForDelete, windowsEnterpriseGuardianStateProbeWait, windowsEnterpriseGuardianStateHolders = previousOpen, previousWait, previousHolders
	})
	windowsEnterpriseGuardianStateProbeWait = time.Millisecond
	windowsEnterpriseGuardianStateHolders = func(path string) []string { return []string{"editor.exe (PID 4242)"} }
	heldFile := filepath.Join(authDir, "protected_targets.json")
	probes := 0
	windowsEnterpriseGuardianStateOpenForDelete = func(path string) error {
		if path == heldFile {
			probes++
			return windows.ERROR_SHARING_VIOLATION
		}
		return nil
	}
	hold := windowsEnterpriseGuardianStateHeld(layout)
	if hold == nil || hold.Path != heldFile || len(hold.Holders) != 1 || probes != 5 {
		t.Fatalf("hold=%+v probes=%d, want protected_targets.json held and five probes", hold, probes)
	}
	if !strings.Contains(hold.describe(), "editor.exe (PID 4242)") {
		t.Fatalf("describe = %q", hold.describe())
	}

	// A holder that lets go within the second is not a hold.
	probes = 0
	windowsEnterpriseGuardianStateOpenForDelete = func(path string) error {
		if path == heldFile {
			probes++
			if probes < 3 {
				return windows.ERROR_SHARING_VIOLATION
			}
		}
		return nil
	}
	if hold := windowsEnterpriseGuardianStateHeld(layout); hold != nil {
		t.Fatalf("a momentary hold counted: %+v", hold)
	}
	// An access error is not a hold: only a sharing violation is.
	windowsEnterpriseGuardianStateOpenForDelete = func(string) error { return windows.ERROR_ACCESS_DENIED }
	if hold := windowsEnterpriseGuardianStateHeld(layout); hold != nil {
		t.Fatalf("an access error counted as a hold: %+v", hold)
	}
	// The state file in the data folder counts too.
	stateFile := filepath.Join(dataDir, hookGuardianStateFile)
	windowsEnterpriseGuardianStateOpenForDelete = func(path string) error {
		if path == stateFile {
			return windows.ERROR_SHARING_VIOLATION
		}
		return nil
	}
	if hold := windowsEnterpriseGuardianStateHeld(layout); hold == nil || hold.Path != stateFile {
		t.Fatalf("hold = %+v, want the guardian state file", hold)
	}
}

// The preflight refuses with the holder and the repair, and the refusal exits
// 1618 so a deployment tool retries it.
func TestWindowsEnterpriseGuardianStatePreflightNamesTheHolderAndTheRepair(t *testing.T) {
	previous, previousLayout := windowsEnterpriseGuardianStateHeldNow, windowsEnterpriseHotConfigLayout
	t.Cleanup(func() {
		windowsEnterpriseGuardianStateHeldNow, windowsEnterpriseHotConfigLayout = previous, previousLayout
	})
	windowsEnterpriseHotConfigLayout = func() (managed.StandaloneLayout, error) { return managed.StandaloneLayout{}, nil }
	windowsEnterpriseGuardianStateHeldNow = func(managed.StandaloneLayout) *windowsGuardianStateHold { return nil }
	if err := windowsEnterpriseGuardianStatePreflight(); err != nil {
		t.Fatalf("nothing held: %v", err)
	}
	windowsEnterpriseGuardianStateHeldNow = func(managed.StandaloneLayout) *windowsGuardianStateHold {
		return &windowsGuardianStateHold{Path: `C:\g\protected_targets.json`, Holders: []string{"notepad.exe (PID 7)"}}
	}
	err := windowsEnterpriseGuardianStatePreflight()
	if err == nil {
		t.Fatal("a held file was not refused")
	}
	for _, want := range []string{`C:\g\protected_targets.json`, "notepad.exe (PID 7)", "nothing was changed", "services are still running", "enterprise windows repair"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("refusal %q does not say %q", err, want)
		}
	}
	windowsEnterpriseHotConfigLayout = func() (managed.StandaloneLayout, error) { return managed.StandaloneLayout{}, os.ErrNotExist }
	if err := windowsEnterpriseGuardianStatePreflight(); err != nil {
		t.Fatalf("no layout is not a hold: %v", err)
	}
}
