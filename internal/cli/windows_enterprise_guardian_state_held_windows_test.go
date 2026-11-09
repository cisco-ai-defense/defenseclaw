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

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
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

// GAP-0977: every file the guardian and its enumerator publish is in the
// probe's list, not only the ledger.
func TestWindowsEnterpriseGuardianStateFilesListsTheWholeClass(t *testing.T) {
	root := t.TempDir()
	layout := managed.StandaloneLayout{
		GuardianAuthDir: filepath.Join(root, "hook-guardian-state"),
		DataDir:         filepath.Join(root, "runtime"),
		ManifestPath:    filepath.Join(root, "hook-guardian", "targets.yaml"),
		HookRuntimeDir:  filepath.Join(root, "hook-runtime"),
	}
	want := map[string]string{
		filepath.Join(layout.GuardianAuthDir, "protected_targets.json"):  "ledger",
		filepath.Join(layout.GuardianAuthDir, "activation.json"):         "activation",
		filepath.Join(layout.GuardianAuthDir, "removed-connectors.json"): "removed connectors",
		filepath.Join(layout.GuardianAuthDir, "user-cleanup.json"):       "cleanup ledger",
		filepath.Join(layout.GuardianAuthDir, "unprotected-agents.json"): "unprotected agents",
		filepath.Join(layout.DataDir, "hook_guardian_state.json"):        "state",
		filepath.Join(layout.DataDir, "hook_guardian_notices.json"):      "notices",
		filepath.Join(layout.DataDir, "hook_guardian_restores.json"):     "restores",
		filepath.Join(layout.DataDir, windowsOpenCodePortWarningsFile):   "opencode warnings",
		layout.ManifestPath: "manifest",
		filepath.Join(filepath.Dir(layout.ManifestPath), "unprotected-agents.json"):     "enumerator unprotected agents",
		filepath.Join(filepath.Dir(layout.ManifestPath), ".enrollment-groups.json"):     "enrollment group cache",
		filepath.Join(filepath.Dir(layout.ManifestPath), ".inventory-grants.json"):      "inventory grants",
		filepath.Join(filepath.Dir(layout.ManifestPath), "opencode-service-ports.json"): "opencode service ports",
		filepath.Join(layout.HookRuntimeDir, ".defenseclaw-connector-off-roster-codex"): "marker",
	}
	for path := range want {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// What the class does not include: another file of the data folder, a
	// folder of the authorization folder, an unrelated marker name.
	for _, path := range []string{filepath.Join(layout.DataDir, "audit.db"), filepath.Join(layout.HookRuntimeDir, "unrelated.txt")} {
		if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// A lock or a state marker an enumerator holds open on purpose is not in it.
	for _, name := range []string{"opencode-service-ports.lock", ".state"} {
		if err := os.WriteFile(filepath.Join(filepath.Dir(layout.ManifestPath), name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(layout.GuardianAuthDir, "claude-mcp"), 0o700); err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, path := range windowsEnterpriseGuardianStateFiles(layout) {
		got[path] = true
	}
	for path, name := range want {
		if !got[path] {
			t.Errorf("%s (%s) is not in the probe's list", path, name)
		}
	}
	if len(got) != len(want) {
		t.Errorf("the list holds %d files, want %d: %v", len(got), len(want), got)
	}
}

// Status and verify say a held guardian state file means the enrollment is not
// proven: connectors read pending, the host is not security-complete, and one
// warning names the file, the holder and the repair.
func TestApplyWindowsEnterpriseGuardianStateHoldMarksTheEnrollmentNotProven(t *testing.T) {
	previous, previousLayout := windowsEnterpriseGuardianStateHeldNow, windowsEnterpriseHotConfigLayout
	t.Cleanup(func() {
		windowsEnterpriseGuardianStateHeldNow, windowsEnterpriseHotConfigLayout = previous, previousLayout
	})
	windowsEnterpriseHotConfigLayout = func() (managed.StandaloneLayout, error) { return managed.StandaloneLayout{}, nil }
	build := func() *enterprisestatus.Result {
		result := &enterprisestatus.Result{SecurityComplete: true}
		result.Enrollment.Accounts = []enterprisestatus.EnrollmentAccount{
			{Account: `C:\Users\a`, Connectors: map[string]string{"claudecode": "enrolled", "cursor": "failed"}},
			{Account: `C:\Users\b`, Connectors: map[string]string{"codex": "pending"}},
		}
		result.Enrollment.Targets, result.Enrollment.Pending, result.Enrollment.Failed = 3, 1, 1
		return result
	}
	windowsEnterpriseGuardianStateHeldNow = func(managed.StandaloneLayout) *windowsGuardianStateHold { return nil }
	untouched := build()
	applyWindowsEnterpriseGuardianStateHold(untouched)
	if !untouched.SecurityComplete || untouched.Enrollment.Accounts[0].Connectors["claudecode"] != "enrolled" || len(untouched.Warnings) != 0 {
		t.Fatalf("nothing held but status changed: %+v", untouched)
	}
	windowsEnterpriseGuardianStateHeldNow = func(managed.StandaloneLayout) *windowsGuardianStateHold {
		return &windowsGuardianStateHold{Path: `C:\g\protected_targets.json`, Holders: []string{"notepad.exe (PID 7)"}}
	}
	held := build()
	applyWindowsEnterpriseGuardianStateHold(held)
	if held.SecurityComplete {
		t.Fatal("a held guardian state file left the host security-complete")
	}
	a := held.Enrollment.Accounts[0]
	if a.Connectors["claudecode"] != "pending" || a.Connectors["cursor"] != "failed" || !strings.Contains(a.Reason, "not proven") {
		t.Fatalf("account a = %+v, want enrolled shown pending, failed kept, reason not proven", a)
	}
	if held.Enrollment.Pending != 2 || held.Enrollment.Failed != 1 {
		t.Fatalf("counts pending=%d failed=%d, want 2 and 1", held.Enrollment.Pending, held.Enrollment.Failed)
	}
	if len(held.Warnings) != 1 || held.Warnings[0].Code != "guardian_state_held" ||
		!strings.Contains(held.Warnings[0].Message, "notepad.exe (PID 7)") || !strings.Contains(held.Warnings[0].Message, "enterprise windows repair") {
		t.Fatalf("warnings = %+v", held.Warnings)
	}
}
