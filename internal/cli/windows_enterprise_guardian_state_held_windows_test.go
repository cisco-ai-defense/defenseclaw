// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"os"
	"os/exec"
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
	previousOpen, previousWait, previousHolders, previousReadable := windowsEnterpriseGuardianStateOpenForDelete, windowsEnterpriseGuardianStateProbeWait, windowsEnterpriseGuardianStateHolders, windowsEnterpriseGuardianStateUserOpenable
	t.Cleanup(func() {
		windowsEnterpriseGuardianStateOpenForDelete, windowsEnterpriseGuardianStateProbeWait, windowsEnterpriseGuardianStateHolders, windowsEnterpriseGuardianStateUserOpenable = previousOpen, previousWait, previousHolders, previousReadable
	})
	windowsEnterpriseGuardianStateUserOpenable = func(string) bool { return false }
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

// GAP-0977 and N2: the probe class is the critical files only, and a file a
// standard account can open is never in it: a user who held one with read
// sharing would otherwise block every ensure and repair.
func TestWindowsEnterpriseGuardianStateFilesAreTheCriticalAdministratorOnlyFiles(t *testing.T) {
	root := t.TempDir()
	layout := managed.StandaloneLayout{
		GuardianAuthDir: filepath.Join(root, "hook-guardian-state"),
		DataDir:         filepath.Join(root, "runtime"),
		ManifestPath:    filepath.Join(root, "hook-guardian", "targets.yaml"),
		HookRuntimeDir:  filepath.Join(root, "hook-runtime"),
	}
	critical := []string{
		filepath.Join(layout.GuardianAuthDir, "protected_targets.json"),
		filepath.Join(layout.GuardianAuthDir, "activation.json"),
		filepath.Join(layout.GuardianAuthDir, "user-cleanup.json"),
		filepath.Join(layout.DataDir, "hook_guardian_state.json"),
	}
	others := []string{
		filepath.Join(layout.GuardianAuthDir, "removed-connectors.json"),
		filepath.Join(layout.GuardianAuthDir, "unprotected-agents.json"),
		filepath.Join(layout.DataDir, "hook_guardian_startup.json"),
		filepath.Join(layout.DataDir, "hook_guardian_notices.json"),
		filepath.Join(layout.DataDir, "hook_guardian_restores.json"),
		filepath.Join(layout.DataDir, windowsOpenCodePortWarningsFile),
		layout.ManifestPath,
		filepath.Join(filepath.Dir(layout.ManifestPath), "unprotected-agents.json"),
		filepath.Join(filepath.Dir(layout.ManifestPath), ".enrollment-groups.json"),
		filepath.Join(layout.HookRuntimeDir, ".defenseclaw-connector-off-roster-claudecode"),
	}
	for _, path := range append(append([]string{}, critical...), others...) {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	previous := windowsEnterpriseGuardianStateUserOpenable
	t.Cleanup(func() { windowsEnterpriseGuardianStateUserOpenable = previous })
	windowsEnterpriseGuardianStateUserOpenable = func(string) bool { return false }
	got := map[string]bool{}
	for _, path := range windowsEnterpriseGuardianStateFiles(layout) {
		got[path] = true
	}
	for _, path := range critical {
		if !got[path] {
			t.Errorf("%s is critical and not in the probe class", path)
		}
	}
	if len(got) != len(critical) {
		t.Errorf("the class holds %d files, want the %d critical ones: %v", len(got), len(critical), got)
	}
	// A critical file a standard account can read leaves the class.
	userReadable := critical[0]
	windowsEnterpriseGuardianStateUserOpenable = func(path string) bool { return path == userReadable }
	for _, path := range windowsEnterpriseGuardianStateFiles(layout) {
		if path == userReadable {
			t.Errorf("%s is readable by a standard account and stayed in the class", path)
		}
	}
}

// The user-readable test reads the real access list: Users, Authenticated
// Users, Everyone or Interactive with read access make a file user-readable.
func TestWindowsEnterpriseGuardianStateUserReadableReadsTheAccessList(t *testing.T) {
	path := filepath.Join(t.TempDir(), "marker")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) {
		t.Helper()
		if out, err := exec.Command("icacls.exe", append([]string{path}, args...)...).CombinedOutput(); err != nil {
			t.Fatalf("icacls %v: %v: %s", args, err, out)
		}
	}
	run("/inheritance:r", "/grant:r", "*S-1-5-18:F", "*S-1-5-32-544:F")
	if windowsEnterpriseGuardianStateUserOpenable(path) {
		t.Fatal("a file only SYSTEM and Administrators can open read as user-readable")
	}
	run("/grant", "*S-1-5-32-545:R")
	if !windowsEnterpriseGuardianStateUserOpenable(path) {
		t.Fatal("a file Users can read was not seen as user-readable")
	}
	run("/remove:g", "*S-1-5-32-545", "/grant", "*S-1-5-11:R")
	if !windowsEnterpriseGuardianStateUserOpenable(path) {
		t.Fatal("a file Authenticated Users can read was not seen as user-readable")
	}
	run("/remove:g", "*S-1-5-11", "/deny", "*S-1-5-32-545:R")
	if windowsEnterpriseGuardianStateUserOpenable(path) {
		t.Fatal("a deny entry counted as a read grant")
	}
	// N2 tighten: any access for any principal beyond SYSTEM, Administrators and
	// a service SID makes the file openable by a standard account.
	run("/remove:d", "*S-1-5-32-545", "/grant", "*S-1-5-32-545:W")
	if !windowsEnterpriseGuardianStateUserOpenable(path) {
		t.Fatal("a write-only Users entry was not seen as openable")
	}
	run("/remove:g", "*S-1-5-32-545")
	if windowsEnterpriseGuardianStateUserOpenable(path) {
		t.Fatal("the file is back to SYSTEM and Administrators only but was seen as openable")
	}
	token, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	user := token.User.Sid.String()
	if windowsEnterpriseGuardianStateSIDIsAdminOnly(token.User.Sid) {
		t.Skipf("the test runs as %s, which is SYSTEM or a service SID", user)
	}
	run("/grant", "*"+user+":R")
	if !windowsEnterpriseGuardianStateUserOpenable(path) {
		t.Fatalf("a user SID named directly (%s) was not seen as openable", user)
	}
}

// The principals that may open a gated file are SYSTEM, Administrators and the
// service SIDs; every other SID, including a domain or local user, may not.
func TestWindowsEnterpriseGuardianStateSIDIsAdminOnly(t *testing.T) {
	for sidText, want := range map[string]bool{
		"S-1-5-18":     true,
		"S-1-5-32-544": true,
		"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464": true,
		"S-1-5-32-545": false,
		"S-1-5-11":     false,
		"S-1-1-0":      false,
		"S-1-5-4":      false,
		"S-1-5-21-111111111-222222222-333333333-1001": false,
		"S-1-5-21-111111111-222222222-333333333-500":  false,
	} {
		sid, err := windows.StringToSid(sidText)
		if err != nil {
			t.Fatal(err)
		}
		if got := windowsEnterpriseGuardianStateSIDIsAdminOnly(sid); got != want {
			t.Errorf("%s: admin-only = %v, want %v", sidText, got, want)
		}
	}
}

// N2: a user-readable file held by a reader of a standard account is not a hold.
func TestWindowsEnterpriseGuardianStateHeldIgnoresAUserReadableFile(t *testing.T) {
	root := t.TempDir()
	layout := managed.StandaloneLayout{GuardianAuthDir: filepath.Join(root, "auth"), DataDir: filepath.Join(root, "runtime")}
	ledger := filepath.Join(layout.GuardianAuthDir, "protected_targets.json")
	for _, path := range []string{ledger, filepath.Join(layout.DataDir, "hook_guardian_state.json")} {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	previousOpen, previousWait, previousReadable := windowsEnterpriseGuardianStateOpenForDelete, windowsEnterpriseGuardianStateProbeWait, windowsEnterpriseGuardianStateUserOpenable
	t.Cleanup(func() {
		windowsEnterpriseGuardianStateOpenForDelete, windowsEnterpriseGuardianStateProbeWait, windowsEnterpriseGuardianStateUserOpenable = previousOpen, previousWait, previousReadable
	})
	windowsEnterpriseGuardianStateProbeWait = time.Millisecond
	windowsEnterpriseGuardianStateOpenForDelete = func(path string) error {
		if path == ledger {
			return windows.ERROR_SHARING_VIOLATION // a reader holds it
		}
		return nil
	}
	windowsEnterpriseGuardianStateUserOpenable = func(path string) bool { return path == ledger }
	if hold := windowsEnterpriseGuardianStateHeld(layout); hold != nil {
		t.Fatalf("a file a standard account can read produced a hold: %+v", hold)
	}
	previousLayout, previousHeld := windowsEnterpriseHotConfigLayout, windowsEnterpriseGuardianStateHeldNow
	t.Cleanup(func() {
		windowsEnterpriseHotConfigLayout, windowsEnterpriseGuardianStateHeldNow = previousLayout, previousHeld
	})
	windowsEnterpriseHotConfigLayout = func() (managed.StandaloneLayout, error) { return layout, nil }
	windowsEnterpriseGuardianStateHeldNow = windowsEnterpriseGuardianStateHeld
	if err := windowsEnterpriseGuardianStatePreflight(); err != nil {
		t.Fatalf("the preflight (the 1618 refusal) fired for a user-readable file: %v", err)
	}
	result := &enterprisestatus.Result{SecurityComplete: true}
	result.Enrollment.Accounts = []enterprisestatus.EnrollmentAccount{{Account: "a", Connectors: map[string]string{"codex": "enrolled"}}}
	applyWindowsEnterpriseGuardianStateHold(result)
	if !result.SecurityComplete || result.Enrollment.Accounts[0].Connectors["codex"] != "enrolled" || len(result.Warnings) != 0 {
		t.Fatalf("status changed for a user-readable file: %+v", result)
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
