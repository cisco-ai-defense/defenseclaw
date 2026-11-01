// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

func TestWindowsClaudeCleanupTransactionUsesCurrentAccountCache(t *testing.T) {
	cache, err := winpath.CurrentUserKnownFolderPath(windows.FOLDERID_LocalAppData)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("LOCALAPPDATA", filepath.Join(t.TempDir(), "foreign-cache"))
	transactionDir, err := windowsManagedClaudeTransactionDir()
	if err != nil || transactionDir != filepath.Join(cache, "DefenseClaw", "claude-settings-teardown") {
		t.Fatalf("transaction directory = %q, %v", transactionDir, err)
	}
	settings := filepath.Join(t.TempDir(), "settings.json")
	launcher := `C:\Users\alice\.local\bin\defenseclaw-hook.exe`
	raw := []byte(`{"hooks":{"PreToolUse":[{"hooks":[{"command":"C:\\Users\\alice\\.local\\bin\\defenseclaw-hook.exe"},{"command":"other-hook"}]}]}}`)
	if err := os.WriteFile(settings, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		t.Fatalf("current token owner: %v", err)
	}
	removed, err := connector.TransformWindowsClaudeSettingsForUninstall(settings, filepath.Join(t.TempDir(), "private-state"), user.User.Sid.String(), func(raw []byte) ([]byte, int, error) {
		return removeWindowsManagedClaudeCommands(raw, launcher)
	})
	if err != nil || removed != 1 {
		t.Fatalf("cleanup removed %d hooks: %v", removed, err)
	}
	after, err := os.ReadFile(settings)
	if err != nil || strings.Contains(string(after), "defenseclaw-hook.exe") || !strings.Contains(string(after), "other-hook") {
		t.Fatalf("settings after cleanup = %s, %v", after, err)
	}
}

func perUserTeardownManifest(connectorName string) enterprisehooks.Manifest {
	return enterprisehooks.Manifest{Version: 1, Targets: []enterprisehooks.ManifestTarget{{
		Connector:    connectorName,
		UserHome:     `C:\Users\alice`,
		SID:          "S-1-5-21-1000000000-2000000000-3000000000-1017",
		AgentVersion: "1.0.88",
	}}}
}

func TestWindowsManagedHooksTeardownPluginConnectorsHaveNoSelector(t *testing.T) {
	t.Setenv(managed.EnterpriseProfileEnv, managed.ProfileStandalone)
	for name, want := range map[string]bool{"copilot": true, "devin": true, "amp": false, "opencode": true, "codex": true} {
		target := windowsManagedHooksTeardownTarget{Connector: name, SID: "S-1-5-21-1-2-3-1017", DataDir: `C:\Users\u\.defenseclaw`}
		if got := windowsManagedHooksTeardownSelectorExpected(target, nil, windowsManagedHooksActivated); got != want {
			t.Fatalf("%s selector expected = %t, want %t", name, got, want)
		}
	}
	identity := windowsManagedHooksTeardownJournal{
		ActivationState: windowsManagedHooksActivated,
		Targets: []windowsManagedHooksTeardownTarget{
			{Connector: "devin", SID: "S-1-5-21-1-2-3-1017", DataDir: `C:\Users\a\.defenseclaw`},
			{Connector: "devin", SID: "S-1-5-21-1-2-3-1018", DataDir: `C:\Users\b\.defenseclaw`},
			{Connector: "amp", SID: "S-1-5-21-1-2-3-1017", DataDir: `C:\Users\a\.defenseclaw`},
		},
		PendingTargets: []windowsManagedHooksTeardownTarget{
			{Connector: "devin", SID: "S-1-5-21-1-2-3-1018", DataDir: `C:\Users\b\.defenseclaw`},
		},
	}
	expected := windowsManagedHooksStandalonePerUserExpected(identity)
	if len(expected) != 1 || len(expected["devin"]) != 1 || expected["devin"][0].SID != "S-1-5-21-1-2-3-1017" {
		t.Fatalf("expected per-user enrollment = %+v", expected)
	}
	identity.ActivationState = windowsManagedHooksNeverActivated
	if got := windowsManagedHooksStandalonePerUserExpected(identity)["devin"]; len(got) != 0 {
		t.Fatalf("never-activated deployment expects enrollment %+v", got)
	}
}

func boolPointerForTest(value bool) *bool { return &value }

func TestWindowsStandaloneUninstallCleansClaudeSettingsWithoutUserSession(t *testing.T) {
	t.Setenv(managed.EnterpriseProfileEnv, managed.ProfileStandalone)
	runtimeDir := useUserCleanupStateDir(t)
	manifest := perUserTeardownManifest("claudecode")
	originalIdentity, originalRemover := enterpriseHookWindowsUserCleanupIdentity, windowsManagedClaudeSettingsRemover
	t.Cleanup(func() {
		enterpriseHookWindowsUserCleanupIdentity, windowsManagedClaudeSettingsRemover = originalIdentity, originalRemover
	})
	enterpriseHookWindowsUserCleanupIdentity = func() error { return nil }
	calls := 0
	windowsManagedClaudeSettingsRemover = func(home, sid string) (int, []string, error) {
		calls++
		if home != manifest.Targets[0].UserHome || sid != manifest.Targets[0].SID {
			t.Fatalf("Claude cleanup target %s %s", home, sid)
		}
		return 29, nil, nil
	}
	for _, purge := range []string{"0", "1"} {
		t.Setenv(windowsManagedHooksPurgeUserStateEnv, purge)
		result := removeWindowsManagedHooksStandalonePerUserRegistrations(context.Background(), runtimeDir, manifest)
		if len(result.Removed) != 1 || result.Removed[0] != "claudecode/"+manifest.Targets[0].SID ||
			len(result.Pending) != 0 || len(result.Failed) != 0 {
			t.Fatalf("purge=%s cleanup result = %+v", purge, result)
		}
	}
	if calls != 2 {
		t.Fatalf("Claude settings cleanup called %d times", calls)
	}
}

// mgmt-p1:GAP-0089: an account enrolled for another connector only can still
// hold a DefenseClaw Claude hook with its own launcher; the uninstall cleans
// and names that settings file too, once per account.
func TestWindowsStandaloneUninstallCleansClaudeSettingsOfAccountsEnrolledForOtherConnectors(t *testing.T) {
	t.Setenv(managed.EnterpriseProfileEnv, managed.ProfileStandalone)
	runtimeDir := useUserCleanupStateDir(t)
	manifest := perUserTeardownManifest("codex")
	second := manifest.Targets[0]
	second.Connector = "copilot"
	manifest.Targets = append(manifest.Targets, second)
	originalIdentity, originalRemover := enterpriseHookWindowsUserCleanupIdentity, windowsManagedClaudeSettingsRemover
	t.Cleanup(func() {
		enterpriseHookWindowsUserCleanupIdentity, windowsManagedClaudeSettingsRemover = originalIdentity, originalRemover
	})
	enterpriseHookWindowsUserCleanupIdentity = func() error { return nil }
	calls := 0
	windowsManagedClaudeSettingsRemover = func(home, sid string) (int, []string, error) {
		calls++
		if home != manifest.Targets[0].UserHome || sid != manifest.Targets[0].SID {
			t.Fatalf("settings cleaned for %s %s", home, sid)
		}
		return 1, nil, nil
	}
	result := removeWindowsManagedHooksStandalonePerUserRegistrations(context.Background(), runtimeDir, manifest)
	want := `removed 1 DefenseClaw hook command(s) from C:\Users\alice\.claude\settings.json`
	if calls != 1 || len(result.SettingsEdited) != 1 || result.SettingsEdited[0] != want {
		t.Fatalf("calls = %d, edited = %q, want one %q", calls, result.SettingsEdited, want)
	}
}

// #1290: the cleanup names each Claude settings file it edited and how many
// commands it removed; #1286: it names each hook left there that still names
// a DefenseClaw launcher, as the settings transaction found it. The exit
// stays a success. A cleanup that cannot read or inspect the file is a
// visible failure, never a silent "nothing left".
func TestWindowsStandaloneUninstallReportsClaudeSettingsEditsAndLeftovers(t *testing.T) {
	t.Setenv(managed.EnterpriseProfileEnv, managed.ProfileStandalone)
	runtimeDir := useUserCleanupStateDir(t)
	manifest := perUserTeardownManifest("claudecode")
	originalIdentity, originalRemover := enterpriseHookWindowsUserCleanupIdentity, windowsManagedClaudeSettingsRemover
	t.Cleanup(func() {
		enterpriseHookWindowsUserCleanupIdentity, windowsManagedClaudeSettingsRemover = originalIdentity, originalRemover
	})
	enterpriseHookWindowsUserCleanupIdentity = func() error { return nil }
	removed := 2
	left := []string{"PreToolUse: a hook command naming defenseclaw-hook (arguments not shown)"}
	var removeErr error
	windowsManagedClaudeSettingsRemover = func(home, sid string) (int, []string, error) {
		if home != manifest.Targets[0].UserHome || sid != manifest.Targets[0].SID {
			t.Fatalf("settings cleaned for %s %s", home, sid)
		}
		return removed, left, removeErr
	}
	settings := `C:\Users\alice\.claude\settings.json`
	result := removeWindowsManagedHooksStandalonePerUserRegistrations(context.Background(), runtimeDir, manifest)
	if len(result.SettingsEdited) != 1 || result.SettingsEdited[0] != "removed 2 DefenseClaw hook command(s) from "+settings {
		t.Fatalf("edited = %q", result.SettingsEdited)
	}
	if len(result.SettingsLeft) != 1 || result.SettingsLeft[0] != settings+": "+left[0] || len(result.Failed) != 0 {
		t.Fatalf("left = %q, failed = %q", result.SettingsLeft, result.Failed)
	}

	// A file with nothing of DefenseClaw's is neither edited nor reported.
	removed, left = 0, nil
	result = removeWindowsManagedHooksStandalonePerUserRegistrations(context.Background(), runtimeDir, manifest)
	if len(result.SettingsEdited) != 0 || len(result.SettingsLeft) != 0 || len(result.Failed) != 0 || len(result.Removed) != 0 {
		t.Fatalf("untouched settings = %+v", result)
	}

	// The settings cannot be read or inspected: the account is a named
	// failure, not a clean result.
	removeErr = errors.New("access denied")
	result = removeWindowsManagedHooksStandalonePerUserRegistrations(context.Background(), runtimeDir, manifest)
	if len(result.Failed) != 1 || !strings.Contains(result.Failed[0], "claudecode/"+manifest.Targets[0].SID) ||
		!strings.Contains(result.Failed[0], "access denied") || len(result.SettingsLeft) != 0 || len(result.Removed) != 0 {
		t.Fatalf("unreadable settings = %+v", result)
	}
}

func TestWindowsStandaloneAdministratorReportsOnlyRemainingClaudeHook(t *testing.T) {
	t.Setenv(managed.EnterpriseProfileEnv, managed.ProfileStandalone)
	runtimeDir := useUserCleanupStateDir(t)
	manifest := perUserTeardownManifest("claudecode")
	originalIdentity, originalSID := enterpriseHookWindowsUserCleanupIdentity, windowsManagedClaudeCurrentUserSID
	originalProbe, originalRemover := windowsManagedClaudeRegistrationProbe, windowsManagedClaudeSettingsRemover
	t.Cleanup(func() {
		enterpriseHookWindowsUserCleanupIdentity, windowsManagedClaudeCurrentUserSID = originalIdentity, originalSID
		windowsManagedClaudeRegistrationProbe, windowsManagedClaudeSettingsRemover = originalProbe, originalRemover
	})
	enterpriseHookWindowsUserCleanupIdentity = func() error { return errors.New("not LocalSystem") }
	windowsManagedClaudeCurrentUserSID = func() (string, error) { return "S-1-5-21-1-2-3-1000", nil }
	present := false
	windowsManagedClaudeRegistrationProbe = func(home, sid string) (bool, []string, error) {
		if home != manifest.Targets[0].UserHome || sid != manifest.Targets[0].SID {
			t.Fatalf("probed %s %s", home, sid)
		}
		return present, nil, nil
	}
	windowsManagedClaudeSettingsRemover = func(string, string) (int, []string, error) {
		t.Fatal("another user's settings were edited")
		return 0, nil, nil
	}
	result := removeWindowsManagedHooksStandalonePerUserRegistrations(context.Background(), runtimeDir, manifest)
	if len(result.Pending) != 0 || len(result.Failed) != 0 {
		t.Fatalf("machine-policy-only enrollment = %+v", result)
	}
	present = true
	result = removeWindowsManagedHooksStandalonePerUserRegistrations(context.Background(), runtimeDir, manifest)
	if len(result.Pending) != 1 || result.Pending[0] != "claudecode/"+manifest.Targets[0].SID || len(result.Failed) != 1 {
		t.Fatalf("another user's legacy hook = %+v", result)
	}
	windowsManagedClaudeCurrentUserSID = func() (string, error) { return manifest.Targets[0].SID, nil }
	windowsManagedClaudeSettingsRemover = func(string, string) (int, []string, error) { return 1, nil, nil }
	result = removeWindowsManagedHooksStandalonePerUserRegistrations(context.Background(), runtimeDir, manifest)
	if len(result.Removed) != 1 || len(result.Pending) != 0 || len(result.Failed) != 0 {
		t.Fatalf("administrator's own legacy hook = %+v", result)
	}
}

// An uninstall that cannot edit another user's settings still reports the
// DefenseClaw hooks the remover would keep there; the real probe finds them
// in a file with nothing removable.
func TestWindowsStandaloneUninstallReportsAnotherUsersUnremovableClaudeHooks(t *testing.T) {
	t.Setenv(managed.EnterpriseProfileEnv, managed.ProfileStandalone)
	t.Setenv("SystemRoot", `C:\Windows`)
	runtimeDir := useUserCleanupStateDir(t)
	manifest := perUserTeardownManifest("claudecode")
	target := manifest.Targets[0]
	originalIdentity, originalSID := enterpriseHookWindowsUserCleanupIdentity, windowsManagedClaudeCurrentUserSID
	originalReader, originalRemover := windowsManagedClaudeUserSettingsReader, windowsManagedClaudeSettingsRemover
	t.Cleanup(func() {
		enterpriseHookWindowsUserCleanupIdentity, windowsManagedClaudeCurrentUserSID = originalIdentity, originalSID
		windowsManagedClaudeUserSettingsReader, windowsManagedClaudeSettingsRemover = originalReader, originalRemover
	})
	enterpriseHookWindowsUserCleanupIdentity = func() error { return errors.New("not LocalSystem") }
	windowsManagedClaudeCurrentUserSID = func() (string, error) { return "S-1-5-21-1-2-3-1000", nil }
	edited := windowsClaudeGuardFixture(filepath.Join(target.UserHome, ".local", "bin", "defenseclaw-hook.exe"), "claudecode", "0")
	raw, err := json.Marshal(map[string]any{"hooks": map[string]any{"Stop": []any{map[string]any{"hooks": []any{edited}}}}})
	if err != nil {
		t.Fatal(err)
	}
	windowsManagedClaudeUserSettingsReader = func(string, string) ([]byte, error) { return raw, nil }
	windowsManagedClaudeSettingsRemover = func(string, string) (int, []string, error) {
		t.Fatal("another user's settings were edited")
		return 0, nil, nil
	}
	result := removeWindowsManagedHooksStandalonePerUserRegistrations(context.Background(), runtimeDir, manifest)
	want := filepath.Join(target.UserHome, ".claude", "settings.json") + ": Stop: a hook command naming defenseclaw-hook (arguments not shown)"
	if len(result.Pending) != 0 || len(result.Failed) != 0 || len(result.SettingsLeft) != 1 || result.SettingsLeft[0] != want {
		t.Fatalf("unremovable leftover = %+v", result)
	}
}

// Finalize removes users' registrations and reports the outcome only for
// the standalone profile; Secure Client finalize never runs it.
func TestCompleteWindowsManagedHooksTeardownUserCleanupIsStandaloneOnly(t *testing.T) {
	original := windowsManagedHooksStandaloneUserRegistrationRemover
	originalACPCopies := windowsManagedHooksStandaloneACPUserCopies
	t.Cleanup(func() {
		windowsManagedHooksStandaloneUserRegistrationRemover = original
		windowsManagedHooksStandaloneACPUserCopies = originalACPCopies
	})
	windowsManagedHooksStandaloneACPUserCopies = func() ([]enterprisehooks.WindowsACPUserCopy, error) { return nil, nil }
	calls, pendingSID := 0, userCleanupSIDB
	windowsManagedHooksStandaloneUserRegistrationRemover = func(
		_ context.Context,
		runtimeDir string,
		manifest enterprisehooks.Manifest,
	) enterpriseHookUserCleanupResult {
		calls++
		if runtimeDir != `C:\ProgramData\DefenseClaw\runtime` || len(manifest.Targets) != 1 {
			t.Fatalf("remover got %s %+v", runtimeDir, manifest)
		}
		return enterpriseHookUserCleanupResult{
			Removed: []string{"devin/" + userCleanupSIDA, "amp/" + userCleanupSIDA},
			Pending: []string{"hermes/" + pendingSID},
		}
	}
	manifest := perUserTeardownManifest("devin")
	manifest.Targets[0].UserHome = t.TempDir()
	if err := os.Mkdir(filepath.Join(manifest.Targets[0].UserHome, ".defenseclaw"), 0o700); err != nil {
		t.Fatal(err)
	}

	t.Setenv(managed.EnterpriseProfileEnv, "")
	var report windowsManagedHooksTeardownReport
	completeWindowsManagedHooksTeardownUserCleanup(&report, `C:\ProgramData\DefenseClaw\runtime`, manifest)
	if calls != 0 || report.UserRegistrationsRemoved != 0 {
		t.Fatalf("Secure Client finalize ran the per-user cleanup: calls=%d", calls)
	}

	t.Setenv(managed.EnterpriseProfileEnv, managed.ProfileStandalone)
	completeWindowsManagedHooksTeardownUserCleanup(&report, `C:\ProgramData\DefenseClaw\runtime`, manifest)
	if calls != 1 || report.UserRegistrationsRemoved != 2 ||
		strings.Join(report.UserRegistrationsPending, ",") != "hermes/"+userCleanupSIDB {
		t.Fatalf("standalone finalize report = %+v", report)
	}
	body, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	// Without a purge, the per-user folder each enrolled account keeps is named.
	if len(report.UserStateRemaining) != 1 || !strings.HasSuffix(report.UserStateRemaining[0], `\.defenseclaw`) {
		t.Fatalf("remaining per-user state = %v", report.UserStateRemaining)
	}
	for _, field := range []string{`"user_registrations_removed":2`, `"user_registrations_pending":["hermes/`, `"user_state_remaining":[`} {
		if !strings.Contains(string(body), field) {
			t.Fatalf("report JSON %s lacks %s", body, field)
		}
	}
	if strings.Contains(string(body), "user_registrations_failed") {
		t.Fatalf("empty failure list serialized: %s", body)
	}

	// A purge removes each folder as LocalSystem, whether or not the account
	// is signed in, and names each one that stays with the reason.
	// GAP-1567: only a purge removes the Cursor hook tombstone.
	originalCursor := windowsManagedHooksStandaloneCursorTombstonePurger
	t.Cleanup(func() { windowsManagedHooksStandaloneCursorTombstonePurger = originalCursor })
	cursorPurges := 0
	windowsManagedHooksStandaloneCursorTombstonePurger = func() error {
		cursorPurges++
		return nil
	}
	completeWindowsManagedHooksTeardownUserCleanup(&report, `C:\ProgramData\DefenseClaw\runtime`, manifest)
	if cursorPurges != 0 {
		t.Fatal("an uninstall without purge removed the Cursor hook tombstone")
	}
	t.Setenv(windowsManagedHooksPurgeUserStateEnv, "1")
	originalIdentity, originalPurger := enterpriseHookWindowsUserCleanupIdentity, windowsManagedHooksStandaloneUserStatePurger
	originalBinaries := windowsManagedHooksStandaloneUserBinariesPurger
	t.Cleanup(func() {
		enterpriseHookWindowsUserCleanupIdentity, windowsManagedHooksStandaloneUserStatePurger = originalIdentity, originalPurger
		windowsManagedHooksStandaloneUserBinariesPurger = originalBinaries
	})
	enterpriseHookWindowsUserCleanupIdentity = func() error { return nil }
	purged, binaries := 0, 0
	windowsManagedHooksStandaloneUserStatePurger = func(home, sid, _ string) error {
		if purged++; home != manifest.Targets[0].UserHome || sid != manifest.Targets[0].SID {
			t.Fatalf("purged %s %s", home, sid)
		}
		return nil
	}
	// The account's per-user binaries in %USERPROFILE%\.local\bin go after
	// its folder.
	windowsManagedHooksStandaloneUserBinariesPurger = func(home, sid string) ([]string, error) {
		if binaries++; binaries != purged || home != manifest.Targets[0].UserHome || sid != manifest.Targets[0].SID {
			t.Fatalf("binaries purge %d for %s %s after %d state purge(s)", binaries, home, sid, purged)
		}
		return []string{filepath.Join(home, ".local", "bin", "defenseclaw.cmd")}, nil
	}
	completeWindowsManagedHooksTeardownUserCleanup(&report, `C:\ProgramData\DefenseClaw\runtime`, manifest)
	if purged != 1 || binaries != 1 || len(report.UserStateRemaining) != 0 {
		t.Fatalf("purge ran %d/%d time(s), remaining %v", purged, binaries, report.UserStateRemaining)
	}
	if cursorPurges != 1 {
		t.Fatalf("the purge removed the Cursor hook tombstone %d time(s)", cursorPurges)
	}
	windowsManagedHooksStandaloneCursorTombstonePurger = func() error { return errors.New("access denied") }
	completeWindowsManagedHooksTeardownUserCleanup(&report, `C:\ProgramData\DefenseClaw\runtime`, manifest)
	if len(report.UserRegistrationsFailed) == 0 ||
		!strings.Contains(strings.Join(report.UserRegistrationsFailed, ";"), "cursor/machine policy: the Cursor hook tombstone") {
		t.Fatalf("a tombstone that stays is not named: %v", report.UserRegistrationsFailed)
	}
	windowsManagedHooksStandaloneCursorTombstonePurger = func() error { return nil }
	// The report names each account whose data went.
	if len(report.UserStatePurged) != 1 || !strings.HasSuffix(report.UserStatePurged[0], `\.defenseclaw`+windowsManagedHooksPurgedBinariesMarker+"defenseclaw.cmd") {
		t.Fatalf("purged accounts = %v", report.UserStatePurged)
	}
	if body, _ := json.Marshal(report); !strings.Contains(string(body), `"user_state_purged":[`) {
		t.Fatalf("report JSON %s lacks user_state_purged", body)
	}
	// A binaries purge that fails names the account as not purged.
	windowsManagedHooksStandaloneUserBinariesPurger = func(string, string) ([]string, error) {
		return nil, errors.New("the user Path entry stays: its registry hive is not loaded while it is signed out")
	}
	purged = 0
	completeWindowsManagedHooksTeardownUserCleanup(&report, `C:\ProgramData\DefenseClaw\runtime`, manifest)
	if len(report.UserStatePurged) != 0 || len(report.UserStateRemaining) != 1 ||
		!strings.Contains(report.UserStateRemaining[0], "registry hive is not loaded") {
		t.Fatalf("failed binaries purge: purged %v remaining %v", report.UserStatePurged, report.UserStateRemaining)
	}
	// GAP-2231: a signed-out account's data and binaries go, only its user
	// Path entry stays (its hive is not loaded): the account is purged and
	// the entry names the documented signed-out reason, not a failure.
	windowsManagedHooksStandaloneUserBinariesPurger = func(home, _ string) ([]string, error) {
		return []string{filepath.Join(home, ".local", "bin", "defenseclaw.cmd"), filepath.Join(home, ".local", "bin")},
			errors.Join(errors.New(`enterprise hooks: the user Path entry stays`), enterprisehooks.ErrWindowsUserHiveNotLoaded)
	}
	completeWindowsManagedHooksTeardownUserCleanup(&report, `C:\ProgramData\DefenseClaw\runtime`, manifest)
	if len(report.UserStatePurged) != 1 || len(report.UserStateRemaining) != 1 ||
		!strings.HasSuffix(report.UserStatePurged[0], windowsManagedHooksPurgedBinariesMarker+"defenseclaw.cmd, the emptied folder") ||
		!strings.HasSuffix(report.UserStateRemaining[0], `\.defenseclaw: `+windowsManagedHooksSignedOutPathEntryReason) {
		t.Fatalf("signed-out Path entry: purged %v remaining %v", report.UserStatePurged, report.UserStateRemaining)
	}
	windowsManagedHooksStandaloneUserBinariesPurger = func(string, string) ([]string, error) { return nil, nil }
	purged = 1
	// An account whose registrations stayed keeps the folder with its
	// connector_backups.
	pendingSID = userCleanupSIDA
	completeWindowsManagedHooksTeardownUserCleanup(&report, `C:\ProgramData\DefenseClaw\runtime`, manifest)
	if purged != 1 || len(report.UserStateRemaining) != 1 || !strings.Contains(report.UserStateRemaining[0], "connector_backups") {
		t.Fatalf("purge with registrations left ran %d time(s), remaining %v", purged, report.UserStateRemaining)
	}
	pendingSID = userCleanupSIDB
	windowsManagedHooksStandaloneUserStatePurger = func(string, string, string) error {
		return errors.New("remove foreign-hook-sessions: access denied")
	}
	completeWindowsManagedHooksTeardownUserCleanup(&report, `C:\ProgramData\DefenseClaw\runtime`, manifest)
	if len(report.UserStateRemaining) != 1 || !strings.HasSuffix(report.UserStateRemaining[0], `\.defenseclaw: remove foreign-hook-sessions: access denied`) {
		t.Fatalf("failed purge remaining = %v", report.UserStateRemaining)
	}
	enterpriseHookWindowsUserCleanupIdentity = func() error { return errors.New("not LocalSystem") }
	completeWindowsManagedHooksTeardownUserCleanup(&report, `C:\ProgramData\DefenseClaw\runtime`, manifest)
	if len(report.UserStateRemaining) != 1 || !strings.HasSuffix(report.UserStateRemaining[0], ": the uninstall did not run as LocalSystem") {
		t.Fatalf("remaining without LocalSystem = %v", report.UserStateRemaining)
	}
}

// Finalize removes the users' registrations before the journal records the
// phase finalized, so an uninstall interrupted during that cleanup, or one
// failing before it, stays prepared and its rerun runs finalize again.
func TestFinalizeWindowsManagedHooksTeardownCleansUpUsersWhilePrepared(t *testing.T) {
	t.Setenv(managed.EnterpriseProfileEnv, managed.ProfileStandalone)
	t.Setenv(windowsManagedHooksPurgeUserStateEnv, "")
	originalMachine, originalWriter, originalRemover := windowsManagedHooksTeardownStandaloneMachineFinalizer,
		windowsManagedHooksTeardownJournalWriter, windowsManagedHooksStandaloneUserRegistrationRemover
	t.Cleanup(func() {
		windowsManagedHooksTeardownStandaloneMachineFinalizer, windowsManagedHooksTeardownJournalWriter,
			windowsManagedHooksStandaloneUserRegistrationRemover = originalMachine, originalWriter, originalRemover
	})
	// The journal writer needs an administrator-owned folder; the phase it
	// would write stands in for the journal on disk.
	written := "prepared"
	windowsManagedHooksTeardownJournalWriter = func(_ string, journal windowsManagedHooksTeardownJournal) error {
		written = journal.Phase
		return nil
	}
	cleanedUpAt := ""
	windowsManagedHooksStandaloneUserRegistrationRemover = func(context.Context, string, enterprisehooks.Manifest) enterpriseHookUserCleanupResult {
		cleanedUpAt = written
		return enterpriseHookUserCleanupResult{}
	}
	machineErr := errors.New("finalize standalone hook runtime directories: access denied")
	windowsManagedHooksTeardownStandaloneMachineFinalizer = func() error { return machineErr }
	finalize := func() error {
		var report windowsManagedHooksTeardownReport
		_, err := finalizeWindowsManagedHooksTeardown(windowsManagedHooksTeardownJournal{Phase: "prepared"},
			"journal.json", &report, `C:\ProgramData\DefenseClaw\runtime`, perUserTeardownManifest("devin"))
		return err
	}
	if err := finalize(); !errors.Is(err, machineErr) || written != "prepared" || cleanedUpAt != "" {
		t.Fatalf("failed finalize: err=%v phase=%s cleanup at %q", err, written, cleanedUpAt)
	}
	windowsManagedHooksTeardownStandaloneMachineFinalizer = func() error { return nil }
	if err := finalize(); err != nil || cleanedUpAt != "prepared" || written != "finalized" {
		t.Fatalf("finalize: err=%v phase=%s, users cleaned up at phase %q", err, written, cleanedUpAt)
	}
}

func TestRemoveEmptyWindowsClaudeManagedSettingsFolders(t *testing.T) {
	programFiles := t.TempDir()
	dropIns := filepath.Join(programFiles, "ClaudeCode", "managed-settings.d")
	if err := os.MkdirAll(dropIns, 0o700); err != nil {
		t.Fatal(err)
	}
	kept := filepath.Join(programFiles, "ClaudeCode", "managed-settings.json")
	if err := os.WriteFile(kept, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	removeEmptyWindowsClaudeManagedSettingsFolders(programFiles)
	if _, err := os.Lstat(dropIns); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the empty managed-settings.d stayed: %v", err)
	}
	if _, err := os.Lstat(kept); err != nil {
		t.Fatalf("a ClaudeCode folder that holds the administrator's settings changed: %v", err)
	}
	if err := os.Remove(kept); err != nil {
		t.Fatal(err)
	}
	removeEmptyWindowsClaudeManagedSettingsFolders(programFiles)
	if _, err := os.Lstat(filepath.Join(programFiles, "ClaudeCode")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the empty ClaudeCode folder stayed: %v", err)
	}
}

// GAP-1765: finalize revokes the gateway's AI-discovery read ACEs before it
// removes users' registrations, and names a revoke failure.
func TestCompleteWindowsManagedHooksTeardownUserCleanupRevokesInventoryACEsFirst(t *testing.T) {
	originalRemover := windowsManagedHooksStandaloneUserRegistrationRemover
	originalRevoker := windowsManagedHooksStandaloneInventoryACERevoker
	t.Cleanup(func() {
		windowsManagedHooksStandaloneUserRegistrationRemover = originalRemover
		windowsManagedHooksStandaloneInventoryACERevoker = originalRevoker
	})
	var order []string
	windowsManagedHooksStandaloneInventoryACERevoker = func(manifest enterprisehooks.Manifest) error {
		order = append(order, "revoke")
		if len(manifest.Targets) != 1 {
			t.Fatalf("revoker got %+v", manifest)
		}
		return errors.New("set DACL: access denied")
	}
	windowsManagedHooksStandaloneUserRegistrationRemover = func(
		_ context.Context,
		_ string,
		_ enterprisehooks.Manifest,
	) enterpriseHookUserCleanupResult {
		order = append(order, "remove")
		return enterpriseHookUserCleanupResult{Removed: []string{"amp/" + userCleanupSIDA}}
	}
	manifest := perUserTeardownManifest("amp")
	manifest.Targets[0].UserHome = t.TempDir()
	t.Setenv(managed.EnterpriseProfileEnv, managed.ProfileStandalone)
	var report windowsManagedHooksTeardownReport
	completeWindowsManagedHooksTeardownUserCleanup(&report, `C:\ProgramData\DefenseClaw\runtime`, manifest)
	if strings.Join(order, ",") != "revoke,remove" || report.UserRegistrationsRemoved != 1 {
		t.Fatalf("order %v report %+v", order, report)
	}
	if len(report.UserRegistrationsFailed) != 1 ||
		!strings.Contains(report.UserRegistrationsFailed[0], "read access on users' agent folders: set DACL: access denied") {
		t.Fatalf("failed = %v", report.UserRegistrationsFailed)
	}
}

// A purge removes the managed ACP folder (token copies and editor contract
// locks) of every account that still has one, whether it is signed out,
// revoked or enrolled for ACP only, and names one it could not remove; an
// uninstall without purge leaves them (GAP-0773).
func TestWindowsManagedHooksTeardownPurgeRemovesEveryAccountsACPCopies(t *testing.T) {
	originalRemover := windowsManagedHooksStandaloneUserRegistrationRemover
	originalCopies, originalACPPurger := windowsManagedHooksStandaloneACPUserCopies, windowsManagedHooksStandaloneACPUserPurger
	originalIdentity, originalCursor := enterpriseHookWindowsUserCleanupIdentity, windowsManagedHooksStandaloneCursorTombstonePurger
	originalFloor := windowsManagedHooksStandaloneFloorPurger
	t.Cleanup(func() {
		windowsManagedHooksStandaloneUserRegistrationRemover = originalRemover
		windowsManagedHooksStandaloneACPUserCopies, windowsManagedHooksStandaloneACPUserPurger = originalCopies, originalACPPurger
		enterpriseHookWindowsUserCleanupIdentity, windowsManagedHooksStandaloneCursorTombstonePurger = originalIdentity, originalCursor
		windowsManagedHooksStandaloneFloorPurger = originalFloor
	})
	windowsManagedHooksStandaloneUserRegistrationRemover = func(context.Context, string, enterprisehooks.Manifest) enterpriseHookUserCleanupResult {
		return enterpriseHookUserCleanupResult{}
	}
	enterpriseHookWindowsUserCleanupIdentity = func() error { return nil }
	windowsManagedHooksStandaloneCursorTombstonePurger = func() error { return nil }
	windowsManagedHooksStandaloneFloorPurger = func() error { return nil }
	const signedOut, acpOnly = "S-1-5-21-1-2-3-3908", "S-1-5-21-1-2-3-3911"
	windowsManagedHooksStandaloneACPUserCopies = func() ([]enterprisehooks.WindowsACPUserCopy, error) {
		return []enterprisehooks.WindowsACPUserCopy{
			{SID: signedOut, Home: `C:\Users\dcad-w2w1`},
			{SID: acpOnly, Home: `C:\Users\odd`},
		}, nil
	}
	var purged []string
	windowsManagedHooksStandaloneACPUserPurger = func(home, sid string) error {
		purged = append(purged, sid)
		if sid == acpOnly {
			return errors.New("access denied")
		}
		return nil
	}
	t.Setenv(managed.EnterpriseProfileEnv, managed.ProfileStandalone)
	manifest := enterprisehooks.Manifest{Version: 1}
	var report windowsManagedHooksTeardownReport
	completeWindowsManagedHooksTeardownUserCleanup(&report, `C:\ProgramData\DefenseClaw\runtime`, manifest)
	if len(purged) != 0 {
		t.Fatalf("an uninstall without purge removed ACP copies: %v", purged)
	}
	t.Setenv(windowsManagedHooksPurgeUserStateEnv, "1")
	completeWindowsManagedHooksTeardownUserCleanup(&report, `C:\ProgramData\DefenseClaw\runtime`, manifest)
	if strings.Join(purged, ",") != signedOut+","+acpOnly {
		t.Fatalf("purge removed the ACP copies of %v", purged)
	}
	if len(report.UserStatePurged) != 1 || report.UserStatePurged[0] != signedOut+`: C:\Users\dcad-w2w1\.defenseclaw\acp` {
		t.Fatalf("purged = %v", report.UserStatePurged)
	}
	if len(report.UserStateRemaining) != 1 || !strings.HasPrefix(report.UserStateRemaining[0], acpOnly+`: C:\Users\odd\.defenseclaw\acp: access denied`) {
		t.Fatalf("remaining = %v", report.UserStateRemaining)
	}
}

// Uninstall cleans every per-user registration the guardian made or still
// owes, as each user; when an interactive administrator cannot act as another
// user, every registration still present is reported.
func TestRemoveWindowsManagedHooksStandalonePerUserRegistrationsCoversEveryRecordedUser(t *testing.T) {
	dataDir := useUserCleanupStateDir(t)
	homeA, homeB := filepath.Join(t.TempDir(), "a"), filepath.Join(t.TempDir(), "b")
	writeUserCleanupAuthorization(t, dataDir,
		userCleanupRow("devin", userCleanupSIDA, homeA),
		userCleanupRow("codex", userCleanupSIDA, homeA),
	)
	if err := saveEnterpriseHookUserCleanups(dataDir, []enterpriseHookUserCleanup{{
		Connector: "amp", SID: userCleanupSIDB, UserHome: homeB, RecordedAt: "r",
		Attempts: 3, LastAttemptAt: time.Now().UTC().Format(time.RFC3339Nano), LastError: "earlier",
	}}, time.Now()); err != nil {
		t.Fatal(err)
	}
	manifest := enterprisehooks.Manifest{Version: 1, Targets: []enterprisehooks.ManifestTarget{
		{Connector: "opencode", SID: userCleanupSIDB, UserHome: homeB},
		{Connector: "hermes", SID: userCleanupSIDB, UserHome: homeB, Deferred: true},
	}}
	originalIdentity, originalAttempt := enterpriseHookWindowsUserCleanupIdentity, enterpriseHookWindowsUserCleanupAttempt
	t.Cleanup(func() {
		enterpriseHookWindowsUserCleanupIdentity, enterpriseHookWindowsUserCleanupAttempt = originalIdentity, originalAttempt
	})
	var attempted []string
	enterpriseHookWindowsUserCleanupAttempt = func(_ context.Context, entry enterpriseHookUserCleanup) (enterpriseHookUserCleanupOutcome, error) {
		attempted = append(attempted, enterpriseHookUserCleanupLabel(entry))
		if entry.SID == userCleanupSIDB && entry.Connector == "opencode" {
			return enterpriseHookUserCleanupPending, nil
		}
		return enterpriseHookUserCleanupDone, nil
	}
	enterpriseHookWindowsUserCleanupIdentity = func() error { return nil }
	originalPresent := windowsManagedHooksStandaloneRegistrationPresent
	t.Cleanup(func() { windowsManagedHooksStandaloneRegistrationPresent = originalPresent })
	registrationsPresent := func(enterprisehooks.ManifestTarget) (bool, error) { return true, nil }
	windowsManagedHooksStandaloneRegistrationPresent = registrationsPresent
	// The Claude settings cleanup runs for every enrolled account
	// (mgmt-p1:GAP-0089), here the opencode/hermes account B. These fixture
	// homes hold no Claude settings, and they are owned by whoever runs the
	// test: a CI runner account is not a trusted profile owner for B, so
	// the real profile check failed the Claude probe there and added a
	// Failed row (BATCH25 Windows Go shard pk1). Record the Claude calls
	// instead; the Claude cleanup itself has its own tests.
	originalRemover, originalProbe := windowsManagedClaudeSettingsRemover, windowsManagedClaudeRegistrationProbe
	t.Cleanup(func() {
		windowsManagedClaudeSettingsRemover, windowsManagedClaudeRegistrationProbe = originalRemover, originalProbe
	})
	var claudeCleaned, claudeProbed []string
	windowsManagedClaudeSettingsRemover = func(_, sid string) (int, []string, error) {
		claudeCleaned = append(claudeCleaned, sid)
		return 0, nil, nil
	}
	windowsManagedClaudeRegistrationProbe = func(_, sid string) (bool, []string, error) {
		claudeProbed = append(claudeProbed, sid)
		return false, nil, nil
	}

	result := removeWindowsManagedHooksStandalonePerUserRegistrations(context.Background(), dataDir, manifest)
	if strings.Join(claudeCleaned, ",") != userCleanupSIDB {
		t.Fatalf("Claude settings cleaned for %v, want the enrolled account %s once", claudeCleaned, userCleanupSIDB)
	}
	want := "amp/" + userCleanupSIDB + ",devin/" + userCleanupSIDA + ",opencode/" + userCleanupSIDB
	if strings.Join(attempted, ",") != want {
		t.Fatalf("attempted %v, want %s (no codex, no never-protected deferred row, backoff ignored)", attempted, want)
	}
	if len(result.Removed) != 2 || strings.Join(result.Pending, ",") != "opencode/"+userCleanupSIDB || len(result.Failed) != 0 {
		t.Fatalf("result = %+v", result)
	}

	// GAP-1795: a deferred row of a user an earlier install enrolled (its
	// DefenseClaw data folder is still there) may still hold that install's
	// registrations, so it is attempted and reported, not skipped.
	if err := os.MkdirAll(filepath.Join(homeB, ".defenseclaw"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, probe := range []struct {
		present bool
		err     error
	}{{true, nil}, {false, errors.New("unreadable")}} {
		windowsManagedHooksStandaloneRegistrationPresent = func(enterprisehooks.ManifestTarget) (bool, error) {
			return probe.present, probe.err
		}
		attempted = nil
		result = removeWindowsManagedHooksStandalonePerUserRegistrations(context.Background(), dataDir, manifest)
		if want := "amp/" + userCleanupSIDB + ",devin/" + userCleanupSIDA + ",hermes/" + userCleanupSIDB + ",opencode/" + userCleanupSIDB; strings.Join(attempted, ",") != want {
			t.Fatalf("probe %+v: attempted %v, want %s", probe, attempted, want)
		}
	}
	// GAP-2023: an earlier uninstall already removed that user's
	// registration (the data folder stays), so there is nothing to report.
	// GAP-2098: the enrolled OpenCode row of the signed-out user holds no
	// plugin either, so it is attempted but not reported as pending.
	windowsManagedHooksStandaloneRegistrationPresent = func(enterprisehooks.ManifestTarget) (bool, error) { return false, nil }
	attempted = nil
	result = removeWindowsManagedHooksStandalonePerUserRegistrations(context.Background(), dataDir, manifest)
	if want := "amp/" + userCleanupSIDB + ",devin/" + userCleanupSIDA + ",opencode/" + userCleanupSIDB; strings.Join(attempted, ",") != want {
		t.Fatalf("no registration left: attempted %v, want %s", attempted, want)
	}
	if len(result.Pending) != 0 {
		t.Fatalf("no registration left: pending %v", result.Pending)
	}
	windowsManagedHooksStandaloneRegistrationPresent = registrationsPresent
	if err := os.RemoveAll(filepath.Join(homeB, ".defenseclaw")); err != nil {
		t.Fatal(err)
	}

	attempted = nil
	enterpriseHookWindowsUserCleanupIdentity = func() error {
		return errors.New("per-user Windows hook mutation requires the LocalSystem guardian service")
	}
	result = removeWindowsManagedHooksStandalonePerUserRegistrations(context.Background(), dataDir, manifest)
	if len(attempted) != 0 || len(result.Pending) != 3 || len(result.Failed) != 1 ||
		!strings.Contains(result.Failed[0], "LocalSystem") {
		t.Fatalf("non-LocalSystem uninstall: attempted=%v result=%+v", attempted, result)
	}
	if len(claudeProbed) == 0 || claudeProbed[len(claudeProbed)-1] != userCleanupSIDB {
		t.Fatalf("non-LocalSystem uninstall probed the Claude settings of %v, want the enrolled account %s", claudeProbed, userCleanupSIDB)
	}
	windowsManagedHooksStandaloneRegistrationPresent = func(enterprisehooks.ManifestTarget) (bool, error) { return false, nil }
	result = removeWindowsManagedHooksStandalonePerUserRegistrations(context.Background(), dataDir, manifest)
	if len(result.Pending) != 0 || len(result.Failed) != 0 {
		t.Fatalf("non-LocalSystem uninstall with no registrations = %+v", result)
	}
	windowsManagedHooksStandaloneRegistrationPresent = registrationsPresent

	// The standalone profile's teardown accepts every per-user connector,
	// Secure Client's only GitHub Copilot.
	t.Run("teardown targets", func(t *testing.T) {
		t.Setenv(managed.EnterpriseProfileEnv, "")
		if _, _, _, _, err := windowsManagedHooksTeardownTargets(perUserTeardownManifest("devin")); err == nil ||
			!strings.Contains(err.Error(), "does not support connector") {
			t.Fatalf("Secure Client teardown accepted devin: %v", err)
		}
		if targets, _, _, _, err := windowsManagedHooksTeardownTargets(perUserTeardownManifest("copilot")); err != nil || len(targets) != 1 {
			t.Fatalf("Secure Client teardown refused copilot: targets=%v err=%v", targets, err)
		}
		t.Setenv(managed.EnterpriseProfileEnv, managed.ProfileStandalone)
		for _, name := range []string{"copilot", "devin", "amp"} {
			targets, claude, codex, cursor, err := windowsManagedHooksTeardownTargets(perUserTeardownManifest(name))
			if err != nil || len(targets) != 1 || len(claude)+len(codex)+len(cursor) != 0 {
				t.Fatalf("%s: targets=%v err=%v", name, targets, err)
			}
		}
		if _, _, _, _, err := windowsManagedHooksTeardownTargets(perUserTeardownManifest("openclaw")); err == nil {
			t.Fatal("standalone teardown accepted openclaw")
		}
	})

	// The kept per-user enrollment follows the manifest's enabled rows.
	t.Run("enrollment keep", func(t *testing.T) {
		manifest := enterprisehooks.Manifest{Version: 1, Targets: []enterprisehooks.ManifestTarget{
			{Connector: "devin", SID: "S-1-5-21-1-2-3-1017"},
			{Connector: "hermes", SID: "S-1-5-21-1-2-3-1018", Enabled: boolPointerForTest(false)},
		}}
		keep := windowsStandalonePerUserEnrollmentKeep(manifest)
		if !keep("devin", "s-1-5-21-1-2-3-1017") {
			t.Fatal("enabled row not kept")
		}
		if keep("hermes", "S-1-5-21-1-2-3-1018") || keep("devin", "S-1-5-21-1-2-3-1018") || keep("copilot", "S-1-5-21-1-2-3-1017") {
			t.Fatal("unauthorized SID kept")
		}
	})
}

// sidecar-r107:GAP-0007: a finished settings transaction leaves its folder
// holding only the empty protocol lock (the lane found exactly that in the
// LocalSystem profile). The committed uninstall removes that folder, and the
// DefenseClaw folder above it once empty, as it does the lifecycle lock
// (sidecar-aispg-retest:GAP-0022).
func TestWindowsUninstallRemovesClaudeCleanupTransactionLeftover(t *testing.T) {
	cache := t.TempDir()
	parent := filepath.Join(cache, "DefenseClaw")
	stateDir := filepath.Join(parent, "claude-settings-teardown")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, windowsManagedClaudeTransactionLock), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := removeWindowsManagedClaudeTransactionFolder(stateDir); err != nil {
		t.Fatalf("remove transaction leftover: %v", err)
	}
	for _, gone := range []string{stateDir, parent} {
		if _, err := os.Lstat(gone); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s stays after the uninstall: %v", gone, err)
		}
	}
	if _, err := os.Lstat(cache); err != nil {
		t.Fatalf("the cache folder itself went: %v", err)
	}
	// A second uninstall, or one whose guardian never edited settings, finds
	// nothing.
	if err := removeWindowsManagedClaudeTransactionFolder(stateDir); err != nil {
		t.Fatalf("absent transaction folder: %v", err)
	}
}

// What is not a finished transaction's lone empty lock stays: receipts, a
// lock with content, a lock a running transaction holds open, and a link.
// A DefenseClaw folder that holds anything else stays too.
func TestWindowsUninstallKeepsClaudeCleanupTransactionFolderInUse(t *testing.T) {
	newFolder := func(t *testing.T, lock []byte) (string, string) {
		t.Helper()
		parent := filepath.Join(t.TempDir(), "DefenseClaw")
		dir := filepath.Join(parent, "claude-settings-teardown")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, windowsManagedClaudeTransactionLock), lock, 0o600); err != nil {
			t.Fatal(err)
		}
		return parent, dir
	}
	assertKept := func(t *testing.T, dir string) {
		t.Helper()
		if err := removeWindowsManagedClaudeTransactionFolder(dir); err == nil {
			t.Fatal("the transaction folder was removed")
		}
		if _, err := os.Lstat(filepath.Join(dir, windowsManagedClaudeTransactionLock)); err != nil {
			t.Fatalf("the lock went: %v", err)
		}
	}

	t.Run("receipts", func(t *testing.T) {
		_, dir := newFolder(t, nil)
		if err := os.WriteFile(filepath.Join(dir, "receipt.json"), []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
		assertKept(t, dir)
	})
	t.Run("lock with content", func(t *testing.T) {
		_, dir := newFolder(t, []byte("x"))
		assertKept(t, dir)
	})
	t.Run("lock held open", func(t *testing.T) {
		_, dir := newFolder(t, nil)
		name, err := windows.UTF16PtrFromString(filepath.Join(dir, windowsManagedClaudeTransactionLock))
		if err != nil {
			t.Fatal(err)
		}
		// The connector's own sharing: read and write, no delete.
		handle, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE,
			windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
		if err != nil {
			t.Fatal(err)
		}
		assertKept(t, dir)
		if err := windows.CloseHandle(handle); err != nil {
			t.Fatal(err)
		}
		if err := removeWindowsManagedClaudeTransactionFolder(dir); err != nil {
			t.Fatalf("released lock: %v", err)
		}
	})
	t.Run("other DefenseClaw content", func(t *testing.T) {
		parent, dir := newFolder(t, nil)
		other := filepath.Join(parent, "other.txt")
		if err := os.WriteFile(other, []byte("kept"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := removeWindowsManagedClaudeTransactionFolder(dir); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Lstat(dir); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("transaction folder stays: %v", err)
		}
		if _, err := os.Lstat(other); err != nil {
			t.Fatalf("other DefenseClaw content went: %v", err)
		}
	})
	t.Run("link", func(t *testing.T) {
		_, target := newFolder(t, nil)
		link := filepath.Join(t.TempDir(), "claude-settings-teardown")
		if err := os.Symlink(target, link); err != nil {
			t.Skipf("symbolic links need a privilege this account lacks: %v", err)
		}
		if err := removeWindowsManagedClaudeTransactionFolder(link); err == nil {
			t.Fatal("a link was treated as the transaction folder")
		}
		if _, err := os.Lstat(filepath.Join(target, windowsManagedClaudeTransactionLock)); err != nil {
			t.Fatalf("the link target's lock went: %v", err)
		}
	})
}

// The standalone finalize removes the leftover with and without purge and
// never fails on it; Secure Client finalize does not run it.
func TestCompleteWindowsManagedHooksTeardownUserCleanupRemovesClaudeTransactionLeftover(t *testing.T) {
	originalRemover := windowsManagedHooksStandaloneUserRegistrationRemover
	originalACPCopies := windowsManagedHooksStandaloneACPUserCopies
	originalLeftover := windowsManagedClaudeTransactionLeftoverRemover
	originalFloor := windowsManagedHooksStandaloneFloorPurger
	originalCursor := windowsManagedHooksStandaloneCursorTombstonePurger
	originalIdentity := enterpriseHookWindowsUserCleanupIdentity
	t.Cleanup(func() {
		windowsManagedHooksStandaloneUserRegistrationRemover = originalRemover
		windowsManagedHooksStandaloneACPUserCopies = originalACPCopies
		windowsManagedClaudeTransactionLeftoverRemover = originalLeftover
		windowsManagedHooksStandaloneFloorPurger = originalFloor
		windowsManagedHooksStandaloneCursorTombstonePurger = originalCursor
		enterpriseHookWindowsUserCleanupIdentity = originalIdentity
	})
	windowsManagedHooksStandaloneUserRegistrationRemover = func(context.Context, string, enterprisehooks.Manifest) enterpriseHookUserCleanupResult {
		return enterpriseHookUserCleanupResult{}
	}
	windowsManagedHooksStandaloneACPUserCopies = func() ([]enterprisehooks.WindowsACPUserCopy, error) { return nil, nil }
	windowsManagedHooksStandaloneFloorPurger = func() error { return nil }
	windowsManagedHooksStandaloneCursorTombstonePurger = func() error { return nil }
	enterpriseHookWindowsUserCleanupIdentity = func() error { return errors.New("not LocalSystem") }
	calls := 0
	windowsManagedClaudeTransactionLeftoverRemover = func() error {
		calls++
		return errors.New("holds an unfinished Claude settings transaction")
	}
	manifest := perUserTeardownManifest("claudecode")
	manifest.Targets[0].UserHome = t.TempDir()

	t.Setenv(managed.EnterpriseProfileEnv, "")
	var report windowsManagedHooksTeardownReport
	completeWindowsManagedHooksTeardownUserCleanup(&report, `C:\ProgramData\DefenseClaw\runtime`, manifest)
	if calls != 0 {
		t.Fatalf("Secure Client finalize removed the Claude transaction folder %d time(s)", calls)
	}
	t.Setenv(managed.EnterpriseProfileEnv, managed.ProfileStandalone)
	for index, purge := range []string{"0", "1"} {
		t.Setenv(windowsManagedHooksPurgeUserStateEnv, purge)
		report = windowsManagedHooksTeardownReport{}
		completeWindowsManagedHooksTeardownUserCleanup(&report, `C:\ProgramData\DefenseClaw\runtime`, manifest)
		if calls != index+1 {
			t.Fatalf("purge=%s: leftover removal ran %d time(s)", purge, calls)
		}
		if len(report.UserRegistrationsFailed) != 0 {
			t.Fatalf("purge=%s: a kept transaction folder failed the finalize: %v", purge, report.UserRegistrationsFailed)
		}
	}
}
