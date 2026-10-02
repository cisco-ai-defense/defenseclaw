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
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

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

// Uninstall cleans every per-user registration the guardian made or still
// owes, as each user; when it cannot act as users at all (an interactive
// administrator), every registration is reported, never silently skipped.
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

	result := removeWindowsManagedHooksStandalonePerUserRegistrations(context.Background(), dataDir, manifest)
	want := "amp/" + userCleanupSIDB + ",devin/" + userCleanupSIDA + ",opencode/" + userCleanupSIDB
	if strings.Join(attempted, ",") != want {
		t.Fatalf("attempted %v, want %s (no codex, no never-protected deferred row, backoff ignored)", attempted, want)
	}
	if len(result.Removed) != 2 || strings.Join(result.Pending, ",") != "opencode/"+userCleanupSIDB || len(result.Failed) != 0 {
		t.Fatalf("result = %+v", result)
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

	// Only the standalone profile's teardown accepts the per-user connectors.
	t.Run("teardown targets", func(t *testing.T) {
		t.Setenv(managed.EnterpriseProfileEnv, "")
		if _, _, _, _, err := windowsManagedHooksTeardownTargets(perUserTeardownManifest("copilot")); err == nil ||
			!strings.Contains(err.Error(), "does not support connector") {
			t.Fatalf("Secure Client teardown accepted copilot: %v", err)
		}
		t.Setenv(managed.EnterpriseProfileEnv, managed.ProfileStandalone)
		for _, name := range []string{"copilot", "devin", "amp"} {
			targets, claude, codex, cursor, err := windowsManagedHooksTeardownTargets(perUserTeardownManifest(name))
			if err != nil || len(targets) != 1 || len(claude)+len(codex)+len(cursor) != 0 {
				t.Fatalf("%s: targets=%v err=%v", name, targets, err)
			}
		}
		if _, _, _, _, err := windowsManagedHooksTeardownTargets(perUserTeardownManifest("openhands")); err == nil {
			t.Fatal("standalone teardown accepted openhands")
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

// Finalize removes users' registrations and reports the outcome only for
// the standalone profile; Secure Client finalize never runs it.
func TestCompleteWindowsManagedHooksTeardownUserCleanupIsStandaloneOnly(t *testing.T) {
	original := windowsManagedHooksStandaloneUserRegistrationRemover
	t.Cleanup(func() { windowsManagedHooksStandaloneUserRegistrationRemover = original })
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
	t.Setenv(windowsManagedHooksPurgeUserStateEnv, "1")
	originalIdentity, originalPurger := enterpriseHookWindowsUserCleanupIdentity, windowsManagedHooksStandaloneUserStatePurger
	t.Cleanup(func() {
		enterpriseHookWindowsUserCleanupIdentity, windowsManagedHooksStandaloneUserStatePurger = originalIdentity, originalPurger
	})
	enterpriseHookWindowsUserCleanupIdentity = func() error { return nil }
	purged := 0
	windowsManagedHooksStandaloneUserStatePurger = func(home, sid, _ string) error {
		if purged++; home != manifest.Targets[0].UserHome || sid != manifest.Targets[0].SID {
			t.Fatalf("purged %s %s", home, sid)
		}
		return nil
	}
	completeWindowsManagedHooksTeardownUserCleanup(&report, `C:\ProgramData\DefenseClaw\runtime`, manifest)
	if purged != 1 || len(report.UserStateRemaining) != 0 {
		t.Fatalf("purge ran %d time(s), remaining %v", purged, report.UserStateRemaining)
	}
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
