// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"golang.org/x/sys/windows"
)

func stubWindowsUserCleanupSeams(
	t *testing.T,
	session func(string, string) error,
	remove func(context.Context, enterprisehooks.InstallOptions) error,
) {
	t.Helper()
	originalSession := enterpriseHookWindowsRequireTargetSession
	originalRemove := enterpriseHooksRemoveManagedPolicy
	enterpriseHookWindowsRequireTargetSession = session
	enterpriseHooksRemoveManagedPolicy = remove
	t.Cleanup(func() {
		enterpriseHookWindowsRequireTargetSession = originalSession
		enterpriseHooksRemoveManagedPolicy = originalRemove
	})
}

// The revocation cleanup is the per-user removal run under the user's own
// session: no session is pending, a deleted profile has nothing left, and
// only an exact removal success completes the entry.
func TestAttemptWindowsStandaloneUserCleanupRunsAsTheSignedInUser(t *testing.T) {
	home := t.TempDir()
	entry := enterpriseHookUserCleanup{
		Connector: "Devin",
		SID:       userCleanupSIDA,
		UserHome:  home,
		DataDir:   filepath.Join(home, ".defenseclaw"),
	}
	var removed []enterprisehooks.InstallOptions
	sessionErr := error(&enterprisehooks.WindowsTargetSessionUnavailableError{SID: userCleanupSIDA})
	removeErr := error(nil)
	stubWindowsUserCleanupSeams(t,
		func(sid, gotHome string) error {
			if sid != userCleanupSIDA || gotHome != filepath.Clean(home) {
				t.Fatalf("session check for %s %s", sid, gotHome)
			}
			return sessionErr
		},
		func(_ context.Context, opts enterprisehooks.InstallOptions) error {
			removed = append(removed, opts)
			return removeErr
		},
	)

	outcome, err := attemptWindowsStandaloneUserCleanup(context.Background(), entry)
	if outcome != enterpriseHookUserCleanupPending || err != nil || len(removed) != 0 {
		t.Fatalf("signed-out user: outcome=%d err=%v removals=%d", outcome, err, len(removed))
	}

	sessionErr = errors.New("token profile mismatch")
	outcome, err = attemptWindowsStandaloneUserCleanup(context.Background(), entry)
	if outcome != enterpriseHookUserCleanupFailed || err == nil || len(removed) != 0 {
		t.Fatalf("session failure: outcome=%d err=%v removals=%d", outcome, err, len(removed))
	}

	sessionErr = nil
	outcome, err = attemptWindowsStandaloneUserCleanup(context.Background(), entry)
	if outcome != enterpriseHookUserCleanupDone || err != nil || len(removed) != 1 {
		t.Fatalf("signed-in user: outcome=%d err=%v removals=%d", outcome, err, len(removed))
	}
	got := removed[0]
	if got.ConnectorName != "devin" || got.OwnerSID != userCleanupSIDA || got.UserHome != filepath.Clean(home) ||
		got.DataDir != entry.DataDir || got.Registry == nil {
		t.Fatalf("removal options = %+v", got)
	}

	removeErr = &enterprisehooks.WindowsTargetSessionUnavailableError{SID: userCleanupSIDA}
	if outcome, _ = attemptWindowsStandaloneUserCleanup(context.Background(), entry); outcome != enterpriseHookUserCleanupPending {
		t.Fatalf("sign-out during removal: outcome=%d", outcome)
	}
	removeErr = errors.New("teardown failed")
	if outcome, err = attemptWindowsStandaloneUserCleanup(context.Background(), entry); outcome != enterpriseHookUserCleanupFailed || err == nil {
		t.Fatalf("removal failure: outcome=%d err=%v", outcome, err)
	}

	gone := entry
	gone.UserHome = filepath.Join(home, "deleted-profile")
	removed = nil
	profileRemoved := false
	originalProfileRemoved := enterpriseHookWindowsUserProfileRemoved
	enterpriseHookWindowsUserProfileRemoved = func(sid string) bool {
		if sid != userCleanupSIDA {
			t.Fatalf("profile check for %s", sid)
		}
		return profileRemoved
	}
	t.Cleanup(func() { enterpriseHookWindowsUserProfileRemoved = originalProfileRemoved })
	// A missing folder while the account can still sign in (a roaming
	// profile whose cached copy was deleted at sign-out, an FSLogix
	// container) waits for that sign-in.
	if outcome, err = attemptWindowsStandaloneUserCleanup(context.Background(), gone); outcome != enterpriseHookUserCleanupPending ||
		err != nil || len(removed) != 0 {
		t.Fatalf("signed-out roaming profile: outcome=%d err=%v removals=%d", outcome, err, len(removed))
	}
	profileRemoved = true
	if outcome, err = attemptWindowsStandaloneUserCleanup(context.Background(), gone); outcome != enterpriseHookUserCleanupDone ||
		err != nil || len(removed) != 0 {
		t.Fatalf("deleted profile: outcome=%d err=%v removals=%d", outcome, err, len(removed))
	}
}

// Only a SID with neither a ProfileList entry nor an account counts as a
// removed profile.
func TestWindowsStandaloneUserProfileRemovedNeedsTheAccountGone(t *testing.T) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	for _, sid := range []string{user.User.Sid.String(), "S-1-5-18", "not-a-sid", ""} {
		if windowsStandaloneUserProfileRemoved(sid) {
			t.Fatalf("SID %q reported as a removed profile", sid)
		}
	}
	if !windowsStandaloneUserProfileRemoved(userCleanupSIDA) {
		t.Fatalf("unknown SID %s with no profile was not reported as removed", userCleanupSIDA)
	}
}

// The guardian step runs only for the standalone profile; Secure Client
// reconciles never plan or attempt a per-user cleanup.
func TestEnterpriseHookStandalonePlatformRevokeUsersIsStandaloneOnly(t *testing.T) {
	dataDir := useUserCleanupStateDir(t)
	home := filepath.Join(t.TempDir(), "alice")
	writeUserCleanupAuthorization(t, dataDir, userCleanupRow("hermes", userCleanupSIDA, home))
	originalCfg, originalAttempt := cfg, enterpriseHookWindowsUserCleanupAttempt
	t.Cleanup(func() { cfg, enterpriseHookWindowsUserCleanupAttempt = originalCfg, originalAttempt })
	var attempted []string
	enterpriseHookWindowsUserCleanupAttempt = func(_ context.Context, entry enterpriseHookUserCleanup) (enterpriseHookUserCleanupOutcome, error) {
		attempted = append(attempted, enterpriseHookUserCleanupLabel(entry))
		return enterpriseHookUserCleanupPending, nil
	}

	t.Setenv(managed.EnterpriseProfileEnv, "")
	cfg = &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise, DataDir: dataDir}
	var log bytes.Buffer
	if err := enterpriseHookStandalonePlatformRevokeUsers(context.Background(), &log, enterprisehooks.Manifest{Version: 1}); err != nil {
		t.Fatal(err)
	}
	if len(attempted) != 0 {
		t.Fatalf("Secure Client attempted per-user cleanups %v", attempted)
	}

	t.Setenv(managed.EnterpriseProfileEnv, managed.ProfileStandalone)
	cfg = &config.Config{
		DeploymentMode: managed.DeploymentModeManagedEnterprise,
		DataDir:        dataDir,
		Enterprise:     config.EnterpriseConfig{Profile: managed.ProfileStandalone},
	}
	if err := enterpriseHookStandalonePlatformRevokeUsers(context.Background(), &log, enterprisehooks.Manifest{Version: 1}); err != nil {
		t.Fatal(err)
	}
	if strings.Join(attempted, ",") != "hermes/"+userCleanupSIDA {
		t.Fatalf("standalone attempted %v", attempted)
	}
	pending, err := loadEnterpriseHookUserCleanups(dataDir)
	if err != nil || len(pending) != 1 {
		t.Fatalf("standalone did not record the signed-out user: %+v %v", pending, err)
	}
}
