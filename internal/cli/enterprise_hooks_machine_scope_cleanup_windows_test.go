// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// GAP-0916: a connector a roster change took off the roster leaves its scoped
// hook token, hook config and runtime records in each enrolled account's
// DefenseClaw folder. For the machine-scope connectors the machine enrollment
// is already revoked, so LocalSystem removes those files at once: no session is
// asked for and none is waited for. The per-user connectors keep the removal
// under the account's own session.
func TestAttemptWindowsStandaloneUserCleanupRemovesMachineScopeRuntimeWithoutASession(t *testing.T) {
	home := t.TempDir()
	original := enterpriseHookWindowsConnectorUserRuntimeRemover
	t.Cleanup(func() { enterpriseHookWindowsConnectorUserRuntimeRemover = original })
	type call struct{ home, sid, dataDir, connector string }
	var calls []call
	removeErr := error(nil)
	enterpriseHookWindowsConnectorUserRuntimeRemover = func(gotHome, sid, dataDir, name string) error {
		calls = append(calls, call{gotHome, sid, dataDir, name})
		return removeErr
	}
	stubWindowsUserCleanupSeams(t,
		func(string, string) error {
			t.Fatal("a machine-scope connector's cleanup asked for the account's session")
			return nil
		},
		func(context.Context, enterprisehooks.InstallOptions) error {
			t.Fatal("a machine-scope connector's cleanup ran the per-user policy removal")
			return nil
		},
	)
	for _, name := range []string{"Cursor", "claudecode", "codex"} {
		calls = nil
		entry := enterpriseHookUserCleanup{Connector: name, SID: userCleanupSIDA, UserHome: home, DataDir: filepath.Join(home, ".defenseclaw")}
		outcome, err := attemptWindowsStandaloneUserCleanup(context.Background(), entry)
		if outcome != enterpriseHookUserCleanupDone || err != nil || len(calls) != 1 ||
			calls[0] != (call{filepath.Clean(home), userCleanupSIDA, entry.DataDir, name}) {
			t.Fatalf("%s: outcome=%d err=%v calls=%+v", name, outcome, err, calls)
		}
	}
	removeErr = errors.New("a file is held")
	entry := enterpriseHookUserCleanup{Connector: "cursor", SID: userCleanupSIDA, UserHome: home, DataDir: filepath.Join(home, ".defenseclaw")}
	if outcome, err := attemptWindowsStandaloneUserCleanup(context.Background(), entry); outcome != enterpriseHookUserCleanupFailed || err == nil {
		t.Fatalf("failed removal: outcome=%d err=%v, want a failure the guardian retries", outcome, err)
	}
	// A profile folder that is gone is handled before the removal, as for every connector.
	gone := entry
	gone.UserHome = filepath.Join(home, "deleted-profile")
	calls = nil
	if outcome, _ := attemptWindowsStandaloneUserCleanup(context.Background(), gone); outcome == enterpriseHookUserCleanupFailed || len(calls) != 0 {
		t.Fatalf("missing profile: outcome=%d calls=%d", outcome, len(calls))
	}
}

// The guardian's revocation plan covers the per-user and machine-scope
// connectors; uninstall's plan keeps the per-user set.
func TestWindowsStandaloneRevokedUserCleanupConnectors(t *testing.T) {
	for name, want := range map[string]bool{
		"cursor": true, "claudecode": true, "codex": true, "Cursor": true,
		"copilot": true, "opencode": true, "hermes": true,
		"unknown": false, "": false,
	} {
		if got := windowsStandaloneRevokedUserCleanupConnector(name); got != want {
			t.Errorf("windowsStandaloneRevokedUserCleanupConnector(%q) = %t, want %t", name, got, want)
		}
	}
	for _, name := range []string{"cursor", "claudecode", "codex"} {
		if windowsStandalonePerUserCleanupConnector(name) {
			t.Errorf("uninstall's plan took on %q", name)
		}
	}
}

// GAP-0964: the files of a connector that left the roster are removed from
// every account that still holds them, whatever the guardian last recorded for
// the account and whatever its Windows session is doing. The old plan came
// only from a previously protected row, so an account whose row was pending (a
// disconnected or signed-out session when the connector was installed, or a
// roster change that was undone) or whose ledger had been rebuilt kept its
// token and hook config for good. Here nothing is protected, the manifest has
// no Cursor row, and the connector is off the roster.
func TestRevokeUsersCleansOffRosterMachineScopeFilesOfAccountsWithoutAProtectedRow(t *testing.T) {
	dataDir := useUserCleanupStateDir(t)
	homeA, homeB, homeC, homeD := t.TempDir(), t.TempDir(), t.TempDir(), t.TempDir()
	sidC := "S-1-5-21-1000000000-2000000000-3000000000-1019"
	sidD := "S-1-5-21-1000000000-2000000000-3000000000-1020"
	writeUserCleanupAuthorization(t, dataDir) // no protected row
	previousCfg, previousProfiles := cfg, enterpriseHookWindowsEligibleProfiles
	previousLeftover, previousRemover := enterpriseHookWindowsConnectorUserRuntimeLeftover, enterpriseHookWindowsConnectorUserRuntimeRemover
	t.Cleanup(func() {
		cfg, enterpriseHookWindowsEligibleProfiles = previousCfg, previousProfiles
		enterpriseHookWindowsConnectorUserRuntimeLeftover, enterpriseHookWindowsConnectorUserRuntimeRemover = previousLeftover, previousRemover
	})
	t.Setenv(managed.EnterpriseProfileEnv, managed.ProfileStandalone)
	cfg = &config.Config{
		DeploymentMode: managed.DeploymentModeManagedEnterprise, DataDir: dataDir,
		Enterprise: config.EnterpriseConfig{Profile: managed.ProfileStandalone},
	}
	cfg.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{"claudecode": {}, "codex": {}}
	listed := 0
	enterpriseHookWindowsEligibleProfiles = func(context.Context) ([]enterprisehooks.TargetCredentials, error) {
		listed++
		return []enterprisehooks.TargetCredentials{
			{UserHome: homeA, SID: userCleanupSIDA}, {UserHome: homeB, SID: userCleanupSIDB},
			{UserHome: homeC, SID: sidC}, {UserHome: homeD, SID: sidD},
		}, nil
	}
	// A and B hold Cursor files and C holds Claude Code files (Claude Code is
	// on the roster); D holds nothing.
	enterpriseHookWindowsConnectorUserRuntimeLeftover = func(home, _ string, name string) bool {
		return (name == "cursor" && (home == homeA || home == homeB)) || (name == "claudecode" && home == homeC)
	}
	var removed []string
	enterpriseHookWindowsConnectorUserRuntimeRemover = func(home, sid, _ string, name string) error {
		removed = append(removed, name+"/"+sid+"/"+filepath.Base(home))
		return nil
	}
	var log bytes.Buffer
	if err := enterpriseHookStandalonePlatformRevokeUsers(context.Background(), &log, enterprisehooks.Manifest{Version: 1}); err != nil {
		t.Fatal(err)
	}
	sort.Strings(removed)
	want := []string{"cursor/" + userCleanupSIDA + "/" + filepath.Base(homeA), "cursor/" + userCleanupSIDB + "/" + filepath.Base(homeB)}
	sort.Strings(want)
	if strings.Join(removed, ",") != strings.Join(want, ",") || listed == 0 {
		t.Fatalf("removed %v, want %v (profiles listed %d); log: %s", removed, want, listed, log.String())
	}
	if pending, err := loadEnterpriseHookUserCleanups(dataDir); err != nil || len(pending) != 0 {
		t.Fatalf("completed cleanups remained recorded: %+v %v", pending, err)
	}

	// A manifest that admits Cursor for an account keeps that account's files,
	// and a failed removal is recorded for the next pass.
	removed = nil
	enterpriseHookWindowsConnectorUserRuntimeRemover = func(home, sid, _ string, name string) error {
		removed = append(removed, name+"/"+sid)
		return errors.New("a file is held")
	}
	if err := enterpriseHookStandalonePlatformRevokeUsers(context.Background(), &log, userCleanupManifest([2]string{"cursor", userCleanupSIDA})); err != nil {
		t.Fatal(err)
	}
	if strings.Join(removed, ",") != "cursor/"+userCleanupSIDB {
		t.Fatalf("removed %v, want only the account the manifest does not admit", removed)
	}
	if pending, err := loadEnterpriseHookUserCleanups(dataDir); err != nil || len(pending) != 1 || pending[0].SID != userCleanupSIDB {
		t.Fatalf("failed cleanup not recorded: %+v %v", pending, err)
	}

	// With every machine-scope connector on the roster nothing is looked at.
	listed = 0
	if got := windowsStandaloneOffRosterRuntimeCleanups(context.Background(), func(string) bool { return true }, nil, time.Now()); len(got) != 0 || listed != 0 {
		t.Fatalf("cleanups %+v with every connector published (profiles listed %d)", got, listed)
	}
}

// Secure Client reconciles never reach the discovery: its profiles are not
// listed and its accounts' files are not looked at (pin row).
func TestRevokeUsersOffRosterDiscoveryIsStandaloneOnly(t *testing.T) {
	dataDir := useUserCleanupStateDir(t)
	writeUserCleanupAuthorization(t, dataDir)
	previousCfg, previousProfiles, previousLeftover := cfg, enterpriseHookWindowsEligibleProfiles, enterpriseHookWindowsConnectorUserRuntimeLeftover
	t.Cleanup(func() {
		cfg, enterpriseHookWindowsEligibleProfiles, enterpriseHookWindowsConnectorUserRuntimeLeftover = previousCfg, previousProfiles, previousLeftover
	})
	enterpriseHookWindowsEligibleProfiles = func(context.Context) ([]enterprisehooks.TargetCredentials, error) {
		t.Fatal("Secure Client listed the profiles for the off-roster cleanup")
		return nil, nil
	}
	enterpriseHookWindowsConnectorUserRuntimeLeftover = func(string, string, string) bool {
		t.Fatal("Secure Client looked in an account folder for a removed connector's files")
		return false
	}
	t.Setenv(managed.EnterpriseProfileEnv, "")
	cfg = &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise, DataDir: dataDir}
	var log bytes.Buffer
	if err := enterpriseHookStandalonePlatformRevokeUsers(context.Background(), &log, enterprisehooks.Manifest{Version: 1}); err != nil {
		t.Fatal(err)
	}
}
