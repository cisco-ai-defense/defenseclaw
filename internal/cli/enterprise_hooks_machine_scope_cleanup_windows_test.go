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
	useOffRosterScan(t, dataDir)
	listed := 0
	enterpriseHookWindowsEligibleProfiles = func(context.Context) ([]enterprisehooks.TargetCredentials, error) {
		listed++
		return []enterprisehooks.TargetCredentials{
			{UserHome: homeA, SID: userCleanupSIDA}, {UserHome: homeB, SID: userCleanupSIDB},
			{UserHome: homeC, SID: sidC}, {UserHome: homeD, SID: sidD},
		}, nil
	}
	// A and B hold Cursor files and C holds Claude Code files (Claude Code is
	// on the roster); D holds nothing. One call per account lists all the
	// connectors that are off the roster.
	var asked []string
	enterpriseHookWindowsConnectorUserRuntimeLeftovers = func(home, sid, _ string, connectors []string) []string {
		asked = append(asked, filepath.Base(home)+":"+strings.Join(connectors, "+"))
		if home == homeA || home == homeB {
			return []string{"cursor"}
		}
		return nil
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
	for _, call := range asked {
		if !strings.HasSuffix(call, ":cursor") {
			t.Fatalf("the scan asked %q: only Cursor is off the roster", call)
		}
	}
	if pending, err := loadEnterpriseHookUserCleanups(dataDir); err != nil || len(pending) != 0 {
		t.Fatalf("completed cleanups remained recorded: %+v %v", pending, err)
	}
	// S4: an account found only by its files is recorded as not managed, like
	// one the guardian held a row for.
	records, err := loadEnterpriseHookRemovedConnectors(dataDir)
	if err != nil || len(records) != 2 {
		t.Fatalf("removed-connectors record = %+v %v, want both accounts with files", records, err)
	}

	// A manifest that admits Cursor for an account keeps that account's files,
	// and a failed removal is recorded for the next pass.
	resetOffRosterScan()
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
	if got := windowsStandaloneOffRosterRuntimeCleanups(context.Background(), &log, func(string) bool { return true }, nil, time.Now()); len(got) != 0 || listed != 0 {
		t.Fatalf("cleanups %+v with every connector published (profiles listed %d)", got, listed)
	}
}

// useOffRosterScan gives a test the standalone guardian config with Claude
// Code and Codex on the roster, the sandbox's seams to put back, and a fresh
// scan throttle.
func useOffRosterScan(t *testing.T, dataDir string) {
	t.Helper()
	previousCfg, previousProfiles := cfg, enterpriseHookWindowsEligibleProfiles
	previousLeftovers, previousRemover := enterpriseHookWindowsConnectorUserRuntimeLeftovers, enterpriseHookWindowsConnectorUserRuntimeRemover
	t.Cleanup(func() {
		cfg, enterpriseHookWindowsEligibleProfiles = previousCfg, previousProfiles
		enterpriseHookWindowsConnectorUserRuntimeLeftovers, enterpriseHookWindowsConnectorUserRuntimeRemover = previousLeftovers, previousRemover
		resetOffRosterScan()
	})
	t.Setenv(managed.EnterpriseProfileEnv, managed.ProfileStandalone)
	cfg = &config.Config{
		DeploymentMode: managed.DeploymentModeManagedEnterprise, DataDir: dataDir,
		Enterprise: config.EnterpriseConfig{Profile: managed.ProfileStandalone},
	}
	cfg.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{"claudecode": {}, "codex": {}}
	resetOffRosterScan()
}

func resetOffRosterScan() {
	enterpriseHookWindowsOffRosterScanState.Lock()
	enterpriseHookWindowsOffRosterScanState.last, enterpriseHookWindowsOffRosterScanState.fingerprint = time.Time{}, ""
	enterpriseHookWindowsOffRosterScanState.Unlock()
}

// S3: the scan runs when the set of connectors off the roster changes and then
// at most once in the interval, and a failed profile list is logged.
func TestOffRosterScanIsThrottledAndLogsTheProfileListError(t *testing.T) {
	dataDir := useUserCleanupStateDir(t)
	useOffRosterScan(t, dataDir)
	home := t.TempDir()
	scans := 0
	enterpriseHookWindowsEligibleProfiles = func(context.Context) ([]enterprisehooks.TargetCredentials, error) {
		scans++
		return []enterprisehooks.TargetCredentials{{UserHome: home, SID: userCleanupSIDA}}, errors.New("group cache unreadable")
	}
	enterpriseHookWindowsConnectorUserRuntimeLeftovers = func(string, string, string, []string) []string { return []string{"cursor"} }
	offCursor := func(name string) bool { return name != "cursor" }
	offCursorAndCodex := func(name string) bool { return name == "claudecode" }
	var log bytes.Buffer
	now := time.Now()
	scan := func(published func(string) bool, at time.Time) int {
		return len(windowsStandaloneOffRosterRuntimeCleanups(context.Background(), &log, published, nil, at))
	}
	if scan(offCursor, now) != 1 || scans != 1 || !strings.Contains(log.String(), "group cache unreadable") {
		t.Fatalf("first scan: scans=%d log=%q", scans, log.String())
	}
	if scan(offCursor, now.Add(time.Minute)) != 0 || scans != 1 {
		t.Fatalf("a scan inside the interval ran: scans=%d", scans)
	}
	if scan(offCursorAndCodex, now.Add(2*time.Minute)) != 1 || scans != 2 {
		t.Fatalf("a changed set of connectors off the roster did not scan: scans=%d", scans)
	}
	if scan(offCursorAndCodex, now.Add(2*time.Minute+enterpriseHookWindowsOffRosterScanInterval)) != 1 || scans != 3 {
		t.Fatalf("a scan after the interval did not run: scans=%d", scans)
	}
}

// S2: an entry for a machine-scope connector the config publishes again is
// held for an account the enrollment admits, not run; an account it does not
// admit is still cleaned.
func TestReAddedConnectorEntryIsHeldForAnEligibleAccountOnly(t *testing.T) {
	dataDir := useUserCleanupStateDir(t)
	useOffRosterScan(t, dataDir)
	enterpriseHookWindowsEligibleProfiles = func(context.Context) ([]enterprisehooks.TargetCredentials, error) {
		return []enterprisehooks.TargetCredentials{{UserHome: t.TempDir(), SID: userCleanupSIDA}}, nil
	}
	published := func(name string) bool { return name == "cursor" }
	hold := windowsStandaloneReAddedHold(context.Background(), published)
	if !hold("cursor", userCleanupSIDA) {
		t.Fatal("an eligible account's entry for a re-added connector was not held")
	}
	if hold("cursor", userCleanupSIDB) {
		t.Fatal("an account the enrollment does not admit was held")
	}
	if hold("codex", userCleanupSIDA) {
		t.Fatal("an entry for a connector still off the roster was held")
	}
	if hold("devin", userCleanupSIDA) {
		t.Fatal("a per-user connector was held")
	}

	// A profile list that fails says nothing about the account: the entry is
	// held (the held-pass bound ends it), not run (GAP-0964 S-G1).
	enterpriseHookWindowsEligibleProfiles = func(context.Context) ([]enterprisehooks.TargetCredentials, error) {
		return nil, errors.New("group cache unreadable")
	}
	failing := windowsStandaloneReAddedHold(context.Background(), published)
	if !failing("cursor", userCleanupSIDB) {
		t.Fatal("a failed profile list was treated as not eligible and the removal ran")
	}
	if failing("codex", userCleanupSIDB) {
		t.Fatal("an entry for a connector still off the roster was held by a failed profile list")
	}
}

// S1: a link left where a connector file should be is said once and the
// cleanup is done; it is not a failure to retry.
func TestAttemptWindowsStandaloneUserCleanupSaysALeftLinkOnceAndIsDone(t *testing.T) {
	home := t.TempDir()
	original := enterpriseHookWindowsConnectorUserRuntimeRemover
	t.Cleanup(func() { enterpriseHookWindowsConnectorUserRuntimeRemover = original })
	enterpriseHookWindowsConnectorUserRuntimeRemover = func(string, string, string, string) error {
		return &enterprisehooks.WindowsConnectorUserRuntimeLinksLeft{Links: []string{`hooks\.hook-cursor.token`}}
	}
	outcome, err := attemptWindowsStandaloneUserCleanup(context.Background(),
		enterpriseHookUserCleanup{Connector: "cursor", SID: userCleanupSIDA, UserHome: home})
	if outcome != enterpriseHookUserCleanupDone || err != nil {
		t.Fatalf("outcome=%d err=%v, want done", outcome, err)
	}
}

// Secure Client reconciles never reach the discovery: its profiles are not
// listed and its accounts' files are not looked at (pin row).
func TestRevokeUsersOffRosterDiscoveryIsStandaloneOnly(t *testing.T) {
	dataDir := useUserCleanupStateDir(t)
	writeUserCleanupAuthorization(t, dataDir)
	useOffRosterScan(t, dataDir)
	enterpriseHookWindowsEligibleProfiles = func(context.Context) ([]enterprisehooks.TargetCredentials, error) {
		t.Fatal("Secure Client listed the profiles for the off-roster cleanup")
		return nil, nil
	}
	enterpriseHookWindowsConnectorUserRuntimeLeftovers = func(string, string, string, []string) []string {
		t.Fatal("Secure Client looked in an account folder for a removed connector's files")
		return nil
	}
	t.Setenv(managed.EnterpriseProfileEnv, "")
	cfg = &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise, DataDir: dataDir}
	var log bytes.Buffer
	if err := enterpriseHookStandalonePlatformRevokeUsers(context.Background(), &log, enterprisehooks.Manifest{Version: 1}); err != nil {
		t.Fatal(err)
	}
}
