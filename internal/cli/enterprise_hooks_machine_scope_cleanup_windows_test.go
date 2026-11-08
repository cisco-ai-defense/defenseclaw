// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

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
	original, originalRecorder := enterpriseHookWindowsConnectorUserRuntimeRemover, enterpriseHookWindowsRemovedConnectorRecorder
	t.Cleanup(func() {
		enterpriseHookWindowsConnectorUserRuntimeRemover, enterpriseHookWindowsRemovedConnectorRecorder = original, originalRecorder
	})
	var recorded []string
	recordErr := error(nil)
	enterpriseHookWindowsRemovedConnectorRecorder = func(entry enterpriseHookUserCleanup) error {
		recorded = append(recorded, entry.Connector)
		return recordErr
	}
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
	if strings.Join(recorded, ",") != "Cursor,claudecode,codex" {
		t.Fatalf("recorded removed connectors = %v, want one per completed cleanup", recorded)
	}
	// A record that cannot be written fails the cleanup, which is retried.
	recordErr = errors.New("record locked")
	entryR := enterpriseHookUserCleanup{Connector: "cursor", SID: userCleanupSIDA, UserHome: home, DataDir: filepath.Join(home, ".defenseclaw")}
	if outcome, err := attemptWindowsStandaloneUserCleanup(context.Background(), entryR); outcome != enterpriseHookUserCleanupFailed || err == nil {
		t.Fatalf("record failure: outcome=%d err=%v", outcome, err)
	}
	recordErr = nil
	recorded = nil
	removeErr = errors.New("a file is held")
	entry := enterpriseHookUserCleanup{Connector: "cursor", SID: userCleanupSIDA, UserHome: home, DataDir: filepath.Join(home, ".defenseclaw")}
	if outcome, err := attemptWindowsStandaloneUserCleanup(context.Background(), entry); outcome != enterpriseHookUserCleanupFailed || err == nil || len(recorded) != 0 {
		t.Fatalf("failed removal: outcome=%d err=%v recorded=%v, want a failure the guardian retries and no record", outcome, err, recorded)
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

// The record is written only for a connector the loaded config no longer
// publishes (the administrator removed it from the roster); a connector it
// still publishes was dropped for this account alone.
func TestRecordWindowsStandaloneRemovedConnectorNeedsTheConnectorOffTheRoster(t *testing.T) {
	dataDir := stubRemovedConnectorsRecord(t)
	previous := cfg
	t.Cleanup(func() { cfg = previous })
	entry := enterpriseHookUserCleanup{Connector: "cursor", SID: userCleanupSIDA, User: "alice", UserHome: `C:\Users\alice`}

	cfg = &config.Config{DataDir: dataDir, DeploymentMode: string(managed.DeploymentModeManagedEnterprise), Enterprise: config.EnterpriseConfig{Profile: managed.ProfileStandalone}}
	cfg.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{"cursor": {}}
	if err := recordWindowsStandaloneRemovedConnector(entry); err != nil {
		t.Fatal(err)
	}
	if entries, _ := loadEnterpriseHookRemovedConnectors(dataDir); len(entries) != 0 {
		t.Fatalf("a connector still on the roster was recorded as removed: %+v", entries)
	}
	cfg.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{"codex": {}}
	if err := recordWindowsStandaloneRemovedConnector(entry); err != nil {
		t.Fatal(err)
	}
	entries, err := loadEnterpriseHookRemovedConnectors(dataDir)
	if err != nil || len(entries) != 1 || entries[0].Connector != "cursor" || entries[0].User != "alice" || entries[0].SID != userCleanupSIDA {
		t.Fatalf("entries = %+v, %v", entries, err)
	}
	cfg = nil
	if err := recordWindowsStandaloneRemovedConnector(entry); err != nil {
		t.Fatalf("no config: %v", err)
	}
}
