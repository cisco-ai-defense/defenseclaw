// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
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
