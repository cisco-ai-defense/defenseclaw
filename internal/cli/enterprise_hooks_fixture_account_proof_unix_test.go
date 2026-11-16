// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"context"
	"os"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

// simulateMachineWithoutFixtureAccounts stands in for a macOS runner. Its
// real account database (dscl) has no record of any fixture name, so every
// fresh proof reads "gone". The standalone fixture must not let that reach
// the accounts it created in its own resolver.
func simulateMachineWithoutFixtureAccounts(t *testing.T) {
	t.Helper()
	previousCleanup, previousName, previousUID := enterpriseHookCleanupAccountGone, enterpriseHookGuardianFreshAccountGone, enterpriseHookRecordedAccountGone
	t.Cleanup(func() {
		enterpriseHookCleanupAccountGone, enterpriseHookGuardianFreshAccountGone, enterpriseHookRecordedAccountGone = previousCleanup, previousName, previousUID
	})
	enterpriseHookCleanupAccountGone = func(context.Context, string) bool { return true }
	enterpriseHookGuardianFreshAccountGone = func(context.Context, string) bool { return true }
	enterpriseHookRecordedAccountGone = func(context.Context, string, int) bool { return true }
}

func runAliceReconcile(t *testing.T, install func()) enterpriseHookReconcileRow {
	t.Helper()
	uid, gid := os.Getuid(), os.Getgid()
	resolver := standaloneTestResolver{accounts: map[string]unixidentity.Account{}, transient: map[string]bool{}}
	f := newStandaloneFixture(t, resolver)
	alice := f.home(t, "alice", 0o700)
	resolver.accounts["alice"] = unixidentity.Account{Name: "alice", UID: uid, GID: gid, Home: alice, Shell: "/bin/bash"}
	f.writeManifest(t, enterprisehooks.ManifestTarget{User: "alice", Connector: "hermes"})
	f.writeLedger(t, protectedRow("alice", alice, "hermes"))
	key := enterpriseHookProtectedTargetKey(enterpriseHookReconcileRow{User: "alice", Connector: "hermes"})
	f.writeBindings(t, map[string]enterpriseHookUnixBinding{key: {UID: uid, Home: alice, LockUpdatedAt: "L", EntryUpdatedAt: "E"}})
	install()
	run, err := runEnterpriseHookReconcileOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	requireLedgerOrStateTrust(t, run.StateErr)
	if len(run.Rows) != 1 {
		t.Fatalf("rows = %+v, want one", run.Rows)
	}
	return run.Rows[0]
}

// A fixture account that its own resolver finds stays protected, whatever
// the real account database of the test machine says about the name.
func TestStandaloneFixtureAccountIsNotRetiredByTheMachineAccountDatabase(t *testing.T) {
	simulateMachineWithoutFixtureAccounts(t)
	row := runAliceReconcile(t, func() {})
	if row.Removed || row.RevokeProtection || !row.OK {
		t.Fatalf("row = %+v, want a protected, non-removed alice", row)
	}
}

// The twin: a proof the test installs itself still retires the account, so
// the fixture hides only the machine account database.
func TestStandaloneFixtureAccountIsRetiredByAProofTheTestInstalls(t *testing.T) {
	row := runAliceReconcile(t, func() {
		enterpriseHookGuardianFreshAccountGone = func(_ context.Context, user string) bool { return user == "alice" }
	})
	if !row.Removed || !row.RevokeProtection {
		t.Fatalf("row = %+v, want alice retired by the installed proof", row)
	}
}
