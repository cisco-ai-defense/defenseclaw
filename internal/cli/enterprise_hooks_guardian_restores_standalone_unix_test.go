// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

// GAP-0499: the standalone Linux and macOS guardian's reconcile dates, by
// uid, the protected target its worker put back; a pass whose targets still
// verify keeps the record as it was, and so does a pass that cannot resolve
// the still-enrolled account (a directory outage, then a failed lookup).
func TestStandaloneReconcileRecordsTheTargetItRestored(t *testing.T) {
	uid, gid := os.Getuid(), os.Getgid()
	resolver := standaloneTestResolver{accounts: map[string]unixidentity.Account{}, transient: map[string]bool{}}
	f := newStandaloneFixture(t, resolver)
	alice := f.home(t, "alice", 0o700)
	resolver.accounts["alice"] = unixidentity.Account{Name: "alice", UID: uid, GID: gid, Home: alice, Shell: "/bin/bash"}
	f.writeManifest(t, enterprisehooks.ManifestTarget{User: "alice", Connector: "hermes"})
	f.writeLedger(t, protectedRow("alice", alice, "hermes"))
	key := enterpriseHookProtectedTargetKey(enterpriseHookReconcileRow{User: "alice", Connector: "hermes"})
	f.writeBindings(t, map[string]enterpriseHookUnixBinding{key: {UID: uid, Home: alice, LockUpdatedAt: "L", EntryUpdatedAt: "E"}})
	previousRunner := enterpriseHookWorkerRunner
	repair := true
	enterpriseHookWorkerRunner = func(ctx context.Context, account enterpriseHookWorkerAccount, request enterpriseHookWorkerRequest) (enterpriseHookWorkerResponse, error) {
		response, err := previousRunner(ctx, account, request)
		for i := range response.Targets {
			response.Targets[i].Repaired = repair
		}
		return response, err
	}

	before := time.Now()
	run, err := runEnterpriseHookReconcileOnce(context.Background())
	after := time.Now()
	if err != nil {
		t.Fatal(err)
	}
	requireLedgerOrStateTrust(t, run.StateErr)
	if run.Repairs != 1 {
		t.Fatalf("run = %+v, want one repair", run)
	}
	restores := guardianRestoresForTest(t, f.dataDir)
	restoredAt, ok := restores[enterpriseHookGuardianRestoreUIDKey(uid, "hermes")]
	if len(restores) != 1 || !ok || restoredAt.Before(before) || restoredAt.After(after) {
		t.Fatalf("restores = %v, want hermes of uid %d between %s and %s", restores, uid, before, after)
	}

	repair = false
	if _, err := runEnterpriseHookReconcileOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if again := guardianRestoresForTest(t, f.dataDir); len(again) != 1 || !again[enterpriseHookGuardianRestoreUIDKey(uid, "hermes")].Equal(restoredAt) {
		t.Fatalf("restores after a clean pass = %v, want the restore at %s", again, restoredAt)
	}

	// An SSSD outage leaves alice's row pending, then her lookup fails: her
	// rows carry no uid, but her target is still in the manifest and the
	// Hermes session started before the restore may still run, so later
	// clean passes (which repair nothing) must still find the entry
	// (verify r1 F3).
	resolver.transient["alice"] = true
	run, err = runEnterpriseHookReconcileOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if run.Pending != 1 {
		t.Fatalf("run during the outage = %+v, want alice pending", run)
	}
	if again := guardianRestoresForTest(t, f.dataDir); len(again) != 1 || !again[enterpriseHookGuardianRestoreUIDKey(uid, "hermes")].Equal(restoredAt) {
		t.Fatalf("restores after a pending pass = %v, want the restore at %s", again, restoredAt)
	}
	resolver.transient["alice"] = false
	delete(resolver.accounts, "alice")
	run, err = runEnterpriseHookReconcileOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if run.Failures != 1 {
		t.Fatalf("run with alice's lookup failing = %+v, want alice failed", run)
	}
	if again := guardianRestoresForTest(t, f.dataDir); len(again) != 1 || !again[enterpriseHookGuardianRestoreUIDKey(uid, "hermes")].Equal(restoredAt) {
		t.Fatalf("restores after a failed pass = %v, want the restore at %s", again, restoredAt)
	}
}
