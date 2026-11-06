//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

// A removed account can remain in the published manifest until the
// enumerator's next cycles. Its target is recorded but no longer needs a
// repair timer. An unrelated enrolled account keeps its worker and coverage.
func TestGAP0693RemovedAccountLeavesGuardianRepairAttention(t *testing.T) {
	uid, gid := os.Getuid(), os.Getgid()
	resolver := standaloneTestResolver{accounts: map[string]unixidentity.Account{}}
	f := newStandaloneFixture(t, resolver)
	liveHome := f.home(t, "live", 0o700)
	removedHome := filepath.Join(f.homes, "removed")
	resolver.accounts["live"] = unixidentity.Account{Name: "live", UID: uid, GID: gid, Home: liveHome}
	f.writeManifest(t,
		enterprisehooks.ManifestTarget{User: "removed", UserHome: removedHome, Connector: "hermes"},
		enterprisehooks.ManifestTarget{User: "live", UserHome: liveHome, Connector: "codex"},
	)
	if err := enterprisehooks.SaveUnixEnumeratorState(enterpriseHookEnumeratorStatePath(f.manifest),
		&enterprisehooks.UnixEnumeratorState{Version: 1, Sources: map[string]string{"removed": "files"}}); err != nil {
		t.Fatal(err)
	}
	f.writeLedger(t, protectedRow("removed", removedHome, "hermes"))
	previousLocal, previousDirectory := enterpriseHooksEnumerateLocalAccounts, enterpriseHooksEnumerateDirectoryConfigured
	t.Cleanup(func() {
		enterpriseHooksEnumerateLocalAccounts, enterpriseHooksEnumerateDirectoryConfigured = previousLocal, previousDirectory
	})
	enterpriseHooksEnumerateLocalAccounts = func(context.Context) (map[string]int, error) {
		return map[string]int{"live": uid}, nil
	}
	enterpriseHooksEnumerateDirectoryConfigured = func() bool { return false }

	run, err := runEnterpriseHookReconcileOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	requireLedgerOrStateTrust(t, run.StateErr)
	if len(run.Rows) != 2 || run.Rows[0].OK || !run.Rows[1].OK {
		t.Fatalf("removed/live rows = %+v", run.Rows)
	}
	if targets := f.workerTargets(); len(targets) != 1 || targets["codex@"+liveHome].Options.ConnectorName != "codex" {
		t.Fatalf("only the live target should reach a worker: %+v", f.workerTargets())
	}
	if got := f.ledger(t).ProtectedTargets; len(got) != 1 || got[0].User != "live" {
		t.Fatalf("removed account retained protected authorization: %+v", got)
	}
	run.StateErr = nil
	var retries enterpriseHookWatchRetries
	retries.observe("startup", run, nil, time.Now())
	if due, needed := retries.nextDue(); needed {
		t.Fatalf("removed account kept a repair timer due at %s", due)
	}
}

func TestGAP0693FreshRecordRetiresStaleMacAccountOnce(t *testing.T) {
	uid, gid := os.Getuid(), os.Getgid()
	resolver := standaloneTestResolver{accounts: map[string]unixidentity.Account{}}
	f := newStandaloneFixture(t, resolver)
	liveHome := f.home(t, "live", 0o700)
	removedHome := f.home(t, "removed", 0o700)
	resolver.accounts["live"] = unixidentity.Account{Name: "live", UID: uid, GID: gid, Home: liveHome}
	// The process cache still names this account after its directory record
	// was deleted. Its worker would keep failing on the old home.
	resolver.accounts["removed"] = unixidentity.Account{Name: "removed", UID: uid + 1, GID: gid, Home: removedHome}
	f.writeManifest(t,
		enterprisehooks.ManifestTarget{User: "removed", UserHome: removedHome, Connector: "hermes"},
		enterprisehooks.ManifestTarget{User: "live", UserHome: liveHome, Connector: "codex"},
	)
	f.writeLedger(t, protectedRow("removed", removedHome, "hermes"))
	previousProof := enterpriseHookGuardianFreshAccountGone
	t.Cleanup(func() { enterpriseHookGuardianFreshAccountGone = previousProof })
	enterpriseHookGuardianFreshAccountGone = func(_ context.Context, user string) bool { return user == "removed" }
	for pass := 0; pass < 2; pass++ {
		run, err := runEnterpriseHookReconcileOnce(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		requireLedgerOrStateTrust(t, run.StateErr)
		if len(run.Rows) != 2 || !run.Rows[0].Removed || run.Rows[0].OK || !run.Rows[1].OK || run.attentionFailures() != 0 {
			t.Fatalf("pass %d removed/live dispositions = %+v", pass, run.Rows)
		}
		if targets := f.workerTargets(); len(targets) != 1 || targets["codex@"+liveHome].Options.ConnectorName != "codex" {
			t.Fatalf("pass %d worker targets = %+v", pass, targets)
		}
		if got := f.ledger(t).ProtectedTargets; len(got) != 1 || got[0].User != "live" {
			t.Fatalf("pass %d authorization = %+v", pass, got)
		}
		var retries enterpriseHookWatchRetries
		run.StateErr = nil
		retries.observe("retry", run, nil, time.Now())
		if _, needed := retries.nextDue(); needed {
			t.Fatalf("pass %d kept the removed target in repair attention", pass)
		}
		// An unprivileged fixture can write the legacy pair but cannot pass
		// the managed runtime trust check before the activation receipt.
		// Complete the receipt with the same pass identity for verify.
		state, exists, stateErr := loadEnterpriseHookGuardianState(f.dataDir)
		if stateErr != nil || !exists {
			t.Fatalf("pass %d guardian state: %v, exists=%v", pass, stateErr, exists)
		}
		authorization := f.ledger(t)
		activation := enterpriseHookGuardianActivation{
			Version:          enterpriseHookGuardianActivationVersion,
			UpdatedAt:        state.UpdatedAt,
			ReconcileID:      strings.Repeat("a", 32),
			Manifest:         f.manifest,
			ManifestSHA256:   run.ManifestSHA256,
			OK:               authorization.OK,
			TargetCount:      authorization.TargetCount,
			SuccessCount:     authorization.SuccessCount,
			FailureCount:     authorization.FailureCount,
			PendingCount:     authorization.PendingCount,
			ProtectedTargets: authorization.ProtectedTargets,
		}
		data, err := json.Marshal(activation)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(f.authDir, hookGuardianActivationFile), data, 0o640); err != nil {
			t.Fatal(err)
		}
		verify, err := runEnterpriseHookVerifyAttemptStandaloneUnix(context.Background(), true)
		if err != nil {
			t.Fatalf("pass %d verify: %v", pass, err)
		}
		if verify.AuthorizationErr != nil || verify.Failures != 1 || len(verify.Excused) != 1 || !verify.Rows[1].OK {
			t.Fatalf("pass %d verify = %+v", pass, verify)
		}
	}
}

func TestGAP0693RemovedTransitionRecordedOnce(t *testing.T) {
	row := enterpriseHookReconcileRow{User: "removed", Connector: "hermes", Removed: true,
		Error: `enterprise hooks: target account "removed" does not exist: no such account`}
	var log bytes.Buffer
	logEnterpriseHookRemovedTransitions(&log, nil, []enterpriseHookReconcileRow{row})
	logEnterpriseHookRemovedTransitions(&log, []enterpriseHookReconcileRow{row}, []enterpriseHookReconcileRow{row})
	if count := bytes.Count(log.Bytes(), []byte("target hermes@removed removed:")); count != 1 {
		t.Fatalf("removal transition records = %d, want one: %s", count, log.String())
	}
}
