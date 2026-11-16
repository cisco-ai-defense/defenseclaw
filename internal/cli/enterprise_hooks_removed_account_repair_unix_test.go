//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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

// A reused name must not keep the old UID's authorization when the
// guardian's process resolver still answers with the previous account.
func TestGAP0693ReusedNameRetiresRecordedUID(t *testing.T) {
	oldUID, gid := os.Getuid(), os.Getgid()
	for _, tc := range []struct {
		name       string
		localUID   int
		localErr   error
		uidGone    bool
		wantRetire bool
	}{
		{name: "fresh local name has another UID and old UID is gone", localUID: oldUID + 1, uidGone: true, wantRetire: true},
		{name: "fresh directory search confirms old UID left", localErr: errors.New("local listing unavailable"), uidGone: true, wantRetire: true},
		{name: "directory account shares a name with a local record", localUID: oldUID + 1},
		{name: "same account remains", localUID: oldUID},
		{name: "uncertain local listing", localErr: errors.New("local listing unavailable")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resolver := standaloneTestResolver{accounts: map[string]unixidentity.Account{}}
			f := newStandaloneFixture(t, resolver)
			home := f.home(t, "reused", 0o700)
			resolver.accounts["reused"] = unixidentity.Account{Name: "reused", UID: oldUID, GID: gid, Home: home}
			f.writeManifest(t, enterprisehooks.ManifestTarget{User: "reused", UserHome: home,
				UID: &oldUID, GID: &gid, Connector: "hermes"})
			f.writeLedger(t, protectedRow("reused", home, "hermes"))
			previousLocal, previousNameGone, previousUIDGone := enterpriseHooksEnumerateLocalAccounts,
				enterpriseHookGuardianFreshAccountGone, enterpriseHookRecordedAccountGone
			t.Cleanup(func() {
				enterpriseHooksEnumerateLocalAccounts = previousLocal
				enterpriseHookGuardianFreshAccountGone = previousNameGone
				enterpriseHookRecordedAccountGone = previousUIDGone
			})
			enterpriseHooksEnumerateLocalAccounts = func(context.Context) (map[string]int, error) {
				if tc.localErr != nil {
					return nil, tc.localErr
				}
				return map[string]int{"reused": tc.localUID}, nil
			}
			enterpriseHookGuardianFreshAccountGone = func(context.Context, string) bool { return false }
			enterpriseHookRecordedAccountGone = func(_ context.Context, user string, uid int) bool {
				if user != "reused" || uid != oldUID {
					t.Fatalf("fresh UID check asked for %q uid %d", user, uid)
				}
				return tc.uidGone
			}
			run, err := runEnterpriseHookReconcileOnce(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			requireLedgerOrStateTrust(t, run.StateErr)
			if len(run.Rows) != 1 || run.Rows[0].Removed != tc.wantRetire ||
				run.Rows[0].RevokeProtection != tc.wantRetire || run.Rows[0].OK == tc.wantRetire {
				t.Fatalf("removed disposition = %+v, want retired=%v", run.Rows, tc.wantRetire)
			}
			if got := len(f.ledger(t).ProtectedTargets); (got == 0) != tc.wantRetire {
				t.Fatalf("protected targets = %d, want retired=%v", got, tc.wantRetire)
			}
		})
	}
}

// A target without a manifest UID still has a recorded identity from its
// previous protected pass. Keep that identity through the enumerator's
// catch-up period, including after the first removal revoked its binding.
func TestGAP0693UIDlessTargetUsesPriorRecordedUID(t *testing.T) {
	oldUID, gid := os.Getuid(), os.Getgid()
	for _, tc := range []struct {
		name           string
		uidGone        bool
		withoutBinding bool
		wantRemoved    bool
	}{
		{name: "recorded UID left", uidGone: true, wantRemoved: true},
		{name: "protected record supplies UID", uidGone: true, withoutBinding: true, wantRemoved: true},
		{name: "recorded UID remains", uidGone: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resolver := standaloneTestResolver{accounts: map[string]unixidentity.Account{}}
			f := newStandaloneFixture(t, resolver)
			home := f.home(t, "reused", 0o700)
			resolver.accounts["reused"] = unixidentity.Account{Name: "reused", UID: oldUID, GID: gid, Home: home}
			f.writeManifest(t, enterprisehooks.ManifestTarget{User: "reused", UserHome: home, Connector: "hermes"})
			prior := protectedRow("reused", home, "hermes")
			prior.UID = oldUID
			f.writeLedger(t, prior)
			if !tc.withoutBinding {
				f.writeBindings(t, map[string]enterpriseHookUnixBinding{
					enterpriseHookProtectedTargetKey(prior): {UID: oldUID, Home: home},
				})
			}
			previousLocal, previousNameGone, previousUIDGone := enterpriseHooksEnumerateLocalAccounts,
				enterpriseHookGuardianFreshAccountGone, enterpriseHookRecordedAccountGone
			t.Cleanup(func() {
				enterpriseHooksEnumerateLocalAccounts = previousLocal
				enterpriseHookGuardianFreshAccountGone = previousNameGone
				enterpriseHookRecordedAccountGone = previousUIDGone
			})
			enterpriseHooksEnumerateLocalAccounts = func(context.Context) (map[string]int, error) {
				return map[string]int{"reused": oldUID + 1}, nil
			}
			enterpriseHookGuardianFreshAccountGone = func(context.Context, string) bool { return false }
			enterpriseHookRecordedAccountGone = func(_ context.Context, user string, uid int) bool {
				if user != "reused" || uid != oldUID {
					t.Fatalf("fresh UID check asked for %q uid %d", user, uid)
				}
				return tc.uidGone
			}
			for pass := 0; pass < 2; pass++ {
				run, err := runEnterpriseHookReconcileOnce(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				requireLedgerOrStateTrust(t, run.StateErr)
				if len(run.Rows) != 1 || run.Rows[0].Removed != tc.wantRemoved ||
					run.Rows[0].RevokeProtection != tc.wantRemoved || run.Rows[0].OK == tc.wantRemoved {
					t.Fatalf("pass %d disposition = %+v, want removed=%v", pass, run.Rows, tc.wantRemoved)
				}
				if run.Rows[0].Removed && run.Rows[0].UID != oldUID {
					t.Fatalf("pass %d removed UID = %d, want %d", pass, run.Rows[0].UID, oldUID)
				}
				if got := len(f.ledger(t).ProtectedTargets); (got == 0) != tc.wantRemoved {
					t.Fatalf("pass %d protected targets = %d, want removed=%v", pass, got, tc.wantRemoved)
				}
			}
		})
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

func TestGAP0693DirectoryMissIsBoundToTheConnector(t *testing.T) {
	f := newStandaloneFixture(t, standaloneTestResolver{accounts: map[string]unixidentity.Account{}})
	if err := enterprisehooks.SaveUnixEnumeratorState(enterpriseHookEnumeratorStatePath(f.manifest),
		&enterprisehooks.UnixEnumeratorState{Version: 1, Sources: map[string]string{"removed": "directory"},
			Misses: map[string]int{"removed\x00hermes": 1}}); err != nil {
		t.Fatal(err)
	}
	previousLocal, previousProof := enterpriseHooksEnumerateLocalAccounts, enterpriseHookGuardianFreshAccountGone
	t.Cleanup(func() {
		enterpriseHooksEnumerateLocalAccounts, enterpriseHookGuardianFreshAccountGone = previousLocal, previousProof
	})
	enterpriseHooksEnumerateLocalAccounts = func(context.Context) (map[string]int, error) { return map[string]int{}, nil }
	enterpriseHookGuardianFreshAccountGone = func(context.Context, string) bool { return false }
	row := enterpriseHookReconcileRow{User: "removed", Connector: "hermes",
		Error: `enterprise hooks: target account "removed" does not exist: no such account`}
	if !enterpriseHookRemovedAccountRow(row) {
		t.Fatal("confirmed directory miss was kept in attention")
	}
	row.Connector = "codex"
	if enterpriseHookRemovedAccountRow(row) {
		t.Fatal("a different connector inherited a removal proof")
	}
}
