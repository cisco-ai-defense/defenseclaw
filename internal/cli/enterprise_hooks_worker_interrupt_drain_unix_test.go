// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

// GAP-0754: the watch loop interrupts a pass for every new file event. A
// worker killed by that interrupt after it put a hook file or config entry
// back never says so, and the restore is counted, audited and recorded
// nowhere. The guardian dispatch lets a running worker answer first.

func waitForWorkerMarker(t *testing.T, home, marker string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(home, marker)); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the worker never wrote %s", marker)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

type slowRepairAnswer struct {
	response enterpriseHookWorkerResponse
	err      error
}

// startSlowRepairWorker runs one worker that repairs a previously protected
// hermes target slowly, and returns the channel its answer arrives on.
func startSlowRepairWorker(ctx context.Context, account enterpriseHookWorkerAccount) <-chan slowRepairAnswer {
	done := make(chan slowRepairAnswer, 1)
	go func() {
		response, err := runEnterpriseHookWorker(ctx, account, enterpriseHookWorkerRequest{
			Operation:  enterpriseHookWorkerOpApply,
			Standalone: true,
			Targets:    []enterpriseHookWorkerTarget{workerTarget(account, 1, enterpriseHookWorkerModeVerifyOrRepair, "hermes", true)},
		})
		done <- slowRepairAnswer{response, err}
	}()
	return done
}

// The interrupt arrives while the worker is repairing: its answer is kept.
func TestEnterpriseHookWorkerInterruptDrainKeepsTheAnswerOfARunningRepair(t *testing.T) {
	useEnterpriseHookWorkerHelper(t, "slow-repair")
	account := selfWorkerAccount(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := startSlowRepairWorker(withEnterpriseHookWorkerInterruptDrain(ctx), account)
	waitForWorkerMarker(t, account.Home, "repair-started")
	cancel()
	got := <-done
	if got.err != nil {
		t.Fatalf("a worker that finished its repair after the interrupt lost its answer: %v", got.err)
	}
	if len(got.response.Targets) != 1 || !got.response.Targets[0].OK || !got.response.Targets[0].Repaired {
		t.Fatalf("answer = %+v, want one repaired target", got.response.Targets)
	}
}

// A caller that did not ask for the drain still kills the worker at once.
func TestEnterpriseHookWorkerWithoutInterruptDrainIsKilledByTheCancel(t *testing.T) {
	useEnterpriseHookWorkerHelper(t, "slow-repair")
	account := selfWorkerAccount(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := startSlowRepairWorker(ctx, account)
	waitForWorkerMarker(t, account.Home, "repair-started")
	cancel()
	got := <-done
	if !errors.Is(got.err, context.Canceled) || len(got.response.Targets) != 0 {
		t.Fatalf("err = %v, answer = %+v, want a canceled worker with no answer", got.err, got.response.Targets)
	}
}

// startSlowCheckWorkers runs one worker for two protected targets of one
// account: hermes is put back at once, the claudecode check then takes
// seconds. It returns the channel the worker's answer arrives on.
func startSlowCheckWorkers(ctx context.Context, account enterpriseHookWorkerAccount) <-chan slowRepairAnswer {
	done := make(chan slowRepairAnswer, 1)
	go func() {
		response, err := runEnterpriseHookWorker(ctx, account, enterpriseHookWorkerRequest{
			Operation:  enterpriseHookWorkerOpApply,
			Standalone: true,
			Targets: []enterpriseHookWorkerTarget{
				workerTarget(account, 1, enterpriseHookWorkerModeVerifyOrRepair, "hermes", true),
				workerTarget(account, 2, enterpriseHookWorkerModeVerifyOrRepair, "claudecode", true),
			},
		})
		done <- slowRepairAnswer{response, err}
	}()
	return done
}

func shortenInterruptDrain(t *testing.T) {
	t.Helper()
	previous := enterpriseHookWorkerInterruptDrain
	enterpriseHookWorkerInterruptDrain = 50 * time.Millisecond
	t.Cleanup(func() { enterpriseHookWorkerInterruptDrain = previous })
}

// A worker that is not repairing anything and outlasts the drain is killed,
// so an interrupt never holds the guardian for the worker timeout.
func TestEnterpriseHookWorkerInterruptDrainEndsAtItsBound(t *testing.T) {
	useEnterpriseHookWorkerHelper(t, "slow-verify")
	shortenInterruptDrain(t)
	account := selfWorkerAccount(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := startSlowRepairWorker(withEnterpriseHookWorkerInterruptDrain(ctx), account)
	waitForWorkerMarker(t, account.Home, "verify-started")
	started := time.Now()
	cancel()
	got := <-done
	if !errors.Is(got.err, context.Canceled) || len(got.response.Targets) != 0 {
		t.Fatalf("err = %v, answer = %+v, want a worker killed at the drain bound", got.err, got.response.Targets)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("the worker was held for %s after the interrupt", elapsed)
	}
}

// A worker in the middle of a repair is not killed at the drain bound,
// however long that repair takes within the worker timeout: the restore it
// makes is accounted when it ends.
func TestEnterpriseHookWorkerInterruptDrainWaitsForARepairUnderWay(t *testing.T) {
	useEnterpriseHookWorkerHelper(t, "slow-repair")
	shortenInterruptDrain(t)
	account := selfWorkerAccount(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := startSlowRepairWorker(withEnterpriseHookWorkerInterruptDrain(ctx), account)
	waitForWorkerMarker(t, account.Home, "repair-started")
	cancel()
	got := <-done
	if len(got.response.Targets) != 1 || !got.response.Targets[0].OK || !got.response.Targets[0].Repaired {
		t.Fatalf("err = %v, answer = %+v, want the repair that was under way kept", got.err, got.response.Targets)
	}
}

// A worker killed at the drain bound while it checks another target has no
// answer to give, but the target it already put back is kept, with the error
// that says the worker was interrupted.
func TestEnterpriseHookWorkerKilledAtTheBoundKeepsTheTargetsItRepaired(t *testing.T) {
	useEnterpriseHookWorkerHelper(t, "slow-second")
	shortenInterruptDrain(t)
	account := selfWorkerAccount(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := startSlowCheckWorkers(withEnterpriseHookWorkerInterruptDrain(ctx), account)
	waitForWorkerMarker(t, account.Home, "verify-started")
	cancel()
	got := <-done
	if !errors.Is(got.err, context.Canceled) {
		t.Fatalf("err = %v, want the worker reported as interrupted", got.err)
	}
	if len(got.response.Targets) != 1 || got.response.Targets[0].Index != 1 ||
		!got.response.Targets[0].OK || !got.response.Targets[0].Repaired || got.response.Targets[0].Result == nil {
		t.Fatalf("kept targets = %+v, want the hermes repair only", got.response.Targets)
	}
}

// The twin: a caller that did not ask for the drain gets no kept target from
// a worker it killed, as before.
func TestEnterpriseHookWorkerKilledWithoutTheDrainKeepsNothing(t *testing.T) {
	useEnterpriseHookWorkerHelper(t, "slow-second")
	account := selfWorkerAccount(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := startSlowCheckWorkers(ctx, account)
	waitForWorkerMarker(t, account.Home, "verify-started")
	cancel()
	got := <-done
	if !errors.Is(got.err, context.Canceled) || len(got.response.Targets) != 0 {
		t.Fatalf("err = %v, answer = %+v, want a killed worker with nothing kept", got.err, got.response.Targets)
	}
}

// With nobody interrupting, the worker answers for both targets as before
// (the progress lines do not reach the answer).
func TestEnterpriseHookWorkerAnswersBothTargetsAfterProgressLines(t *testing.T) {
	useEnterpriseHookWorkerHelper(t, "slow-second")
	account := selfWorkerAccount(t)
	got := <-startSlowCheckWorkers(withEnterpriseHookWorkerInterruptDrain(context.Background()), account)
	if got.err != nil || len(got.response.Targets) != 2 {
		t.Fatalf("err = %v, answer = %+v, want both targets answered", got.err, got.response.Targets)
	}
	if !got.response.Targets[0].Repaired || got.response.Targets[1].Repaired {
		t.Fatalf("answer = %+v, want hermes repaired and claudecode verified", got.response.Targets)
	}
}

// A worker that has not started when the interrupt arrives never starts.
func TestEnterpriseHookWorkerInterruptDrainDoesNotStartAfterTheInterrupt(t *testing.T) {
	useEnterpriseHookWorkerHelper(t, "slow-repair")
	account := selfWorkerAccount(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := runEnterpriseHookWorker(withEnterpriseHookWorkerInterruptDrain(ctx), account, enterpriseHookWorkerRequest{
		Operation:  enterpriseHookWorkerOpApply,
		Standalone: true,
		Targets:    []enterpriseHookWorkerTarget{workerTarget(account, 1, enterpriseHookWorkerModeVerifyOrRepair, "hermes", true)},
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if _, statErr := os.Stat(filepath.Join(account.Home, "repair-started")); statErr == nil {
		t.Fatal("a worker started after the interrupt")
	}
}

// The whole pass: an event interrupts it while the worker restores a hook
// target, and the interrupted pass still counts, records and returns the
// restore.
func TestStandaloneInterruptedPassCountsRestoreOfWorkerStillRunning(t *testing.T) {
	useEnterpriseHookWorkerHelper(t, "slow-repair")
	shortenInterruptDrain(t) // the repair outlasts the drain bound
	uid, gid := os.Getuid(), os.Getgid()
	resolver := standaloneTestResolver{accounts: map[string]unixidentity.Account{}, transient: map[string]bool{}}
	f := newStandaloneFixture(t, resolver)
	enterpriseHookWorkerRunner = runEnterpriseHookWorker // the fixture restores its own
	home := f.home(t, "alice", 0o700)
	resolver.accounts["alice"] = unixidentity.Account{Name: "alice", UID: uid, GID: gid, Home: home, Shell: "/bin/bash"}
	f.writeManifest(t, enterprisehooks.ManifestTarget{User: "alice", Connector: "hermes"})
	f.writeLedger(t, protectedRow("alice", home, "hermes"))
	key := enterpriseHookProtectedTargetKey(enterpriseHookReconcileRow{User: "alice", Connector: "hermes"})
	f.writeBindings(t, map[string]enterpriseHookUnixBinding{key: {UID: uid, Home: home, LockUpdatedAt: "L", EntryUpdatedAt: "E"}})
	interrupt, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		deadline := time.Now().Add(20 * time.Second)
		for time.Now().Before(deadline) {
			if _, err := os.Stat(filepath.Join(home, "repair-started")); err == nil {
				cancel() // an event preempts the pass while the worker repairs
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()
	run, err := runEnterpriseHookReconcileOnce(interrupt)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("interrupted pass error = %v, rows = %+v", err, run.Rows)
	}
	if run.Repairs != 1 || len(run.RepairedTargets) != 1 {
		t.Fatalf("repairs = %d (%v), want 1", run.Repairs, run.RepairedTargets)
	}
	if restores := guardianRestoresForTest(t, f.dataDir); len(restores) != 1 {
		t.Fatalf("restore entries = %v, want 1", restores)
	}
}

// The whole pass, one account with two protected targets: an event interrupts
// the pass while the worker checks the second, after it put the first back.
// The worker is killed at the drain bound, and the pass still counts, records
// and returns the restore it made.
func TestStandaloneInterruptedPassCountsRestoreOfWorkerKilledOnAnotherTarget(t *testing.T) {
	useEnterpriseHookWorkerHelper(t, "slow-second")
	shortenInterruptDrain(t)
	uid, gid := os.Getuid(), os.Getgid()
	resolver := standaloneTestResolver{accounts: map[string]unixidentity.Account{}, transient: map[string]bool{}}
	f := newStandaloneFixture(t, resolver)
	enterpriseHookWorkerRunner = runEnterpriseHookWorker // the fixture restores its own
	home := f.home(t, "alice", 0o700)
	resolver.accounts["alice"] = unixidentity.Account{Name: "alice", UID: uid, GID: gid, Home: home, Shell: "/bin/bash"}
	f.writeManifest(t,
		enterprisehooks.ManifestTarget{User: "alice", Connector: "hermes"},
		enterprisehooks.ManifestTarget{User: "alice", Connector: "claudecode"},
	)
	f.writeLedger(t, protectedRow("alice", home, "hermes"), protectedRow("alice", home, "claudecode"))
	bindings := map[string]enterpriseHookUnixBinding{}
	for _, name := range []string{"hermes", "claudecode"} {
		key := enterpriseHookProtectedTargetKey(enterpriseHookReconcileRow{User: "alice", Connector: name})
		bindings[key] = enterpriseHookUnixBinding{UID: uid, Home: home, LockUpdatedAt: "L", EntryUpdatedAt: "E"}
	}
	f.writeBindings(t, bindings)
	interrupt, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		deadline := time.Now().Add(20 * time.Second)
		for time.Now().Before(deadline) {
			if _, err := os.Stat(filepath.Join(home, "verify-started")); err == nil {
				cancel() // an event preempts the pass while the worker checks claudecode
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()
	run, err := runEnterpriseHookReconcileOnce(interrupt)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("interrupted pass error = %v, rows = %+v", err, run.Rows)
	}
	if run.Repairs != 1 || len(run.RepairedTargets) != 1 {
		t.Fatalf("repairs = %d (%v), want 1: hermes only", run.Repairs, run.RepairedTargets)
	}
	restores := guardianRestoresForTest(t, f.dataDir)
	if len(restores) != 1 {
		t.Fatalf("restore entries = %v, want the hermes restore only", restores)
	}
	for key := range restores {
		if !strings.Contains(strings.ToLower(key), "hermes") {
			t.Fatalf("restore entry %q, want the hermes restore", key)
		}
	}
}
