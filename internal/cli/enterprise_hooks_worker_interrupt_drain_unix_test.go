// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

// GAP-0754: the watch loop interrupts a pass for every new file event. A
// worker killed by that interrupt after it put a hook file or config entry
// back never says so, and the restore is counted, audited and recorded
// nowhere. The guardian dispatch lets a running worker answer first.

func waitForWorkerRepairStart(t *testing.T, home string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(home, "repair-started")); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the worker never began its repair")
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
	waitForWorkerRepairStart(t, account.Home)
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
	waitForWorkerRepairStart(t, account.Home)
	cancel()
	got := <-done
	if !errors.Is(got.err, context.Canceled) || len(got.response.Targets) != 0 {
		t.Fatalf("err = %v, answer = %+v, want a canceled worker with no answer", got.err, got.response.Targets)
	}
}

// A worker that outlasts the drain is killed, so an interrupt never holds
// the guardian for the worker timeout.
func TestEnterpriseHookWorkerInterruptDrainEndsAtItsBound(t *testing.T) {
	useEnterpriseHookWorkerHelper(t, "slow-repair")
	previous := enterpriseHookWorkerInterruptDrain
	enterpriseHookWorkerInterruptDrain = 50 * time.Millisecond
	t.Cleanup(func() { enterpriseHookWorkerInterruptDrain = previous })
	account := selfWorkerAccount(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := startSlowRepairWorker(withEnterpriseHookWorkerInterruptDrain(ctx), account)
	waitForWorkerRepairStart(t, account.Home)
	cancel()
	got := <-done
	if !errors.Is(got.err, context.Canceled) || len(got.response.Targets) != 0 {
		t.Fatalf("err = %v, answer = %+v, want a worker killed at the drain bound", got.err, got.response.Targets)
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
