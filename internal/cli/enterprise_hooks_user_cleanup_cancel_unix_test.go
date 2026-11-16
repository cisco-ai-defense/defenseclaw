//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"testing"
	"time"
)

// A pass cancelled while a cleanup worker ran (a newer pass superseded it, or
// the service is stopping) did not find the cleanup failing: the entry is
// carried unchanged, with no recorded error, so the next pass retries at once
// and not after the retry interval.
func TestUserCleanupAttemptCutShortByACancelledPassIsNotAFailure(t *testing.T) {
	entry := enterpriseHookUserCleanup{Connector: "hermes", User: "sample-user", UID: 1001, UserHome: "/Users/sample-user"}
	cancelled := errors.New("worker for uid 1001 timed out: context canceled")
	now := time.Now()

	ctx, cancel := context.WithCancel(context.Background())
	remaining, result := runEnterpriseHookUserCleanups(ctx, []enterpriseHookUserCleanup{entry},
		func(context.Context, enterpriseHookUserCleanup) (enterpriseHookUserCleanupOutcome, error) {
			cancel()
			return enterpriseHookUserCleanupFailed, cancelled
		}, now)
	if len(remaining) != 1 || remaining[0].LastError != "" || remaining[0].Attempts != 0 ||
		len(result.Failed) != 0 || len(result.Pending) != 1 {
		t.Fatalf("a cancelled attempt was recorded as a failure: remaining %+v, result %+v", remaining, result)
	}
	if enterpriseHookUserCleanupBackingOff(remaining[0], now.Add(time.Second)) {
		t.Fatal("a cancelled attempt put the cleanup into the retry interval")
	}

	// Benign twin: the same error on a live pass is a real failure, recorded
	// and backed off as before.
	remaining, result = runEnterpriseHookUserCleanups(context.Background(), []enterpriseHookUserCleanup{entry},
		func(context.Context, enterpriseHookUserCleanup) (enterpriseHookUserCleanupOutcome, error) {
			return enterpriseHookUserCleanupFailed, cancelled
		}, now)
	if len(remaining) != 1 || remaining[0].LastError == "" || remaining[0].Attempts != 1 || len(result.Failed) != 1 ||
		!enterpriseHookUserCleanupBackingOff(remaining[0], now.Add(time.Second)) {
		t.Fatalf("a failure on a live pass changed: remaining %+v, result %+v", remaining, result)
	}

	// A cleanup that finished before the pass was cancelled is done.
	ctx, cancel = context.WithCancel(context.Background())
	remaining, result = runEnterpriseHookUserCleanups(ctx, []enterpriseHookUserCleanup{entry},
		func(context.Context, enterpriseHookUserCleanup) (enterpriseHookUserCleanupOutcome, error) {
			cancel()
			return enterpriseHookUserCleanupDone, nil
		}, now)
	if len(remaining) != 0 || len(result.Removed) != 1 {
		t.Fatalf("a finished cleanup was kept: remaining %+v, result %+v", remaining, result)
	}
}

// The cleanup worker removes files the previous run owned. The watch pump
// must read those removals as work of this pass for the whole pass (GAP-0842:
// each removal cancelled the pass, which killed the worker with "context
// canceled" and left the files for a retry five minutes later), while a
// change to another account still preempts the pass.
func TestStandaloneCleanupWorkerHoldsItsTargetForTheWatchPass(t *testing.T) {
	removed := enterpriseHookReconcileRow{User: "sample-user", UserHome: "/Users/sample-user", Connector: "hermes"}
	other := enterpriseHookReconcileRow{User: "other-user", UserHome: "/Users/other-user", Connector: "hermes"}
	hook := "/Users/sample-user/.defenseclaw/hooks/hermes-hook.sh"
	otherHook := "/Users/other-user/.defenseclaw/hooks/hermes-hook.sh"
	prior := enterpriseHookReconcileRun{
		Rows: []enterpriseHookReconcileRow{removed, other},
		WatchPathOwners: map[string][]string{
			hook:      {enterpriseHookProtectedTargetKey(removed)},
			otherHook: {enterpriseHookProtectedTargetKey(other)},
		},
	}
	active := newEnterpriseHookWatchActiveWorkers(prior)
	ctx := context.WithValue(context.Background(), enterpriseHookWatchActiveWorkersKey{}, active)

	var during bool
	previous := enterpriseHookWorkerRunner
	t.Cleanup(func() { enterpriseHookWorkerRunner = previous })
	enterpriseHookWorkerRunner = func(context.Context, enterpriseHookWorkerAccount, enterpriseHookWorkerRequest) (enterpriseHookWorkerResponse, error) {
		during, _ = active.state(hook)
		return enterpriseHookWorkerResponse{}, errors.New("stub")
	}
	entry := enterpriseHookUserCleanup{Connector: "hermes", User: "sample-user", UID: 1001, UserHome: "/Users/sample-user"}
	account := enterpriseHookWorkerAccount{UID: 1001, GID: 20, User: "sample-user", Home: "/Users/sample-user"}
	runEnterpriseHookStandaloneCleanupWorker(ctx, entry, account, "/Users/sample-user/.defenseclaw")

	if !during {
		t.Fatal("the removed target was not held active while its cleanup worker ran")
	}
	if after, _ := active.state(hook); !after {
		t.Fatal("a late event for a file the cleanup removed would cancel the next cleanup of the pass")
	}
	if others, _ := active.state(otherHook); others {
		t.Fatal("the hold covered another account; a change there must still preempt the pass")
	}

	// Benign twin: a pass without a watch registry (the one-shot reconcile
	// and the uninstall) runs the worker as before.
	if _, _, err := runEnterpriseHookStandaloneCleanupWorker(context.Background(), entry, account, "/Users/sample-user/.defenseclaw"); err == nil {
		t.Fatal("the stubbed worker error was lost")
	}
}
