// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"testing"
	"time"
)

// A config reload cancels the recovery loop of the old server while the
// loop of the new one waits for a wake. A row a handler leaves then is
// audited by the new server's loop: the wake reaches every running loop,
// so the canceled one cannot take it. Before, the one process-wide wake
// went to the loop that had waited longest, the old one, which exited
// without a pass, and the row stayed until another wake, a full journal or
// a restart.
func TestPendingHookRecoveryWakeReachesTheLoopOfTheReloadedServer(t *testing.T) {
	f := newManagedHookAuditFixture(t, nil)
	interval := pendingHookRecoveryRetryInterval
	t.Cleanup(func() { pendingHookRecoveryRetryInterval = interval })
	serve := func(a *APIServer) (stop func()) {
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan error, 1)
		go func() { done <- a.Run(ctx) }()
		stopped := false
		stop = func() {
			if !stopped {
				stopped = true
				cancel()
				<-done
			}
		}
		t.Cleanup(stop)
		return stop
	}
	// waitIdle waits until the start pass of a loop audited the row of
	// session, then for the loop to wait for its next wake.
	waitIdle := func(session string) {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for f.hookRows(t, session) != 1 || len(pendingEntries(t, f)) != 0 {
			if time.Now().After(deadline) {
				t.Fatalf("the start pass did not audit %s", session)
			}
			time.Sleep(20 * time.Millisecond)
		}
		time.Sleep(200 * time.Millisecond)
	}
	// The old server's loop would take a row left for it an hour after the
	// wake; the reload cancels it first.
	pendingHookRecoveryRetryInterval = time.Hour
	orphanPendingHook(t, f, "before-the-old-server", pendingAllow)
	stopOld := serve(f.restartedAPI(t, true))
	waitIdle("before-the-old-server")
	pendingHookRecoveryRetryInterval = 100 * time.Millisecond
	orphanPendingHook(t, f, "before-the-reloaded-server", pendingAllow)
	serve(f.restartedAPI(t, true))
	waitIdle("before-the-reloaded-server")

	const session = "left-during-the-reload"
	orphanPendingHook(t, f, session, pendingAllow)
	wakePendingHookRecovery() // as the handler that left the row does
	time.Sleep(100 * time.Millisecond)
	stopOld()
	deadline := time.Now().Add(5 * time.Second)
	for len(pendingEntries(t, f)) != 0 {
		if time.Now().After(deadline) {
			t.Fatal("the row a handler left during the reload stayed: the reloaded server's loop got no wake")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got, rows := f.audited(t, session)[session], f.hookRows(t, session); got != "unconfirmed/no_answer" || rows != 1 {
		t.Fatalf("recovered audit %q in %d rows, want unconfirmed/no_answer once", got, rows)
	}
}
