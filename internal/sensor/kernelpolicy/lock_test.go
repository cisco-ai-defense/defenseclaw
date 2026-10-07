//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package kernelpolicy

import (
	"context"
	"errors"
	"testing"
	"time"
)

func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func loadedFamilies(h *harness) bool {
	for _, family := range []Family{FamilyObserve, FamilyConnect, FamilyControls} {
		if _, ok := h.tg.find(family); !ok {
			return false
		}
	}
	return true
}

// A cleanup that ran while the helper was up (the rollback of an interrupted
// transaction, before the fix that stops the helper first) left the stale
// applied records in the state the helper wrote on its way down. The next
// helper must read them as DefenseClaw's own retirement, not as an
// operator's deletion, and load every family again.
func TestAHelperStartedAfterACleanupLoadsItsPoliciesAgain(t *testing.T) {
	h := enforcing(t)
	if _, err := Cleanup(context.Background(), h.tg, h.dirs); err != nil {
		t.Fatal(err)
	}
	h.start(h.intent) // the old helper's stop persists what it still held
	h.pass()
	if overrides := h.status().Overrides; len(overrides) != 0 {
		t.Fatalf("a DefenseClaw cleanup was read as an operator: %v", overrides)
	}
	if !loadedFamilies(h) {
		t.Fatalf("policies not loaded again: %v", h.tg.names())
	}
}

// A helper in observe or enforce holds the reconciler lock while it runs, so
// a one-shot cleanup is refused instead of removing its policies under it;
// a helper that starts during a cleanup waits for it and then reads the
// record again.
func TestTheReconcilerLockKeepsACleanupAndARunningHelperApart(t *testing.T) {
	h := newHarness(t, observeIntent(), baseTargets)
	h.procs = twoUserProcs()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- h.ctl.Run(ctx) }()
	waitUntil(t, "the start pass", func() bool { return loadedFamilies(h) })
	if _, err := LockForCleanup(h.dirs); !errors.Is(err, ErrReconcilerRunning) {
		t.Fatalf("a cleanup under a running reconciler got %v", err)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}

	unlock, err := LockForCleanup(h.dirs)
	if err != nil {
		t.Fatalf("the lock outlived the helper: %v", err)
	}
	h.start(observeIntent())
	h.tg.take()
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	go func() { done <- h.ctl.Run(ctx) }()
	time.Sleep(20 * time.Millisecond) // several lock retries
	if calls := h.tg.take(); len(calls) != 0 {
		t.Fatalf("the helper reconciled during a cleanup: %v", calls)
	}
	if _, err := Cleanup(context.Background(), h.tg, h.dirs); err != nil {
		t.Fatal(err)
	}
	if len(h.tg.names()) != 0 {
		t.Fatalf("cleanup left %v", h.tg.names())
	}
	unlock()
	waitUntil(t, "the policies to come back", func() bool { return loadedFamilies(h) })
	if overrides := h.status().Overrides; len(overrides) != 0 {
		t.Fatalf("the cleanup was read as an operator: %v", overrides)
	}
	cancel()
	<-done
}
