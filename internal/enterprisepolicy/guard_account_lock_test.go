// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The per-account removal lock (1.0.4 guard consolidation, GAP-0348,
// GAP-0414): a pending removal blocks new online answers of its account
// only, an answer inside the lock finishes before the removal goes on (or
// the removal goes on after a bounded wait), and anything the lock cannot
// be taken for denies.
func TestForeignHookAccountLockIsWriterPreferredPerAccount(t *testing.T) {
	dataDir := t.TempDir()
	short := func() (context.Context, context.CancelFunc) {
		return context.WithTimeout(context.Background(), 100*time.Millisecond)
	}

	// Exchanges of one account share the lock.
	ctx, cancel := short()
	first, err := LockForeignHookAccountExchange(ctx, dataDir, "1001")
	cancel()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel = short()
	second, err := LockForeignHookAccountExchange(ctx, dataDir, "1001")
	cancel()
	if err != nil {
		t.Fatalf("two exchanges of one account must share the lock: %v", err)
	}
	second()

	// A removal waits for the exchange inside; while it waits, a new
	// exchange of the account is denied (writer preferred), and another
	// account's exchange is not delayed.
	type result struct {
		release func()
		drained bool
		err     error
		at      time.Time
	}
	done := make(chan result, 1)
	go func() {
		release, drained, err := LockForeignHookAccountRemoval(context.Background(), dataDir, "1001")
		done <- result{release, drained, err, time.Now()}
	}()
	time.Sleep(50 * time.Millisecond)
	ctx, cancel = short()
	_, err = LockForeignHookAccountExchange(ctx, dataDir, "1001")
	cancel()
	if !errors.Is(err, ErrForeignHookRemovalPending) {
		t.Fatalf("a new exchange while a removal waits must be denied as pending: %v", err)
	}
	ctx, cancel = short()
	other, err := LockForeignHookAccountExchange(ctx, dataDir, "1002")
	cancel()
	if err != nil {
		t.Fatalf("another account must not wait on this account's removal: %v", err)
	}
	other()
	released := time.Now()
	first()
	got := <-done
	if got.err != nil || !got.drained || got.at.Before(released) {
		t.Fatalf("the removal must take the lock once the exchange inside is done: %+v", got)
	}
	ctx, cancel = short()
	_, err = LockForeignHookAccountExchange(ctx, dataDir, "1001")
	cancel()
	if !errors.Is(err, ErrForeignHookRemovalPending) {
		t.Fatalf("an exchange while the removal holds the lock must be denied as pending: %v", err)
	}
	got.release()
	ctx, cancel = short()
	after, err := LockForeignHookAccountExchange(ctx, dataDir, "1001")
	cancel()
	if err != nil {
		t.Fatalf("the exchange after the removal must get the lock: %v", err)
	}
	after()
}

// An exchange that does not finish delays a removal by at most
// ForeignHookRemovalDrainWait; the removal then goes on with the gate held,
// so no new exchange gets in.
func TestForeignHookAccountRemovalWaitIsBounded(t *testing.T) {
	dataDir := t.TempDir()
	stuck, err := LockForeignHookAccountExchange(context.Background(), dataDir, "1001")
	if err != nil {
		t.Fatal(err)
	}
	defer stuck()
	start := time.Now()
	release, drained, err := LockForeignHookAccountRemoval(context.Background(), dataDir, "1001")
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if waited := time.Since(start); drained || waited < ForeignHookRemovalDrainWait || waited > ForeignHookRemovalDrainWait+2*time.Second {
		t.Fatalf("drained %v after %s, want not drained after about %s", drained, waited, ForeignHookRemovalDrainWait)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := LockForeignHookAccountExchange(ctx, dataDir, "1001"); !errors.Is(err, ErrForeignHookRemovalPending) {
		t.Fatalf("the gate must keep new exchanges out: %v", err)
	}
	if ForeignHookExchangeHold >= ForeignHookRemovalDrainWait || ForeignHookExchangeWait >= ForeignHookRemovalDrainWait {
		t.Fatal("an exchange must answer, or give up, before a removal stops waiting for it")
	}
}

// A lock that cannot be taken for another reason (the lock path is a
// folder, or the identity names no account) is an error, which denies;
// it is not a removal in progress.
func TestForeignHookAccountLockThatCannotBeTakenDenies(t *testing.T) {
	dataDir := t.TempDir()
	gate, _, ok := ForeignHookAccountLockPaths(dataDir, "1001")
	if !ok {
		t.Fatal("no lock paths")
	}
	if err := os.MkdirAll(gate, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := LockForeignHookAccountExchange(context.Background(), dataDir, "1001"); err == nil || errors.Is(err, ErrForeignHookRemovalPending) {
		t.Fatalf("a folder at the lock path must deny as unverifiable: %v", err)
	}
	if _, _, err := LockForeignHookAccountRemoval(context.Background(), dataDir, "1001"); err == nil {
		t.Fatal("a removal must not go on without the lock")
	}
	if _, err := LockForeignHookAccountExchange(context.Background(), dataDir, "not-an-account"); err == nil {
		t.Fatal("an identity that names no account has no lock")
	}
	if _, err := LockForeignHookAccountExchange(context.Background(), filepath.Join(dataDir, "missing", "data"), "1002"); err == nil {
		t.Fatal("a data directory that does not exist must deny")
	}
}
