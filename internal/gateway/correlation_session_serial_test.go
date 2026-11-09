// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Attempts of one session never overlap, attempts of different sessions do,
// and a waiter leaves when its context ends (rel-1-0-6 GAP-0490).
func TestHookCorrelationSerialHoldsOneSessionToOneAttempt(t *testing.T) {
	var turns hookCorrelationSerial
	var inside [2]atomic.Int32
	var overlapped, parallel atomic.Bool
	var wg sync.WaitGroup
	for i := 0; i < 80; i++ {
		session := i % 2
		wg.Add(1)
		go func() {
			defer wg.Done()
			release, err := turns.acquire(t.Context(), []string{"claudecode\x00a", "claudecode\x00b"}[session])
			if err != nil {
				t.Error(err)
				return
			}
			defer release()
			if inside[session].Add(1) > 1 {
				overlapped.Store(true)
			}
			if inside[1-session].Load() != 0 {
				parallel.Store(true)
			}
			time.Sleep(time.Millisecond)
			inside[session].Add(-1)
		}()
	}
	wg.Wait()
	if overlapped.Load() {
		t.Fatal("two attempts of one session ran together")
	}
	if !parallel.Load() {
		t.Fatal("attempts of different sessions never ran together")
	}
	turns.mu.Lock()
	defer turns.mu.Unlock()
	if len(turns.entries) != 0 {
		t.Fatalf("%d turn entries left behind", len(turns.entries))
	}
}

func TestHookCorrelationSerialWaiterLeavesWithItsContext(t *testing.T) {
	var turns hookCorrelationSerial
	release, err := turns.acquire(t.Context(), "k")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	if _, err := turns.acquire(ctx, "k"); err == nil {
		t.Fatal("a waiter got the turn while another attempt held it")
	}
	// The cancelled waiter took nothing: the next one gets the turn once the
	// holder leaves, and an extra release is harmless.
	release()
	release()
	next, err := turns.acquire(t.Context(), "k")
	if err != nil {
		t.Fatal(err)
	}
	next()
	turns.mu.Lock()
	defer turns.mu.Unlock()
	if len(turns.entries) != 0 {
		t.Fatalf("%d turn entries left behind", len(turns.entries))
	}
}
