// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"testing"
	"time"
)

// GAP-1822: the arrival wait uses no gateway CPU, so the call gives its
// caller's run slot up for the window and takes it back after.
func TestSessionStartArrivalWaitGivesUpTheRunSlot(t *testing.T) {
	run := make(chan struct{}, 1)
	run <- struct{}{}
	slot := &hookRunSlot{run: run, held: true}
	ctx := context.WithValue(context.Background(), hookRunSlotContextKey{}, slot)
	var gate sessionStartGate
	free := make(chan bool, 1)
	go func() {
		select {
		case run <- struct{}{}:
			<-run
			free <- true
		case <-time.After(5 * time.Second):
			free <- false
		}
	}()
	if reason, refuse := gate.await(ctx, "codex\x00\x00unseen", 10*time.Second, time.Second, func(context.Context) (bool, string) { return false, "" }); refuse {
		t.Fatalf("allowed judged start refused: %s", reason)
	}
	if !<-free {
		t.Fatal("the run slot stayed held for the whole arrival window")
	}
	slot.mu.Lock()
	held := slot.held
	slot.mu.Unlock()
	if !held || len(run) != 1 {
		t.Fatalf("the run slot was not taken back: held=%t tokens=%d", held, len(run))
	}
}
