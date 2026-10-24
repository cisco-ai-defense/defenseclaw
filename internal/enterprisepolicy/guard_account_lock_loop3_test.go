// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"context"
	"testing"
	"time"
)

// Review P2 (1.0.4 guard loop round 3): a removal goes on past an exchange
// still inside the account's lock only once that exchange's answer
// deadline has passed, so the drain must get its whole wait whatever is
// left of the caller's context. A worker whose context ends a moment after
// it took the gate (its deadline, or a cancel) still waits for the
// exchange inside: it reports drained once the exchange let go, and gives
// up only after ForeignHookRemovalDrainWait.
func TestForeignHookAccountRemovalDrainIgnoresTheCallersDeadline(t *testing.T) {
	for name, ending := range map[string]func() (context.Context, context.CancelFunc){
		"deadline": func() (context.Context, context.CancelFunc) {
			return context.WithTimeout(context.Background(), 100*time.Millisecond)
		},
		"cancel": func() (context.Context, context.CancelFunc) {
			ctx, cancel := context.WithCancel(context.Background())
			time.AfterFunc(100*time.Millisecond, cancel)
			return ctx, cancel
		},
	} {
		t.Run(name, func(t *testing.T) {
			dataDir := t.TempDir()
			inside, err := LockForeignHookAccountExchange(context.Background(), dataDir, "1001")
			if err != nil {
				t.Fatal(err)
			}
			hold := 600 * time.Millisecond
			time.AfterFunc(hold, inside)
			ctx, cancel := ending()
			defer cancel()
			start := time.Now()
			release, drained, err := LockForeignHookAccountRemoval(ctx, dataDir, "1001")
			if err != nil {
				t.Fatalf("a removal whose caller's context ended during the drain: %v", err)
			}
			defer release()
			if waited := time.Since(start); !drained || waited < hold {
				t.Fatalf("drained %v after %s: the drain must wait for the exchange inside (%s) past the caller's context", drained, waited, hold)
			}
		})
	}

	// An exchange that never lets go is waited for the whole drain wait.
	dataDir := t.TempDir()
	stuck, err := LockForeignHookAccountExchange(context.Background(), dataDir, "1001")
	if err != nil {
		t.Fatal(err)
	}
	defer stuck()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	release, drained, err := LockForeignHookAccountRemoval(ctx, dataDir, "1001")
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if waited := time.Since(start); drained || waited < ForeignHookRemovalDrainWait {
		t.Fatalf("drained %v after %s, want not drained after the whole %s", drained, waited, ForeignHookRemovalDrainWait)
	}
}
