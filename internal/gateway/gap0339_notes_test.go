// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/chainstate"
)

// GAP-0339 review F3: an unrecorded-step note the leader could not take is
// kept and retried until it lands, the newest note of an actor replacing an
// older one, and given up only after the chain window.
func TestSubstrateNoteIsRetriedUntilTheLeaderTakesIt(t *testing.T) {
	var mu sync.Mutex
	failures, delivered := 3, []string{}
	q := &substrateNoteQueue{every: 5 * time.Millisecond, keep: time.Minute, timeout: time.Second,
		send: func(_ context.Context, n substrateNote) error {
			mu.Lock()
			defer mu.Unlock()
			if failures > 0 {
				failures--
				return errors.New("leader down")
			}
			delivered = append(delivered, n.why)
			return nil
		}}
	a := chainstate.Actor{Atespace: "eng-web", UID: "u1"}
	if err := q.deliver(context.Background(), substrateNote{actor: a, why: "first"}); err == nil {
		t.Fatal("the first send failed but deliver reported none")
	}
	_ = q.deliver(context.Background(), substrateNote{actor: a, why: "second"})
	deadline := time.Now().Add(5 * time.Second)
	for q.pendingCount() > 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if q.pendingCount() != 0 || len(delivered) != 1 || delivered[0] != "second" {
		t.Fatalf("pending %d delivered %v, want the newest note delivered once", q.pendingCount(), delivered)
	}
}

// A note that never lands is given up after the window, with a warning.
func TestSubstrateNoteIsGivenUpAfterTheWindow(t *testing.T) {
	q := &substrateNoteQueue{every: 5 * time.Millisecond, keep: 20 * time.Millisecond, timeout: time.Second,
		send: func(context.Context, substrateNote) error { return errors.New("leader down") }}
	_ = q.deliver(context.Background(), substrateNote{actor: chainstate.Actor{Atespace: "eng-web", UID: "u2"}, why: "x"})
	deadline := time.Now().Add(5 * time.Second)
	for q.pendingCount() > 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if q.pendingCount() != 0 {
		t.Fatalf("a note past its window is still pending")
	}
}
