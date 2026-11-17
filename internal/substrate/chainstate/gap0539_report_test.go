// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package chainstate

import (
	"context"
	"testing"
	"time"
)

// A report names known actors only: an unknown or deleted one gets no
// chain state, and a malformed or oversized report changes nothing.
func TestGAP0539RunningReportMakesNoState(t *testing.T) {
	h := newHarness(t, t.TempDir(), Options{})
	if _, err := h.svc.Running(context.Background(), RunningRequest{Actors: []Actor{actorB}}); err != nil {
		t.Fatal(err)
	}
	h.svc.mu.Lock()
	_, made := h.svc.actors[actorB.key()]
	h.svc.mu.Unlock()
	if made {
		t.Fatal("a running report made chain state for an actor the leader did not know")
	}
	if _, err := h.svc.Running(context.Background(), RunningRequest{Actors: []Actor{{Atespace: "Bad Space", UID: "x"}}}); err == nil {
		t.Fatal("a malformed actor was accepted")
	}
	if _, err := h.svc.Running(context.Background(), RunningRequest{Actors: make([]Actor, MaxRunningActors+1)}); err == nil {
		t.Fatal("an oversized report was accepted")
	}
	h.hook(actorA, "s1", secretRead(t))
	h.advance(33 * time.Minute)
	if _, err := h.svc.Running(context.Background(), RunningRequest{Actors: []Actor{actorA, {Atespace: "Bad Space", UID: "x"}}}); err == nil {
		t.Fatal("a report with a malformed actor was accepted")
	}
	h.wantEgressRefused(actorA, "after a refused report")
}
