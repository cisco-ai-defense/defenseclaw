// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package chainstate

import (
	"context"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

// GAP-0292 (lane F20): the chain window counts the actor's running time,
// and the leader measures it from the actor's own requests. Nothing that
// stops the actor without it running ends or ages out the window, whether
// or not the controller reported it.

// work keeps the actor running for d: one intent call a minute, a request
// that adds no window event.
func (h *harness) work(a Actor, d time.Duration) {
	h.t.Helper()
	for done := time.Duration(0); done < d; done += time.Minute {
		h.advance(time.Minute)
		if _, err := h.svc.IntentGet(context.Background(), IntentRequest{Actor: a, Key: "k"}); err != nil {
			h.t.Fatal(err)
		}
	}
}

func (h *harness) wantEgressRefused(a Actor, what string) {
	h.t.Helper()
	v, err := h.egress(a)
	if err != nil || !v.Deny || v.Rule != guardrail.ToolChainSecretReadThenEgress {
		h.t.Fatalf("%s: egress after a secret read: %+v err=%v, want refused", what, v, err)
	}
}

var benign = guardrail.ToolChainProjection{ParseStatus: "not_applicable"}

// SMK J44 (stk push 14): a secret read, the actor stopped 40 minutes, an
// upload. Each row is what one way of stopping it tells the leader.
func TestGAP0292StoppedActorKeepsTheChainWindow(t *testing.T) {
	t.Parallel()
	for _, path := range []struct {
		name          string
		before, after []string // lifecycle events when it stops, when it is back
	}{
		{"raw ate suspend the controller never saw", nil, nil},
		{"idle or task-end suspend: the controller set the state itself and sent only the resume", nil, []string{LifecycleResumed}},
		{"controller restart while suspended: only the resume", nil, []string{LifecycleResumed}},
		{"suspend reported, resume lost", []string{LifecycleSuspended}, nil},
		{"suspend and resume reported", []string{LifecycleSuspended}, []string{LifecycleResumed}},
		{"atelet detach after 30 minutes, sent as a revert", []string{LifecycleSuspended}, []string{LifecycleReverted, LifecycleResumed}},
		{"node drain or eviction", nil, []string{LifecycleCrashed, LifecycleSuspended, LifecycleReverted, LifecycleResumed}},
	} {
		t.Run(path.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t, t.TempDir(), Options{})
			h.hook(actorA, "s1", secretRead(t))
			h.advance(time.Second)
			h.wantEgressRefused(actorA, "before the stop")
			h.advance(time.Minute)
			for _, ev := range path.before {
				h.life(LifecycleEvent{Actor: actorA, Event: ev})
			}
			h.advance(40 * time.Minute)
			for _, ev := range path.after {
				h.life(LifecycleEvent{Actor: actorA, Event: ev})
			}
			h.advance(20 * time.Second)
			h.wantEgressRefused(actorA, "after 40 minutes stopped")
		})
	}
}

// A real revert does not end the egress chain either: the snapshot the
// actor returns to may hold what it read. The session window still takes
// its barrier.
func TestGAP0292RevertKeepsTheEgressChain(t *testing.T) {
	t.Parallel()
	h := newHarness(t, t.TempDir(), Options{})
	h.hook(actorA, "s1", secretRead(t))
	h.advance(time.Second)
	if r := h.life(LifecycleEvent{Actor: actorA, Event: LifecycleReverted}); r.Barriers != 1 {
		t.Fatalf("barriers %+v, want the session window's only", r)
	}
	h.advance(time.Second)
	h.wantEgressRefused(actorA, "after a revert")
	if _, a := h.hook(actorA, "s1", projection(t, guardrail.ToolChainSecretReadThenEgress, 2)); !slices.Contains(a.DetectedChainIDs, guardrail.ToolChainSecretReadThenEgress) {
		t.Fatalf("hook path after a revert: actor window %+v", a)
	}
}

// A new leader on the same volume keeps the window and the clock: what it
// did not save is running time it does not count, never time it adds.
func TestGAP0292LeaderRestartKeepsTheChainWindow(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	h := newHarness(t, dir, Options{})
	h.hook(actorA, "s1", secretRead(t))
	h.work(actorA, 10*time.Minute)
	h.srv.Close()
	_ = h.svc.Close()

	n := newHarness(t, dir, Options{})
	n.now = h.clock().Add(40 * time.Minute)
	n.wantEgressRefused(actorA, "a new leader 40 minutes later")
	n.work(actorA, 31*time.Minute)
	if v, err := n.egress(actorA); err != nil || v.Deny {
		t.Fatalf("31 running minutes on the new leader: %+v err=%v, want allowed", v, err)
	}
}

// The window still ends after 30 minutes of running time (not
// over-tightened).
func TestGAP0292TheWindowStillEndsOnRunningTime(t *testing.T) {
	t.Parallel()
	h := newHarness(t, t.TempDir(), Options{})
	h.hook(actorA, "s1", secretRead(t))
	h.work(actorA, 29*time.Minute)
	h.wantEgressRefused(actorA, "29 running minutes")
	h.work(actorA, 2*time.Minute)
	if v, err := h.egress(actorA); err != nil || v.Deny {
		t.Fatalf("31 running minutes: %+v err=%v, want allowed", v, err)
	}
}

// A long suspend or silence purges an actor's state, but not a window that
// still holds a secret read: an empty state would answer allow.
func TestGAP0292PurgeKeepsAWindowThatHoldsASecretRead(t *testing.T) {
	t.Parallel()
	h := newHarness(t, t.TempDir(), Options{PurgeAfter: time.Hour})
	h.hook(actorA, "s1", secretRead(t))
	h.hook(actorB, "s1", benign)
	h.life(LifecycleEvent{Actor: actorA, Event: LifecycleSuspended})
	h.advance(2 * time.Hour)
	if res, err := h.svc.Sweep(context.Background()); err != nil || res.Purged != 1 {
		t.Fatalf("sweep %+v err=%v, want only the benign actor purged", res, err)
	}
	if _, err := os.Stat(h.svc.statePath(actorA)); err != nil {
		t.Fatalf("the actor with a secret read was purged: %v", err)
	}
	h.wantEgressRefused(actorA, "after the sweep")
}

// The atespace cap evicts an actor whose window holds a secret read last,
// even when it is the least recently used.
func TestGAP0292TheAtespaceCapEvictsASecretReadLast(t *testing.T) {
	t.Parallel()
	h := newHarness(t, t.TempDir(), Options{MaxActors: 2})
	h.hook(actorA, "s1", secretRead(t))
	h.advance(time.Second)
	h.hook(actorB, "s1", benign)
	h.advance(time.Second)
	actorC := Actor{Atespace: actorA.Atespace, UID: "3c0ad1e2-5b7f-4a8e-9d21-6f4b2c8e1a90"}
	h.hook(actorC, "s1", benign)
	if _, err := os.Stat(h.svc.statePath(actorA)); err != nil {
		t.Fatalf("the actor with a secret read was evicted: %v", err)
	}
	if _, err := os.Stat(h.svc.statePath(actorB)); err == nil {
		t.Fatal("the benign actor was kept past the cap")
	}
	h.wantEgressRefused(actorA, "after the cap evicted another actor")
}
