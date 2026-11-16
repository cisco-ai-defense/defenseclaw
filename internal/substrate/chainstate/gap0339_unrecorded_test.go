// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package chainstate

import (
	"context"
	"testing"
	"time"
)

// substrate-1 GAP-0339: an unrecorded tool step a gateway reports is in the
// actor's next egress verdicts for the chain window of running time (a
// suspend doesn't age it), with its reason, and it survives a new leader.
func TestGAP0339UnrecordedStepReachesTheEgressVerdict(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	h := newHarness(t, dir, Options{})
	ctx := context.Background()
	if v, err := h.egress(actorA); err != nil || v.Unrecorded != "" {
		t.Fatalf("before: %+v err=%v", v, err)
	}
	if err := h.client.Unrecorded(ctx, actorA, "the hook event has no correlation"); err != nil {
		t.Fatal(err)
	}
	if v, err := h.egress(actorA); err != nil || v.Unrecorded != "the hook event has no correlation" || v.Deny {
		t.Fatalf("after: %+v err=%v, want the reason and no chain refusal", v, err)
	}
	if v, err := h.egress(actorB); err != nil || v.Unrecorded != "" {
		t.Fatalf("another actor: %+v err=%v", v, err)
	}
	h.srv.Close()
	_ = h.svc.Close()
	n := newHarness(t, dir, Options{})
	n.now = h.clock()
	if v, err := n.egress(actorA); err != nil || v.Unrecorded == "" {
		t.Fatalf("a new leader: %+v err=%v", v, err)
	}
	n.work(actorA, 31*time.Minute)
	if v, err := n.egress(actorA); err != nil || v.Unrecorded != "" {
		t.Fatalf("31 running minutes later: %+v err=%v, want none", v, err)
	}
	if err := n.client.Unrecorded(ctx, Actor{}, "x"); err == nil {
		t.Fatal("an unrecorded step without an actor was accepted")
	}
}
