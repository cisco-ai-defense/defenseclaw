// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package chainstate

import (
	"context"
	"testing"
	"time"
)

// substrate-1 GAP-0539: the chain horizon is 30 minutes of the actor's
// running time, wall time while it runs ("a suspend, however long, doesn't
// count"). A quiet actor that runs (no hook, intent or egress request) ages
// a secret read out of the window when the controller keeps reporting it
// running; one the leader is not told about stays refused (fail closed).

// running is the controller's running report of a, as a ChainRunning call
// the leader serves (an error is ignored: an older leader refuses the
// method, and then the egress stays refused).
func (h *harness) running(a ...Actor) {
	h.t.Helper()
	_ = h.client.call(context.Background(), "ChainRunning", map[string]any{"actors": a}, nil)
}

func (h *harness) egressAllowed(a Actor, what string) {
	h.t.Helper()
	v, err := h.egress(a)
	if err != nil || v.Deny {
		h.t.Fatalf("%s: egress %+v err=%v, want allowed (the secret read is past 30 minutes of running time)", what, v, err)
	}
}

// The J44 control cell on E3: S1 reads a secret, the actor runs 33 minutes
// with no request of its own, S2 uploads.
func TestGAP0539QuietRunningActorAgesTheSecretRead(t *testing.T) {
	h := newHarness(t, t.TempDir(), Options{})
	h.hook(actorA, "s1", secretRead(t))
	for i := 0; i < 33; i++ {
		h.advance(time.Minute)
		h.running(actorA)
	}
	h.egressAllowed(actorA, "33 min running, quiet")
}

func TestGAP0539RunningTimeStopsWithoutAReport(t *testing.T) {
	t.Run("no report (controller outage, or the actor is not running)", func(t *testing.T) {
		h := newHarness(t, t.TempDir(), Options{})
		h.hook(actorA, "s1", secretRead(t))
		h.advance(33 * time.Minute)
		h.wantEgressRefused(actorA, "33 min wall time with no running report")
	})
	t.Run("reported 15 min, suspended 2 h, reported 5 min", func(t *testing.T) {
		h := newHarness(t, t.TempDir(), Options{})
		h.hook(actorA, "s1", secretRead(t))
		for i := 0; i < 15; i++ {
			h.advance(time.Minute)
			h.running(actorA)
		}
		// Suspended for 2 h: not reported running. Like a gap between two
		// requests, at most ActiveGap of it counts (GAP-0292).
		h.advance(2 * time.Hour)
		for i := 0; i < 5; i++ {
			h.advance(time.Minute)
			h.running(actorA)
		}
		h.wantEgressRefused(actorA, "15 + 5 (the 2 h gap counts ActiveGap) + 4 = 24 min running in 2 h 20 min of wall time")
		for i := 0; i < 8; i++ {
			h.advance(time.Minute)
			h.running(actorA)
		}
		h.egressAllowed(actorA, "32 min running")
	})
	t.Run("another actor's report", func(t *testing.T) {
		h := newHarness(t, t.TempDir(), Options{})
		h.hook(actorA, "s1", secretRead(t))
		h.hook(actorB, "s1", benign)
		for i := 0; i < 33; i++ {
			h.advance(time.Minute)
			h.running(actorB)
		}
		h.wantEgressRefused(actorA, "only another actor reported running")
	})
}
