// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package chainstate

import (
	"slices"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

// GAP-0310 (R13's TestR13ClockStepBackwardStillEnds, failed at 1ab25d7838
// and a632e56828): the running time follows the leader's wall clock, so a
// backward step (an NTP step, a failover onto a node whose clock lags) put
// the egress check before the secret read, and the chain match skips an
// event received after the final one. The running time never goes back
// now: it keeps a high-water mark, saved with the window.
func TestGAP0310ClockStepBackwardKeepsTheRefusal(t *testing.T) {
	t.Parallel()
	h := newHarness(t, t.TempDir(), Options{})
	h.hook(actorA, "s1", secretRead(t))
	h.work(actorA, time.Minute)
	h.advance(-time.Hour)
	h.wantEgressRefused(actorA, "the callout after a 1 h backward step")
	// The window still ends on running time: the step neither freezes the
	// clock nor makes it run back.
	h.work(actorA, 28*time.Minute)
	h.wantEgressRefused(actorA, "29 running minutes")
	if _, a := h.hook(actorA, "s1", projection(t, guardrail.ToolChainSecretReadThenEgress, 2)); !slices.Contains(a.DetectedChainIDs, guardrail.ToolChainSecretReadThenEgress) {
		t.Fatalf("the hook path after a 1 h backward step: actor window %+v, want the chain", a)
	}
	h.work(actorA, 2*time.Minute)
	if v, err := h.egress(actorA); err != nil || v.Deny {
		t.Fatalf("31 running minutes after a backward step: %+v err=%v, want allowed", v, err)
	}
}

// A forward step counts at most one ActiveGap (R13's TestR13ClockStepForward).
func TestGAP0310ClockStepForwardCountsOneGap(t *testing.T) {
	t.Parallel()
	h := newHarness(t, t.TempDir(), Options{})
	h.hook(actorA, "s1", secretRead(t))
	h.work(actorA, time.Minute)
	h.advance(2 * time.Hour)
	h.wantEgressRefused(actorA, "after a 2 h forward step")
}

// A new leader whose clock lags its predecessor's reads the saved mark.
func TestGAP0310NewLeaderWithALaggingClockKeepsTheRefusal(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	h := newHarness(t, dir, Options{})
	h.hook(actorA, "s1", secretRead(t))
	h.work(actorA, time.Minute)
	h.srv.Close()
	_ = h.svc.Close()

	n := newHarness(t, dir, Options{})
	n.now = h.clock().Add(-time.Hour)
	n.wantEgressRefused(actorA, "a new leader 1 h behind")
	if _, a := n.hook(actorA, "s1", projection(t, guardrail.ToolChainSecretReadThenEgress, 2)); !slices.Contains(a.DetectedChainIDs, guardrail.ToolChainSecretReadThenEgress) {
		t.Fatalf("the hook path on a new leader 1 h behind: actor window %+v, want the chain", a)
	}
}
