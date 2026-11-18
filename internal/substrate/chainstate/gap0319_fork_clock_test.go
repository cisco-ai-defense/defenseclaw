// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package chainstate

import (
	"bytes"
	"testing"
	"time"
)

// GAP-0319: the controller stamps a fork event with its own clock. A
// controller clock ahead of the leader's must not move the child's running
// time forward: the child keeps the parent's high-water mark (forkClock),
// so the secret read it inherits stays in its window and the child's next
// egress is still refused.
func TestGAP0319ForkChildKeepsTheParentClockUnderControllerSkew(t *testing.T) {
	for _, skew := range []time.Duration{0, 10 * time.Minute, 45 * time.Minute, 6 * time.Hour} {
		t.Run(skew.String(), func(t *testing.T) {
			h := newHarness(t, t.TempDir(), Options{})
			h.hook(actorA, "s1", secretRead(t))
			h.advance(time.Second)
			at := h.clock().Add(skew) // the controller's clock, skew ahead of the leader's
			r := h.life(LifecycleEvent{Actor: actorB, Event: LifecycleForked, Parent: &actorA, AtUnixNano: at.UnixNano()})
			if r.CopiedEvents == 0 {
				t.Fatalf("fork copied nothing: %+v", r)
			}
			h.advance(time.Second)
			h.wantEgressRefused(actorB, "fork child, controller clock "+skew.String()+" ahead")
			st := h.svc.stateOf(h.svc.actors[actorB.key()])
			if lim := h.clock().UnixNano(); st.RunningHighUnixNano > lim {
				t.Fatalf("child running high-water mark %v is past the leader's clock %v",
					time.Unix(0, st.RunningHighUnixNano).UTC(), h.clock())
			}
		})
	}
}

// GAP-0319, late fork event: the child read a secret itself before the
// controller reported the fork. A fork event stamped by a controller clock
// 45 minutes ahead must not age the child's own read out of its 30-minute
// window, so the child's next egress is still refused.
func TestGAP0319LateForkEventKeepsTheChildsOwnSecretRead(t *testing.T) {
	h := newHarness(t, t.TempDir(), Options{Warn: &bytes.Buffer{}})
	h.hook(actorA, "s1", projection(t, reverseShell, 1))
	h.hook(actorB, "s1", secretRead(t))
	h.advance(time.Second)
	at := h.clock().Add(45 * time.Minute)
	h.life(LifecycleEvent{Actor: actorB, Event: LifecycleForked, Parent: &actorA, AtUnixNano: at.UnixNano()})
	h.advance(time.Second)
	h.wantEgressRefused(actorB, "the child's own secret read after a late fork event 45 min ahead")
}
