// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package chainstate

import (
	"fmt"
	"testing"
	"time"
)

// GAP-0292, SMK TST-0813 (smk-p14-marker-idle): the controller's own idle
// suspend, on that cell's timeline. Read at 21:01, no request for 15
// minutes, idle suspend at 21:16 (the controller sets the state itself: no
// suspended event), atelet's detach 30 minutes later (sent as a revert
// before F20), resume at 21:49, upload at 21:50. F18's task-end suspend
// tells the leader the same: nothing until the resume.
func TestGAP0292IdleSuspendOnTheSMKTimeline(t *testing.T) {
	t.Parallel()
	for _, detachAsRevert := range []bool{false, true} {
		t.Run(fmt.Sprintf("detach sent as a revert %v", detachAsRevert), func(t *testing.T) {
			t.Parallel()
			h := newHarness(t, t.TempDir(), Options{})
			h.hook(actorA, "s1", secretRead(t))
			h.advance(15*time.Minute + 38*time.Second)
			h.advance(30 * time.Minute)
			if detachAsRevert {
				h.life(LifecycleEvent{Actor: actorA, Event: LifecycleReverted})
			}
			h.advance(3 * time.Minute)
			h.life(LifecycleEvent{Actor: actorA, Event: LifecycleResumed})
			h.advance(21 * time.Second)
			h.wantEgressRefused(actorA, "idle suspend, 48 minutes of wall time")
		})
	}
}
