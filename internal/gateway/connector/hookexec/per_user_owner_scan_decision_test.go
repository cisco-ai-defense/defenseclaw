// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"context"
	"errors"
	"testing"
	"time"
)

// The decision itself: an abandoned scan that has shown the recorded gateway
// holding the listener is the outage of an unanswered listener; one that has
// not is an unproven peer.
func TestAbandonedOwnerScanAnswerFollowsTheRecordedHolder(t *testing.T) {
	for _, tc := range []struct {
		name   string
		holder bool
		want   error
	}{
		{"recorded gateway holds the listener", true, errPerUserOwnerScanUnfinished},
		{"holder not shown", false, errPerUserOwnerUnproven},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tryCtx, release := connectBy(context.Background(), time.Now().Add(50*time.Millisecond), nil)
			defer release()
			check, _ := tryCtx.Value(perUserPeerCheckKey{}).(*perUserPeerCheck)
			if check == nil {
				t.Fatal("connectBy set no peer check")
			}
			check.pending.Store(true)
			check.deciding.Store(true)
			check.recordedHolder.Store(tc.holder)
			select {
			case <-tryCtx.Done():
			case <-time.After(ownerScanGrace + 3*time.Second):
				t.Fatal("the try was never ended")
			}
			if cause := context.Cause(tryCtx); !errors.Is(cause, tc.want) {
				t.Fatalf("cause = %v, want %v", cause, tc.want)
			}
			if tc.holder != PerUserPostListenerUnanswered(context.Cause(tryCtx)) {
				t.Fatalf("outage = %v, want %v", !tc.holder, tc.holder)
			}
		})
	}
}
