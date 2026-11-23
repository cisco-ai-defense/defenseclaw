// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package hookexec

import (
	"context"
	"os"
	"testing"
	"time"
)

// GAP-1534: an owner scan that outlasts ownerScanGrace before it has tied the
// listener to the recorded gateway proves nothing about who listens. A decoy
// of this account on the gateway port, whose owner read is slow (a busy host,
// a scan that never got to run), stays refused as an unverified peer in every
// fail mode: it used to get the outage of an unanswered listener, which the
// default tiers allow. A slow record lookup of the own frozen gateway is the
// same unproven state and is refused the same way.
func TestOwnerScanOutlastingTheGraceBeforeTheRecordedHolderIsShownIsRefused(t *testing.T) {
	addr := frozenListener(t)
	for _, tc := range []struct {
		name string
		pid  func(t *testing.T) int
	}{
		{"unrecorded listener of this account", otherProcess},
		{"own frozen gateway, record lookup outlasts the grace", func(*testing.T) int { return os.Getpid() }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dataDir := recordGateway(t, tc.pid(t), nil)
			homes := func() []string {
				time.Sleep(ownerScanGrace + 600*time.Millisecond)
				return []string{dataDir}
			}
			tryCtx, release := connectBy(withPerUserGatewayHomes(context.Background(), homes), time.Now().Add(perUserConnectedWait), nil)
			defer release()
			_, err := PostPerUserHook(tryCtx, addr, "/api/v1/claude-code/hook", nil, []byte("{}"))
			if err == nil {
				t.Fatal("a frozen listener answered")
			}
			if PerUserPostListenerUnanswered(err) || !PerUserPostPeerUnverified(err) {
				t.Fatalf("a listener the scan never tied to the recorded gateway got the outage: %v", err)
			}
		})
	}
}
