// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package hookexec

import (
	"net"
	"os"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/proofclock/proofclocktest"
)

// The read of the connected peer runs when a call connects and is capped on
// the system clock. It is not a post-deadline proof budget, so a proof that
// reads it asks the proof clock for no timer: a timer longer than the
// longest proof budget there would make requireRestartProofBudgets fail on
// macOS, and a proof clock that stands still must still let the read end.
func TestConnectedPeerReadStartsNoTimerOnTheProofClock(t *testing.T) {
	clock := proofclocktest.Install(t)
	client, _, _ := acceptedDarwinLoopbackPair(t, "tcp4", net.IPv4(127, 0, 0, 1))
	pid, ok := perUserConnectedPeerPID(client.LocalAddr().(*net.TCPAddr), client.RemoteAddr().(*net.TCPAddr))
	if !ok || pid != os.Getpid() {
		t.Fatalf("connected peer = %d, %v; want this process", pid, ok)
	}
	if got := clock.Requested(); len(got) != 0 {
		t.Fatalf("the peer read started timers %v on the proof clock", got)
	}
}
