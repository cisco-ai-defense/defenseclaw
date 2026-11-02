// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// TestPerUserPeerRecordReadsThePeerOnlyOnDemand pins rel-1-0-6 GAP-0381: the
// read of the process behind a per-user call's connection (a walk of every
// process of the account on Linux, lsof on macOS) runs only when a restart
// proof can need it. A call answered without a start reads nothing; a start
// seen during the call (Read) or the proof's own wait reads it once.
func TestPerUserPeerRecordReadsThePeerOnlyOnDemand(t *testing.T) {
	var reads atomic.Int32
	previous := perUserConnectedPeerRead
	perUserConnectedPeerRead = func(_, remote net.Addr) (perUserPeerProcess, bool) {
		reads.Add(1)
		server, _ := remote.(*net.TCPAddr)
		return perUserPeerProcess{pid: 4242, identity: "4242 start", server: server}, true
	}
	t.Cleanup(func() { perUserConnectedPeerRead = previous })
	local := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 50001}
	remote := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 18970}

	answered := NewPerUserPeerRecord()
	answered.Read() // before the call connected: nothing to read
	answered.capture(local, remote)
	select {
	case <-answered.Connected():
	default:
		t.Fatal("capture did not mark the call connected")
	}
	time.Sleep(50 * time.Millisecond)
	if n := reads.Load(); n != 0 {
		t.Fatalf("an answered call read its peer %d times, want 0", n)
	}

	started := NewPerUserPeerRecord()
	started.capture(local, remote)
	started.Read()
	started.Read()
	if got, ok := started.wait(time.Second); !ok || got.pid != 4242 || got.server.Port != remote.Port {
		t.Fatalf("peer after a seen start = %+v %v, want pid 4242 on the gateway port", got, ok)
	}
	if n := reads.Load(); n != 1 {
		t.Fatalf("a seen start read the peer %d times, want 1", n)
	}

	atDeadline := NewPerUserPeerRecord()
	atDeadline.capture(local, remote)
	if got, ok := atDeadline.wait(time.Second); !ok || got.pid != 4242 {
		t.Fatalf("peer read by the proof = %+v %v, want pid 4242", got, ok)
	}
	if n := reads.Load(); n != 2 {
		t.Fatalf("reads after the proof's own read = %d, want 2", n)
	}

	never := NewPerUserPeerRecord()
	if _, ok := never.wait(20 * time.Millisecond); ok {
		t.Fatal("a call that never connected has a peer")
	}
	if n := reads.Load(); n != 2 {
		t.Fatalf("a call that never connected read a peer (%d reads)", n)
	}
}
