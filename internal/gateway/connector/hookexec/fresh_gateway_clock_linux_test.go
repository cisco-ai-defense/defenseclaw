// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package hookexec

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/procidentity"
	"github.com/defenseclaw/defenseclaw/internal/proofclock/proofclocktest"
)

// freshGatewayClock installs the proof clock for a test that drives a real
// process through the fresh-gateway proof, standing one second after the
// start of that process. The 12 s window of the proof is then read on this
// clock: a slow host cannot age the gateway, and a test moves the clock to
// the limit to pin it. It returns the start of the process.
func freshGatewayClock(t *testing.T, pid int) (*proofclocktest.Clock, time.Time) {
	t.Helper()
	start, ok := procidentity.StartTime(pid)
	if !ok {
		t.Fatal("helper start time unavailable")
	}
	clock := proofclocktest.Install(t)
	clock.Set(start.Add(time.Second))
	return clock, start
}

// dateGatewayRecord sets the modification time of the gateway record, which
// the cheap first look of the native hook reads, so a test decides it and
// the host does not.
func dateGatewayRecord(t *testing.T, dataDir string, at time.Time) {
	t.Helper()
	if err := os.Chtimes(filepath.Join(dataDir, "gateway.pid"), at, at); err != nil {
		t.Fatal(err)
	}
}

// eventuallyWithin waits up to limit of real time for cond, which a real
// process makes true in its own time. The limit is the wall-clock guard each
// test had before the proof clock; the proof clock decides what the product
// does, and the guard still fails a read the host makes slower than that.
func eventuallyWithin(t *testing.T, what string, limit time.Duration, cond func() bool) {
	t.Helper()
	for end := time.Now().Add(limit); !cond(); time.Sleep(10 * time.Millisecond) {
		if time.Now().After(end) {
			t.Fatalf("%s did not happen within %v", what, limit)
		}
	}
}

// awaitOwnerRead waits for the background read of the connection owner to
// end. The read stops its timer on the proof clock when it ends, whatever it
// found, so that event, and not the speed of the host, says the read is
// done. Time stands still on the proof clock, so a slow read cannot spend the
// product wait. A read that never ends stays bounded by the test timeout.
func awaitOwnerRead(t *testing.T, clock *proofclocktest.Clock) {
	t.Helper()
	deadline, bounded := t.Deadline()
	for clock.Stopped() == 0 {
		if bounded && time.Now().After(deadline.Add(-5*time.Second)) {
			t.Fatal("the read of the connection owner did not end before the test timeout")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestFreshGatewayWindowsKeepTheirProductValues pins the limits the
// fresh-gateway proof reads on the proof clock.
func TestFreshGatewayWindowsKeepTheirProductValues(t *testing.T) {
	if perUserFreshGatewayWindow != 12*time.Second || freshOwnerCaptureWait != time.Second {
		t.Fatalf("window %v, owner read %v, want 12s and 1s", perUserFreshGatewayWindow, freshOwnerCaptureWait)
	}
}

// TestFreshOwnerReadPastItsWaitNamesNoOwner holds the process-table read of
// the connection owner and ends it at a moment the test chooses on the proof
// clock: a read that ends inside the product wait names the owner, and a read
// that ends once the clock has reached that wait names none, however
// the host paced it.
func TestFreshOwnerReadPastItsWaitNamesNoOwner(t *testing.T) {
	client := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40001}
	server := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40002}
	for _, tc := range []struct {
		name    string
		elapsed time.Duration // how far the clock stands when the read ends
		named   bool
	}{
		{"read ends inside the wait", freshOwnerCaptureWait - time.Nanosecond, true},
		{"read ends at the wait", freshOwnerCaptureWait, false},
		{"read ends past the wait", 5 * freshOwnerCaptureWait, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clock := proofclocktest.Install(t)
			started := clock.Now()
			release := make(chan struct{})
			scanning := make(chan struct{})
			scan := func(ctx context.Context, _, _ *net.TCPAddr) (int, bool) {
				close(scanning)
				<-release
				if !tc.named {
					// The timer ends the context on its own goroutine.
					<-ctx.Done()
				}
				return os.Getpid(), true
			}
			check := &perUserPeerCheck{}
			done := make(chan struct{})
			go func() {
				defer close(done)
				captureFreshGatewayOwner(check, client, server, scan)
			}()
			<-scanning
			if got := clock.Requested(); len(got) != 1 || got[0] != freshOwnerCaptureWait {
				t.Fatalf("owner read timers = %v, want one of %v", got, freshOwnerCaptureWait)
			}
			clock.Set(started.Add(tc.elapsed))
			close(release)
			<-done
			if got := check.owner.Load() != nil; got != tc.named {
				t.Fatalf("owner named = %v after a read that ended %v into the wait, want %v", got, tc.elapsed, tc.named)
			}
		})
	}
}

// TestFreshOwnerReadSlowOnTheHostIsStillNamedWhileTheProofClockStands holds
// the process-table read for longer than the product wait of real time, as a
// loaded host does, while the proof clock stands still: the read has not
// spent its wait, so it names the owner, and the test waits for the end of
// the read, not for a second of wall time.
func TestFreshOwnerReadSlowOnTheHostIsStillNamedWhileTheProofClockStands(t *testing.T) {
	clock := proofclocktest.Install(t)
	client := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40001}
	server := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40002}
	scan := func(context.Context, *net.TCPAddr, *net.TCPAddr) (int, bool) {
		time.Sleep(freshOwnerCaptureWait + 200*time.Millisecond)
		return os.Getpid(), true
	}
	check := &perUserPeerCheck{}
	go captureFreshGatewayOwner(check, client, server, scan)
	awaitOwnerRead(t, clock)
	if owner := check.owner.Load(); owner == nil || owner.pid != os.Getpid() {
		t.Fatalf("owner after a slow read on a standing clock = %+v, want this process", owner)
	}
}
