// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// GAP-2002: under hook load a home walk can outlast the profile's scan
// share. The scan then uses the last complete walk of that home while it is
// fresh, the walk itself runs on and refreshes it, and without a fresh
// complete walk the account stays incomplete.
func TestWindowsPrivateHomeWalkReusesAFreshCompleteWalkPastTheScanDeadline(t *testing.T) {
	for len(windowsPrivateWalkLate) > 0 {
		<-windowsPrivateWalkLate
	}
	home := filepath.Join(t.TempDir(), "dcw-std1")
	run, bound, reuse, now := windowsPrivateWalkRun, windowsPrivateWalkBackgroundBound, windowsPrivateWalkReuse, windowsPrivateWalkNow
	release := make(chan struct{})
	t.Cleanup(func() {
		windowsPrivateWalkRun, windowsPrivateWalkBackgroundBound, windowsPrivateWalkReuse, windowsPrivateWalkNow = run, bound, reuse, now
	})
	clock := time.Now()
	windowsPrivateWalkNow = func() time.Time { return clock }
	windowsPrivateWalkReuse = 10 * time.Minute
	calls := 0
	prefix := filepath.Join(home, "work", "tool")
	windowsPrivateWalkRun = func(ctx context.Context, walked string) ([]string, bool) {
		calls++
		if calls == 1 {
			return []string{prefix}, true
		}
		select { // a walk slowed down by load
		case <-release:
			return []string{prefix}, true
		case <-ctx.Done():
			return nil, false
		}
	}
	scan := func(d time.Duration) ([]string, bool) {
		ctx, cancel := context.WithTimeout(context.Background(), d)
		defer cancel()
		return windowsPrivateHomeWalk(ctx, home)
	}

	if got, complete := scan(5 * time.Second); !complete || len(got) != 1 || got[0] != prefix {
		t.Fatalf("first walk = %q complete=%t, want the walked prefix", got, complete)
	}
	started := time.Now()
	got, complete := scan(2500 * time.Millisecond)
	if !complete || len(got) != 1 || got[0] != prefix {
		t.Fatalf("walk past the deadline = %q complete=%t, want the fresh complete walk", got, complete)
	}
	if waited := time.Since(started); waited > 2*time.Second {
		t.Fatalf("scan waited %s for its walk, want it to keep part of its share", waited)
	}

	clock = clock.Add(11 * time.Minute) // the last complete walk is now too old
	if got, complete := scan(2500 * time.Millisecond); complete || len(got) != 0 {
		t.Fatalf("stale walk = %q complete=%t, want incomplete", got, complete)
	}
	if calls != 2 {
		t.Fatalf("walks started = %d, want one walk running on, not one per scan", calls)
	}

	// The reused walk was not late: no extra cycle yet.
	select {
	case <-WindowsPrivateWalkCompletedLate():
		t.Fatal("a walk signalled an extra cycle before any scan reported its account incomplete")
	default:
	}
	close(release) // the slow walk finishes and refreshes the record
	// The scan above reported the account incomplete for want of it.
	select {
	case <-WindowsPrivateWalkCompletedLate():
	case <-time.After(5 * time.Second):
		t.Fatal("the late walk did not ask for an extra cycle")
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		windowsPrivateWalks.Lock()
		state := windowsPrivateWalks.homes[strings.ToLower(filepath.Clean(home))]
		done := state != nil && state.running == nil && state.lastAt.Equal(clock)
		windowsPrivateWalks.Unlock()
		if done {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the walk that ran on did not refresh the home's last complete walk")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got, complete := scan(2500 * time.Millisecond); !complete || len(got) != 1 {
		t.Fatalf("after the slow walk finished = %q complete=%t, want complete", got, complete)
	}
	// The extra cycle used the fresh walk, so it asks for no other.
	select {
	case <-WindowsPrivateWalkCompletedLate():
		t.Fatal("the extra cycle's own scan asked for another cycle")
	case <-time.After(200 * time.Millisecond):
	}
}

// A walk that ends incomplete for a reason other than time (its entry bound,
// an unlistable folder) is reported as it ended, not covered by an older
// complete walk.
func TestWindowsPrivateHomeWalkReportsAFinishedIncompleteWalk(t *testing.T) {
	home := filepath.Join(t.TempDir(), "dcw-std2")
	run := windowsPrivateWalkRun
	t.Cleanup(func() { windowsPrivateWalkRun = run })
	complete := true
	windowsPrivateWalkRun = func(context.Context, string) ([]string, bool) { return []string{home}, complete }
	if _, ok := windowsPrivateHomeWalk(context.Background(), home); !ok {
		t.Fatal("complete walk reported incomplete")
	}
	complete = false
	if got, ok := windowsPrivateHomeWalk(context.Background(), home); ok {
		t.Fatalf("an over-bound walk was replaced by the older complete one: %q", got)
	}
	expired, cancel := context.WithCancel(context.Background())
	cancel()
	if _, ok := windowsPrivateHomeWalk(expired, home); ok {
		t.Fatal("an expired scan reported a walk")
	}
}

// enumerate --once exits after its cycle, so it waits for a walk its scan
// gave up on and runs one more cycle with it (rel-1-0-6 r106 CI); with no
// such walk it does not wait.
func TestWaitWindowsPrivateWalksReportedWaitsForAWalkAScanGaveUpOn(t *testing.T) {
	for len(windowsPrivateWalkLate) > 0 {
		<-windowsPrivateWalkLate
	}
	home := filepath.Join(t.TempDir(), "dcw-std2")
	run := windowsPrivateWalkRun
	t.Cleanup(func() { windowsPrivateWalkRun = run })
	prefix := filepath.Join(home, "work", "tool")
	release := make(chan struct{})
	windowsPrivateWalkRun = func(ctx context.Context, _ string) ([]string, bool) {
		select { // a cold first walk under install load
		case <-release:
			return []string{prefix}, true
		case <-ctx.Done():
			return nil, false
		}
	}

	quick, cancelQuick := context.WithTimeout(context.Background(), 5*time.Second)
	started := time.Now()
	if WaitWindowsPrivateWalksReported(quick) {
		t.Fatal("no walk was reported incomplete, want no extra cycle")
	}
	cancelQuick()
	if waited := time.Since(started); waited > time.Second {
		t.Fatalf("waited %s with no reported walk, want no wait", waited)
	}

	scan, cancelScan := context.WithTimeout(context.Background(), 2500*time.Millisecond)
	_, complete := windowsPrivateHomeWalk(scan, home)
	cancelScan()
	if complete {
		t.Fatal("the scan did not wait out its walk, want the account incomplete")
	}
	time.AfterFunc(200*time.Millisecond, func() { close(release) })
	wait, cancelWait := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelWait()
	if !WaitWindowsPrivateWalksReported(wait) {
		t.Fatal("the walk finished complete, want one more cycle")
	}
	again, cancelAgain := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelAgain()
	if got, complete := windowsPrivateHomeWalk(again, home); !complete || len(got) != 1 || got[0] != prefix {
		t.Fatalf("the extra cycle's walk = %q complete=%t, want the walked prefix", got, complete)
	}
}
