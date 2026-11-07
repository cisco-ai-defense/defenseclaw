// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Holders of one lane run together (so their writes share a commit), and the
// other lane never overlaps them (rel-1-0-6 GAP-0490).
func TestLaneGateSharesALaneAndExcludesTheOther(t *testing.T) {
	var gate laneGate
	var inLane [2]atomic.Int32
	var overlap, together atomic.Bool
	var wg sync.WaitGroup
	for i := 0; i < 200; i++ {
		lane := i % 2
		wg.Add(1)
		go func() {
			defer wg.Done()
			leave := gate.enter(lane)
			if inLane[1-lane].Load() != 0 {
				overlap.Store(true)
			}
			if inLane[lane].Add(1) > 1 {
				together.Store(true)
			}
			time.Sleep(time.Millisecond)
			inLane[lane].Add(-1)
			leave()
		}()
	}
	wg.Wait()
	if overlap.Load() {
		t.Fatal("the two lanes ran at the same time")
	}
	if !together.Load() {
		t.Fatal("holders of one lane never ran together")
	}
}

// A lane that waits is not starved by a steady stream of the lane that runs.
func TestLaneGateDoesNotStarveTheOtherLane(t *testing.T) {
	var gate laneGate
	stop := make(chan struct{})
	var stream sync.WaitGroup
	for i := 0; i < 4; i++ {
		stream.Add(1)
		go func() {
			defer stream.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				leave := gate.enter(journalLane)
				time.Sleep(time.Millisecond)
				leave()
			}
		}()
	}
	defer func() { close(stop); stream.Wait() }()
	time.Sleep(10 * time.Millisecond)
	entered := make(chan struct{})
	go func() {
		gate.enter(auditLane)()
		close(entered)
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the audit lane waited behind a steady stream of the journal lane")
	}
}
