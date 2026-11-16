// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package sensor

import (
	"context"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/sensor/agentchain"
	"github.com/defenseclaw/defenseclaw/internal/sensor/plane"
)

// startedKernelService is a brokered service whose host plane runs on a
// fake source with no events of its own.
func startedKernelService(t *testing.T) (*Service, context.Context) {
	t.Helper()
	now := time.Unix(1_760_000_000, 0)
	service := newBrokeredService(t, &kernelAcquirer{source: newFake(fullCoverage())}, &now)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	service.startHostPlane(ctx)
	return service, ctx
}

func wouldBlockKeysWrite(pid int) plane.Event {
	return plane.Event{
		Kind: plane.KindFileWrite, PID: pid, ExecID: "keys", Path: "/home/dev/.ssh/authorized_keys", UID: uidp(1001),
		Source: plane.SourceTetragon, Policy: "defenseclaw-controls-1a2b3c4d", PolicyOwner: plane.PolicyOwnerDefenseClaw,
		Outcome: plane.OutcomeWouldBlock, Control: "kernel.ssh_authorized_keys_write",
		At: time.Unix(1_760_000_000, 0),
	}
}

// TestKernelEventsSurviveAPollTheEmitterNeverRead pins rel-1-0-6:GAP-0148:
// polls come from several clocks (the poll interval, the 10 s kernel-status
// tick, the supervisor, an operator scan) while the gateway emits on its own
// tick, so two polls can land between two emissions. The second poll must
// not drop the kernel events the first one drained: the kernel events
// counter would count fewer would-blocks than the helper.
func TestKernelEventsSurviveAPollTheEmitterNeverRead(t *testing.T) {
	t.Parallel()
	service, ctx := startedKernelService(t)
	service.hostPlane.recordKernelEvent(wouldBlockKeysWrite(4101), agentchain.Lineage{}, false)
	service.Poll(ctx)
	service.hostPlane.recordKernelEvent(wouldBlockKeysWrite(4102), agentchain.Lineage{}, false)
	service.Poll(ctx)
	events := service.Snapshot().KernelEvents
	if len(events) != 2 || events[0].PID != 4101 || events[1].PID != 4102 {
		t.Fatalf("kernel events after two unread polls = %+v, want both would-blocks, oldest first", events)
	}
}

// TestTakenKernelEventsAreReportedOnce pins the other half: once the emitter
// took a snapshot, the next poll starts a fresh batch, so no event is
// counted twice.
func TestTakenKernelEventsAreReportedOnce(t *testing.T) {
	t.Parallel()
	service, ctx := startedKernelService(t)
	service.hostPlane.recordKernelEvent(wouldBlockKeysWrite(4201), agentchain.Lineage{}, false)
	service.Poll(ctx)
	if taken := service.TakeSnapshot().KernelEvents; len(taken) != 1 || taken[0].PID != 4201 {
		t.Fatalf("taken = %+v, want the one would-block", taken)
	}
	service.Poll(ctx)
	if again := service.TakeSnapshot().KernelEvents; len(again) != 0 {
		t.Fatalf("a taken event was handed over again: %+v", again)
	}
	service.hostPlane.recordKernelEvent(wouldBlockKeysWrite(4202), agentchain.Lineage{}, false)
	service.Poll(ctx)
	if events := service.TakeSnapshot().KernelEvents; len(events) != 1 || events[0].PID != 4202 {
		t.Fatalf("after a take = %+v, want only the new would-block", events)
	}
}

// TestCarryForwardKeepsTheOldestWithinTheBound pins the bound: a carried
// batch never grows past the per-poll limit, and what does not fit is
// counted as dropped, never hidden.
func TestCarryForwardKeepsTheOldestWithinTheBound(t *testing.T) {
	t.Parallel()
	joined, dropped := carryForward([]int{1, 2, 3}, 1, []int{4, 5}, 2, 4)
	if len(joined) != 4 || joined[0] != 1 || joined[3] != 4 || dropped != 4 {
		t.Fatalf("joined %v dropped %d, want [1 2 3 4] and 1+2+1 dropped", joined, dropped)
	}
	joined, dropped = carryForward([]int{1, 2, 3, 4, 5}, 0, []int{6}, 0, 4)
	if len(joined) != 4 || joined[3] != 4 || dropped != 2 {
		t.Fatalf("joined %v dropped %d, want the 4 oldest and 2 dropped", joined, dropped)
	}
	if joined, dropped = carryForward(nil, 0, []int{7}, 3, 4); len(joined) != 1 || dropped != 3 {
		t.Fatalf("nothing to carry: joined %v dropped %d", joined, dropped)
	}
}

// cowork-1-0-8 GAP-0080: the kernel controls' hour counts follow a helper
// restart by the epoch of its counters. A restarted helper whose total
// already passed the old one counts from zero, not as the difference; a
// helper that predates the epoch is told by a total that went down.
func TestKernelHitHourCountsFollowAHelperRestartByItsEpoch(t *testing.T) {
	service := &Service{}
	at := time.Unix(1_790_000_000, 0)
	for _, step := range []struct {
		name           string
		blocked, since int64
		want           int64
	}{
		{"baseline", 5, 100, 0},
		{"growth", 7, 100, 2},
		{"a restarted helper whose total passed the old one", 9, 200, 11},
		{"a helper that predates the epoch, total down", 3, 0, 14},
		{"growth without an epoch", 4, 0, 15},
	} {
		at = at.Add(time.Minute)
		if _, blocked := service.noteKernelHits(at, map[string]int64{"blocked_total": step.blocked}, step.since); blocked != step.want {
			t.Fatalf("%s: blocked in the hour %d, want %d", step.name, blocked, step.want)
		}
	}
}
