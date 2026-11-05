// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package plane

import (
	"sync"
	"testing"
)

// TestBufferDropCounterIsSafeUnderConcurrentPush pins the counter against the
// Linux source's two readers.
//
// cn_proc and fanotify run as separate goroutines over one Buffer and both
// call Push. A plain int64 counter races there, and the lost increments
// understate the drop count -- which is exactly the number the service
// reports as reduced coverage, so undercounting reproduces the silent
// degradation this package exists to prevent. Run under -race.
func TestBufferDropCounterIsSafeUnderConcurrentPush(t *testing.T) {
	buffer := NewBuffer()

	// Fill it so every subsequent Push has to evict.
	for range eventBuffer {
		buffer.Push(Event{Kind: KindExec, PID: 1})
	}

	const writers, each = 4, 200
	var wait sync.WaitGroup
	for range writers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for range each {
				buffer.Push(Event{Kind: KindExec, PID: 2})
			}
		}()
	}
	wait.Wait()

	// Every push past a full buffer evicts one event and counts one drop, so
	// the total is exact rather than merely nonzero. A racing counter loses
	// increments and lands short.
	if got, want := buffer.Dropped(), int64(writers*each); got != want {
		t.Fatalf("Dropped() = %d, want %d: increments were lost to a race", got, want)
	}
}

// TestBufferProtectsLineageUnderBackPressure pins the retention bias that
// keeps attribution working on a busy host.
//
// A saturated buffer that drops uniformly loses exec events first, because
// file events outnumber them by orders of magnitude when an AI agent is
// reading its own configuration directory. Losing an exec does not cost one
// signal -- it orphans an entire subtree, so the lineage gate discards
// every tactic beneath it and the host reads as quiet.
func TestBufferProtectsLineageUnderBackPressure(t *testing.T) {
	t.Parallel()
	buffer := NewBuffer()

	// Fill it completely with file traffic, the way an agent's own config
	// reads do.
	for index := 0; index < eventBuffer; index++ {
		buffer.Push(Event{Kind: KindFileRead, Path: "/home/dev/.claude/settings.json"})
	}

	// More file traffic must not displace anything.
	buffer.Push(Event{Kind: KindFileRead, Path: "/home/dev/.claude/again.json"})

	// An exec must get in, because the tree depends on it.
	buffer.Push(Event{Kind: KindExec, PID: 4242, PPID: 1, Name: "claude"})

	events := buffer.Events()
	foundExec := false
	for drained := 0; drained < eventBuffer; drained++ {
		select {
		case event := <-events:
			if event.Kind == KindExec && event.Name == "claude" {
				foundExec = true
			}
		default:
			drained = eventBuffer
		}
	}
	if !foundExec {
		t.Fatal("an exec was dropped in favour of file reads: the process tree " +
			"loses the ancestor and every tactic below it becomes unattributable")
	}
	if buffer.Dropped() == 0 {
		t.Fatal("the buffer overflowed without counting a drop; reduced coverage " +
			"has to be reported, not absorbed")
	}
}

// cowork-1-0-8 GAP-0067 (S1 review 1 N1): an image digest that finds the
// buffer full displaces no exec or exit, and still reaches the consumer
// once there is room, ahead of the event that found the room.
func TestBufferKeepsTheTreeAndTheImageDigest(t *testing.T) {
	t.Parallel()
	buffer := NewBuffer()
	for index := 0; index < eventBuffer; index++ {
		kind := KindExec
		if index%2 == 1 {
			kind = KindExit
		}
		buffer.Push(Event{Kind: kind, PID: index})
	}
	buffer.Push(Event{Kind: KindImageDigest, PID: 4242, ImageDigestState: DigestRead})
	if dropped := buffer.Dropped(); dropped != 0 {
		t.Fatalf("dropped %d with the digest kept for later", dropped)
	}
	events := buffer.Events()
	for index := 0; index < eventBuffer; index++ {
		if event := <-events; event.PID != index || !event.Kind.lineage() {
			t.Fatalf("event %d = %+v, want the tree's event %d in order", index, event, index)
		}
	}
	buffer.Push(Event{Kind: KindFileRead, PID: 7})
	if event := <-events; event.Kind != KindImageDigest || event.PID != 4242 {
		t.Fatalf("after room = %+v, want the kept digest", event)
	}
	if event := <-events; event.Kind != KindFileRead {
		t.Fatalf("then %+v, want the file read", event)
	}
	for index := 0; index <= maxLateDigests; index++ {
		for len(events) < eventBuffer {
			buffer.Push(Event{Kind: KindExec, PID: index})
		}
		buffer.Push(Event{Kind: KindImageDigest, PID: index})
	}
	if dropped := buffer.Dropped(); dropped != 1 {
		t.Fatalf("dropped %d past maxLateDigests kept digests, want 1", dropped)
	}
}

// TestBufferStillReportsEveryDrop keeps the counter honest for both classes.
func TestBufferStillReportsEveryDrop(t *testing.T) {
	t.Parallel()
	buffer := NewBuffer()
	for index := 0; index < eventBuffer; index++ {
		buffer.Push(Event{Kind: KindFileRead})
	}
	before := buffer.Dropped()
	buffer.Push(Event{Kind: KindFileRead})
	if buffer.Dropped() != before+1 {
		t.Fatalf("a refused file event was not counted: %d -> %d", before, buffer.Dropped())
	}
	buffer.Push(Event{Kind: KindExec})
	if buffer.Dropped() != before+2 {
		t.Fatalf("an eviction made room without being counted: %d", buffer.Dropped())
	}
}
