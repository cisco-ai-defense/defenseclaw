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
	"fmt"
	"reflect"
	"strings"
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

// S1 review 2 F1: a kept digest never takes the room an exec or exit that
// frees it needs; it follows that event.
func TestKeptImageDigestNeverDisplacesTheTree(t *testing.T) {
	t.Parallel()
	buffer := NewBuffer()
	for index := 0; index < eventBuffer; index++ {
		kind := KindExec
		if index%2 == 1 {
			kind = KindExit
		}
		buffer.Push(Event{Kind: kind, PID: index})
	}
	buffer.Push(Event{Kind: KindImageDigest, PID: 4242})
	events := buffer.Events()
	if event := <-events; event.PID != 0 {
		t.Fatalf("first event %+v", event)
	}
	buffer.Push(Event{Kind: KindExec, PID: 9999})
	if dropped := buffer.Dropped(); dropped != 0 {
		t.Fatalf("dropped %d: the kept digest displaced a tree event", dropped)
	}
	for index := 1; index < eventBuffer; index++ {
		if event := <-events; event.PID != index || !event.Kind.lineage() {
			t.Fatalf("event %+v, want tree event %d in order", event, index)
		}
	}
	if event := <-events; event.PID != 9999 {
		t.Fatalf("last tree event %+v, want the exec that found room", event)
	}
	if kept := buffer.lateCount.Load(); kept != 1 {
		t.Fatalf("kept digests %d, want 1", kept)
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

// cowork-1-0-8 GAP-0072 (the class of GAP-0071): every host sensor source this
// OS builds (bufferedSources) names the events its own buffer dropped in its
// coverage, the same way, whatever dropped them: a file event at a full
// buffer, a process event displacing the oldest, an image digest past the
// late queue. A full buffer that dropped nothing is not a loss.
func TestEverySourceNamesItsBufferDropsInCoverage(t *testing.T) {
	sources := bufferedSources()
	if len(sources) == 0 {
		t.Fatal("no host sensor source listed for this OS")
	}
	for name, build := range sources {
		t.Run(name, func(t *testing.T) {
			source, buffer := build()
			before := source.Coverage()
			wantBufferDrops(t, before, 0)
			for index := 0; index < eventBuffer; index++ {
				buffer.Push(Event{Kind: KindFileRead, PID: index})
			}
			wantBufferDrops(t, source.Coverage(), 0)
			buffer.Push(Event{Kind: KindFileRead, PID: -1})
			wantBufferDrops(t, source.Coverage(), 1)
			buffer.Push(Event{Kind: KindExec, PID: -2})
			wantBufferDrops(t, source.Coverage(), 2)
			for index := 0; index <= maxLateDigests; index++ {
				buffer.Push(Event{Kind: KindImageDigest, PID: -3 - index})
			}
			after := source.Coverage()
			wantBufferDrops(t, after, 3)
			if again := source.Coverage(); !reflect.DeepEqual(again, after) {
				t.Fatalf("coverage changed between calls:\n%+v\n%+v", after, again)
			}
			if len(after.Limitations) != len(before.Limitations)+1 ||
				strings.Join(after.Limitations[:len(before.Limitations)], "\n") != strings.Join(before.Limitations, "\n") {
				t.Fatalf("limitations before the drops %q, after %q: want the same plus one drop line",
					before.Limitations, after.Limitations)
			}
		})
	}
}

// wantBufferDrops checks that coverage names exactly dropped buffer drops,
// in one line, or none when dropped is 0.
func wantBufferDrops(t *testing.T, coverage Coverage, dropped int64) {
	t.Helper()
	lines := 0
	for _, limitation := range coverage.Limitations {
		if strings.Contains(limitation, "dropped from the sensor's event buffer") {
			lines++
		}
	}
	joined := strings.Join(coverage.Limitations, "; ")
	switch {
	case dropped == 0 && lines != 0:
		t.Fatalf("limitations = %q, want no buffer drop line", joined)
	case dropped > 0 && (lines != 1 || !strings.Contains(joined, fmt.Sprintf(
		"%d events were dropped from the sensor's event buffer under back-pressure", dropped))):
		t.Fatalf("limitations = %q, want one line naming %d dropped events", joined, dropped)
	}
}
