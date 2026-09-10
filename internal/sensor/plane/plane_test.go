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
