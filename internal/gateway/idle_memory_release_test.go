// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"runtime/debug"
	"runtime/metrics"
	"testing"
)

// GAP-2013: an idle gateway gives back the heap its last calls freed, once,
// and never while calls keep coming.
func TestIdleMemoryReleaserReleasesOnceAfterWork(t *testing.T) {
	var allocated uint64 = 100 << 20
	releases := 0
	r := newIdleMemoryReleaser(func() uint64 { return allocated }, func() { releases++ })

	// Busy ticks: calls allocate 20 MiB per tick, nothing is released.
	for range 3 {
		allocated += 20 << 20
		if r.tick() {
			t.Fatal("released while calls were still allocating")
		}
	}
	// The first quiet tick after the work releases.
	allocated += 1 << 20
	if !r.tick() || releases != 1 {
		t.Fatalf("quiet tick after work: releases=%d, want 1", releases)
	}
	// Staying idle does not release again.
	for range 5 {
		allocated += 1 << 20
		if r.tick() {
			t.Fatal("released again while idle with no new work")
		}
	}
	if releases != 1 {
		t.Fatalf("releases=%d after idle ticks, want 1", releases)
	}
	// New work, then quiet: one more release.
	allocated += 30 << 20
	r.tick()
	allocated += 1 << 20
	if !r.tick() || releases != 2 {
		t.Fatalf("quiet tick after new work: releases=%d, want 2", releases)
	}
}

func TestIdleMemoryReleaserSkipsSmallWork(t *testing.T) {
	var allocated uint64
	releases := 0
	r := newIdleMemoryReleaser(func() uint64 { return allocated }, func() { releases++ })
	for range 20 {
		allocated += 512 << 10
		r.tick()
	}
	if releases != 0 {
		t.Fatalf("released %d times for background-only allocation, want 0", releases)
	}
}

var idleMemoryReleaseSink [][]byte

// The real release: heap freed by work goes back to the OS, and the
// allocation counter the releaser reads moves with real allocation.
func TestIdleMemoryReleaserRealRuntimeReturnsFreedHeap(t *testing.T) {
	released := func() uint64 {
		s := []metrics.Sample{{Name: "/memory/classes/heap/released:bytes"}}
		metrics.Read(s)
		return s[0].Value.Uint64()
	}
	start := heapAllocatedBytes()
	for range 64 {
		idleMemoryReleaseSink = append(idleMemoryReleaseSink, make([]byte, 1<<20))
	}
	if grown := heapAllocatedBytes() - start; grown < 64<<20 {
		t.Fatalf("heap allocation counter grew %d bytes for 64 MiB of work", grown)
	}
	idleMemoryReleaseSink = nil
	var allocated uint64
	r := newIdleMemoryReleaser(func() uint64 { return allocated }, debug.FreeOSMemory)
	allocated += 64 << 20
	r.tick()
	before := released()
	if !r.tick() {
		t.Fatal("quiet tick after 64 MiB of work did not release")
	}
	if after := released(); after < before+(16<<20) {
		t.Fatalf("heap released grew %d bytes, want at least 16 MiB", int64(after)-int64(before))
	}
}
