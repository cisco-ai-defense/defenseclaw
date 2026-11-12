// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package testenv

import (
	"runtime"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// onOneCPU runs fn on a goroutine of its own, on a thread held for it and
// pinned to cpu. The goroutine ends still holding the thread, so the runtime
// discards the thread and the pinning reaches nothing else.
func onOneCPU(t *testing.T, cpu int, fn func()) {
	t.Helper()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		runtime.LockOSThread()
		var set unix.CPUSet
		set.Set(cpu)
		if err := unix.SchedSetaffinity(0, &set); err != nil {
			t.Errorf("pin to CPU %d: %v", cpu, err)
			return
		}
		fn()
	}()
	wg.Wait()
}

// The reading is of the thread that ran the call. With a CPU shared by
// spinning threads, a call that spins on its own thread on that CPU reads
// what it was denied, and a call that sleeps reads none of what the spinners
// lost, so the wait of the other threads cannot excuse it: a sleep over the
// bound stays over it.
func TestMeasureReadsTheThreadOfTheCallNotTheProcess(t *testing.T) {
	if _, ok := threadWaited(); !ok {
		t.Skip("the host keeps no per-thread scheduler statistics")
	}
	var allowed unix.CPUSet
	if err := unix.SchedGetaffinity(0, &allowed); err != nil || allowed.Count() == 0 {
		t.Skipf("no CPU set to pin to: %v", err)
	}
	cpu := 0
	for !allowed.IsSet(cpu) {
		cpu++
	}
	const spinners = 3
	var spinning sync.WaitGroup
	done := make(chan struct{})
	for range spinners {
		spinning.Add(1)
		go func() {
			defer spinning.Done()
			onOneCPU(t, cpu, func() {
				x := 1
				for {
					select {
					case <-done:
						_ = x
						return
					default:
						x = x*31 + 7
					}
				}
			})
		}()
	}
	defer func() {
		close(done)
		spinning.Wait()
	}()
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(spinners + 2))
	time.Sleep(100 * time.Millisecond) // the spinners hold the CPU

	const bound = 200 * time.Millisecond
	var slept Call
	var sleptFor time.Duration
	onOneCPU(t, cpu, func() {
		started := time.Now()
		slept = Measure(func() { time.Sleep(2 * bound) })
		sleptFor = time.Since(started)
	})
	if got := slept.Denied(); got > bound/2 {
		t.Errorf("a call that slept %v read %v denied: the wait of the other threads was taken for its own", sleptFor, got)
	}
	if slept.Within(sleptFor, bound) {
		t.Errorf("a call that slept %v passed a %v bound beside starved threads", sleptFor, bound)
	}

	// A window over the same crowd names it starved; one over a sleeping
	// process on a free host does not.
	window := StartWindow()
	time.Sleep(2 * bound)
	if !window.Starved() {
		t.Errorf("%d spinning threads on one CPU: a window of %v was not starved", spinners, 2*bound)
	}

	var busy Call
	onOneCPU(t, cpu, func() {
		started := time.Now()
		busy = Measure(func() {
			x := 1
			for time.Since(started) < 2*bound {
				x = x*31 + 7
			}
			_ = x
		})
	})
	if got := busy.Denied(); got < bound/2 {
		t.Errorf("%d spinning threads on one CPU: a call spinning on its own thread read %v denied of %v, want at least %v",
			spinners, got, 2*bound, bound/2)
	}
}
