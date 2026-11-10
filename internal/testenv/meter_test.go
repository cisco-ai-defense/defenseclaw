// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package testenv

import (
	"runtime"
	"sync"
	"testing"
	"time"
)

// Only a busy thread names the host: a sleeper reads nothing however long
// the host kept others waiting, and a reading is the longest wait of a busy
// thread, never more than the interval.
func TestDeniedBetweenNamesOnlyTheWaitOfBusyThreads(t *testing.T) {
	const wall = time.Second
	ms := func(n int) time.Duration { return time.Duration(n) * time.Millisecond }
	for _, tc := range []struct {
		name          string
		before, after map[int]threadTimes
		want          time.Duration
	}{
		{"idle process", map[int]threadTimes{1: {}}, map[int]threadTimes{1: {run: ms(1)}}, 0},
		{"a sleeper beside a starved host", map[int]threadTimes{1: {}}, map[int]threadTimes{1: {run: ms(2), wait: ms(30)}}, 0},
		{"one thread without the CPU for 600 ms", map[int]threadTimes{1: {}}, map[int]threadTimes{1: {run: ms(300), wait: ms(600)}}, ms(600)},
		{"longest of two busy threads, an idle one ignored",
			map[int]threadTimes{1: {}, 2: {}, 3: {}},
			map[int]threadTimes{1: {run: ms(400), wait: ms(500)}, 2: {run: ms(100), wait: ms(300)}, 3: {run: ms(5)}}, ms(500)},
		{"a thread that began or ended inside the interval is not read", map[int]threadTimes{1: {}}, map[int]threadTimes{2: {run: ms(300), wait: ms(600)}}, 0},
		{"a wait over the interval is the interval", map[int]threadTimes{1: {}}, map[int]threadTimes{1: {run: ms(10), wait: 2 * wall}}, wall},
		{"a counter that went back names nothing", map[int]threadTimes{1: {run: ms(900)}}, map[int]threadTimes{1: {run: ms(100), wait: ms(500)}}, 0},
	} {
		if got := deniedBetween(tc.before, tc.after, wall); got != tc.want {
			t.Errorf("%s: deniedBetween = %v, want %v", tc.name, got, tc.want)
		}
	}
	if got := deniedBetween(map[int]threadTimes{1: {}}, map[int]threadTimes{1: {run: time.Second}}, 0); got != 0 {
		t.Errorf("no interval: %v, want 0", got)
	}
}

// A call that stays inside its bound costs no reading, one over MaxStretch
// bounds never passes, and a Meter that has no reading leaves the bound as
// the product value.
func TestMeterWithinKeepsTheBoundWhereTheHostIsNotShort(t *testing.T) {
	var none *Meter
	if !none.Within(time.Second, 2*time.Second) {
		t.Error("a took inside its bound did not pass")
	}
	if none.Within(1100*time.Millisecond, time.Second) {
		t.Error("a took over its bound passed with no reading")
	}
	started := &Meter{started: time.Now().Add(-time.Minute), before: map[int]threadTimes{}}
	if started.Within(time.Duration(float64(time.Second)*(MaxStretch+0.5)), time.Second) {
		t.Errorf("a took of %.1fx its bound passed", MaxStretch+0.5)
	}
}

// On Linux with scheduler statistics the real reading follows the host: a
// process whose threads are shared out names what it lost, and one that only
// sleeps names none of it.
func TestMeterReadsTheCPUTheHostKeptFromTheProcess(t *testing.T) {
	if readThreadTimes() == nil {
		t.Skip("the host keeps no per-thread scheduler statistics")
	}
	sleeper := StartMeter()
	time.Sleep(300 * time.Millisecond)
	if got := sleeper.Denied(); got > 100*time.Millisecond {
		t.Errorf("a sleeping process was denied %v of 300 ms", got)
	}

	// Three times as many pinned-down spinning threads as CPUs: each gets
	// about a third of one, so each waits for most of the interval.
	spinners := 3 * runtime.NumCPU()
	var stop sync.WaitGroup
	done := make(chan struct{})
	for range spinners {
		stop.Add(1)
		go func() {
			defer stop.Done()
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
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
		}()
	}
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(spinners))
	loaded := StartMeter()
	time.Sleep(400 * time.Millisecond)
	got := loaded.Denied()
	close(done)
	stop.Wait()
	if got < 100*time.Millisecond {
		t.Errorf("%d spinning threads on %d CPUs: denied %v of 400 ms, want at least 100 ms", spinners, runtime.NumCPU(), got)
	}
}
