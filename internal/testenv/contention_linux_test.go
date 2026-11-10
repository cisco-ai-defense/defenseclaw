// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package testenv

import (
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// A process whose threads are ready and have no CPU to run on has its wait
// counted: twice as many busy threads as CPUs make the host keep each of them
// waiting, and the measure names that wait and a factor above 1.
func TestContentionNamesTheWaitOfAnOversubscribedHost(t *testing.T) {
	spinners := 2 * runtime.NumCPU()
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(spinners))
	contention := StartContention()
	var stop atomic.Bool
	var wg sync.WaitGroup
	for range spinners {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !stop.Load() {
			}
		}()
	}
	time.Sleep(500 * time.Millisecond)
	stop.Store(true)
	wg.Wait()
	if wait := contention.Wait(); wait <= 0 {
		t.Fatalf("%d busy threads on %d CPUs: wait %v, want a wait", spinners, runtime.NumCPU(), wait)
	}
	if factor := contention.Factor(); factor <= 1 {
		t.Fatalf("%d busy threads on %d CPUs: factor %v, want above 1", spinners, runtime.NumCPU(), factor)
	}
}
