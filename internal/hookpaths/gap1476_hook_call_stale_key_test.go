// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// A goroutine that began no hook call never finds one, and never takes one
// away, while calls on other goroutines begin, end, and let their thread go
// and take one back as stillPlain does (rel-1-0-10:GAP-1476). On Windows the
// key is the OS thread: a lookup that read the key unpinned and then moved
// off that thread found the call that locked it next. Off Windows the key
// names the goroutine itself, which no other live goroutine has
// (goroutineKey), and the test holds by construction.
// The goroutine of each call finds its own call after every retake.
func TestGAP1476GoroutineWithoutAHookCallFindsNoneByAStaleThreadKey(t *testing.T) {
	run := 200 * time.Millisecond
	if runtime.GOOS == "windows" {
		run = 3 * time.Second
	}
	stop := make(chan struct{})
	var wrongFound, wrongTaken, ownLost, lookups, rekeys atomic.Int64
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				end := HookCall()
				own := currentHookCall()
				for range 50 {
					released := releaseHookCallThread()
					runtime.Gosched()
					retakeHookCallThread(released)
					rekeys.Add(1)
					if currentHookCall() != own {
						ownLost.Add(1)
					}
				}
				end()
			}
		}()
	}
	for i := range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				if i%2 == 0 {
					if currentHookCall() != nil {
						wrongFound.Add(1)
					}
				} else if taken := releaseHookCallThread(); taken != nil {
					// Put the call back where it can be ended; the test fails.
					wrongTaken.Add(1)
					retakeHookCallThread(taken)
					runtime.UnlockOSThread()
				}
				lookups.Add(1)
			}
		}()
	}
	time.Sleep(run)
	close(stop)
	wg.Wait()
	t.Logf("ROW|GAP-1476|found=%d|taken=%d|own-lost=%d|lookups=%d|rekeys=%d|procs=%d",
		wrongFound.Load(), wrongTaken.Load(), ownLost.Load(), lookups.Load(), rekeys.Load(), runtime.GOMAXPROCS(0))
	if wrongFound.Load() != 0 || wrongTaken.Load() != 0 {
		t.Fatalf("goroutines that began no call found a call %d times and took one away %d times", wrongFound.Load(), wrongTaken.Load())
	}
	if ownLost.Load() != 0 {
		t.Fatalf("a call's goroutine lost its own call %d times", ownLost.Load())
	}
	if lookups.Load() == 0 || rekeys.Load() == 0 {
		t.Fatal("the test ran no lookups or no retakes")
	}
}
