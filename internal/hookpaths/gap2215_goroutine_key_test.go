// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookpaths

import (
	"runtime"
	"sync"
	"testing"
)

// The goroutine key names one goroutine for its whole life: the same key in
// every frame, over stack growth, a yield and a move to another thread, and a
// key no other live goroutine has. The hook call the goroutine began is
// found deep in its stack after the stack grew (rel-1-0-10:GAP-2215: the key
// is a register read of the goroutine's g, not a traceback of its stack).
func TestGAP2215GoroutineKeyNamesOneLiveGoroutine(t *testing.T) {
	key := goroutineKey()
	if key == 0 {
		t.Fatal("goroutineKey read no key")
	}
	end := HookCall()
	defer end()
	call := currentHookCall()
	if call == nil {
		t.Fatal("HookCall began no call the goroutine finds")
	}
	var deep func(n int) (uint64, *hookCall)
	deep = func(n int) (uint64, *hookCall) {
		// 2,000 frames grow the stack past its first size: the runtime
		// copies it, and the goroutine keeps its g.
		if n == 0 {
			runtime.Gosched()
			return goroutineKey(), currentHookCall()
		}
		return deep(n - 1)
	}
	for _, depth := range []int{1, 100, 2000} {
		if got, found := deep(depth); got != key || found != call {
			t.Fatalf("at depth %d the key is %#x (want %#x) and the call found is %p (want %p)", depth, got, key, found, call)
		}
	}
	runtime.LockOSThread()
	if goroutineKey() != key {
		t.Fatal("the key changed when the goroutine was locked to its thread")
	}
	runtime.UnlockOSThread()

	const live = 64
	keys := make(chan uint64, live)
	release := make(chan struct{})
	var wg sync.WaitGroup
	for range live {
		wg.Add(1)
		go func() {
			defer wg.Done()
			own := goroutineKey()
			keys <- own
			<-release // all live at once
			if goroutineKey() != own || currentHookCall() != nil {
				t.Error("a goroutine read another key, or found a call it did not begin")
			}
		}()
	}
	seen := map[uint64]bool{key: true}
	for range live {
		k := <-keys
		if seen[k] {
			t.Fatalf("two live goroutines have the key %#x", k)
		}
		seen[k] = true
	}
	close(release)
	wg.Wait()
}
