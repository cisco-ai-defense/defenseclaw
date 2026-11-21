// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
)

// The known-folder read of stillPlain lets the hook call's thread go for its
// wait on Windows, and the goroutine takes a thread back after it
// (rel-1-0-10:GAP-1316). The call is the same call after every read: the
// goroutine finds it with its memory, no other goroutine finds it, also while
// the thread is free, and the end closes it.
func TestGAP1316HookCallIsTheSameCallOverTheReadsThatLetItsThreadGo(t *testing.T) {
	resetPlainFolders(t)
	dir := t.TempDir()
	known, err := walkLstat(dir)
	if err != nil {
		t.Fatal(err)
	}
	end := HookCall()
	call := currentHookCall()
	if call == nil {
		t.Fatal("HookCall began no call the goroutine finds")
	}
	call.stats = map[string]statAnswer{"marker": {}}
	stop := make(chan struct{})
	var others sync.WaitGroup
	var found atomic.Int64
	for range 4 {
		others.Add(1)
		go func() {
			defer others.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				if currentHookCall() != nil {
					found.Add(1)
				}
				runtime.Gosched()
			}
		}()
	}
	for i := range 2000 {
		if same, answered := stillPlain(dir, known); !same || !answered {
			t.Fatalf("read %d of a plain folder: same %v, answered %v", i, same, answered)
		}
		if got := currentHookCall(); got != call {
			t.Fatalf("after read %d the goroutine finds call %p, want %p", i, got, call)
		}
	}
	close(stop)
	others.Wait()
	if n := found.Load(); n != 0 {
		t.Fatalf("other goroutines found the call %d times", n)
	}
	if _, kept := call.stats["marker"]; !kept {
		t.Fatal("the call lost its memory over the reads")
	}
	released := releaseHookCallThread()
	if runtime.GOOS == "windows" {
		if released != call {
			t.Fatalf("released %p, want the call %p", released, call)
		}
		if currentHookCall() != nil {
			t.Fatal("the call is found while its thread is free")
		}
	} else if released != nil || currentHookCall() != call {
		t.Fatal("off Windows the call lets no thread go")
	}
	runtime.Gosched()
	retakeHookCallThread(released)
	if currentHookCall() != call {
		t.Fatal("the call is not found after its thread is taken back")
	}
	end()
	if currentHookCall() != nil {
		t.Fatal("the call is open after its end")
	}
	hookCalls.mu.Lock()
	defer hookCalls.mu.Unlock()
	for key, open := range hookCalls.calls {
		if open == call {
			t.Fatalf("the end left the call open under key %d", key)
		}
	}
}

// A goroutine that holds its thread for itself (a LockOSThread of its own)
// keeps that thread over a read that lets the call's thread go, and the call
// keeps its key (rel-1-0-10:GAP-1316).
func TestGAP1316HookCallOnAThreadItsGoroutineHoldsKeepsTheThread(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	key := hookCallKey()
	end := HookCall()
	defer end()
	call := currentHookCall()
	if call == nil {
		t.Fatal("HookCall began no call the goroutine finds")
	}
	for range 50 {
		released := releaseHookCallThread()
		runtime.Gosched()
		retakeHookCallThread(released)
		if got := hookCallKey(); got != key {
			t.Fatalf("the goroutine runs on thread key %d, want its own %d", got, key)
		}
		if call.key != key || currentHookCall() != call {
			t.Fatal("the call moved off the thread its goroutine holds")
		}
	}
}
