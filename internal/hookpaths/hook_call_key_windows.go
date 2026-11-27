// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hookpaths

import (
	"runtime"

	"golang.org/x/sys/windows"
)

// lockHookCallKey keeps the calling goroutine on its OS thread until unlock,
// so that hookCallKey names it. A locked thread runs no other goroutine
// (runtime.LockOSThread): the thread's id names the goroutine that began the
// call for as long as the call is open, as its goroutine number did.
func lockHookCallKey() (unlock func()) {
	runtime.LockOSThread()
	return runtime.UnlockOSThread
}

// hookCallKey is the key of the calling goroutine's hook call: the id of its
// OS thread, one GetCurrentThreadId. Finding the call by goroutineID was a
// traceback of the goroutine's stack for every memo read, 22% of a padded
// Windows hook decision and more than the reads it saved
// (rel-1-0-10:GAP-1293). A goroutine that began no call runs on a thread no
// open call is locked to, so it finds none.
func hookCallKey() uint64 { return uint64(windows.GetCurrentThreadId()) }

// foundCallServes is false on Windows: the key is the OS thread, which a
// goroutine may let go between two reads (releaseHookCallThread), and
// reading it is one GetCurrentThreadId, so every read finds the call again
// as it did (JoinHookCall).
const foundCallServes = false

// releaseHookCallThread lets the thread of the calling goroutine's hook call
// go for a wait in which the goroutine reads none of the call's memory, and
// returns the call to give to retakeHookCallThread after the wait (nil: the
// goroutine runs no call, and nothing was let go). A goroutine locked to its
// thread parks the thread when it waits, so the known-folder read of
// stillPlain ran on another thread and its answer woke this one: two thread
// switches for each read, about 1,700 of them in a Windows hook call that
// appends to 12 files after a Set-Location (rel-1-0-10:GAP-1316). With the
// thread free the read runs on it, as it did before the lock.
//
// While the thread is free the call has no key, so a goroutine the thread
// runs meanwhile finds no call, as before. A goroutine that holds its thread
// for more than the call (a LockOSThread of its own) keeps that thread, and
// the call keeps its key.
//
// The key and the map are read on one thread, as in currentHookCall: a
// goroutine that runs no call and moved off its thread between the two reads
// would otherwise take another call's key away (rel-1-0-10:GAP-1476).
func releaseHookCallThread() *hookCall {
	runtime.LockOSThread()
	id := hookCallKey()
	hookCalls.mu.Lock()
	call := hookCalls.calls[id]
	if call != nil {
		delete(hookCalls.calls, id)
	}
	hookCalls.mu.Unlock()
	runtime.UnlockOSThread()
	if call != nil {
		runtime.UnlockOSThread()
	}
	return call
}

// retakeHookCallThread locks the goroutine to the thread it runs on after a
// wait that releaseHookCallThread let go of call's thread, and keys call by
// that thread. No other open call has that key: a thread keyed to a call is
// locked to the call's goroutine, so this goroutine cannot run on it.
func retakeHookCallThread(call *hookCall) {
	if call == nil {
		return
	}
	runtime.LockOSThread()
	id := hookCallKey()
	hookCalls.mu.Lock()
	call.key = id
	hookCalls.calls[id] = call
	hookCalls.mu.Unlock()
}
