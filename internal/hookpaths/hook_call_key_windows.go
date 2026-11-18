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
