// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package fixturefs

import (
	"runtime"

	"golang.org/x/sys/windows"
)

// lockUnreadKey holds the calling goroutine on its thread, so that no other
// goroutine runs there and the thread's id is the goroutine's key.
func lockUnreadKey() (unlock func()) {
	runtime.LockOSThread()
	return runtime.UnlockOSThread
}

// unreadKey is the id of the calling thread.
func unreadKey() uint64 { return uint64(windows.GetCurrentThreadId()) }
