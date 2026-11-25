// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookpaths

import (
	"bytes"
	"runtime"
	"strconv"
)

// lockHookCallKey keeps nothing off Windows: hookCallKey reads the
// goroutine's own number, which never changes.
func lockHookCallKey() (unlock func()) { return func() {} }

// hookCallKey is the key of the calling goroutine's hook call off Windows:
// its goroutine number (0: not read). Off Windows a memo read finds no call
// (memoReads), so the traceback is paid only by the share-wait checks.
func hookCallKey() uint64 { return goroutineID() }

// foundCallServes reports that a call the goroutine found a moment before
// (Call) may serve its next read without finding it again: off Windows the
// key is the goroutine number, which never changes, so the open call the
// goroutine found is the one hookCallKey would find (JoinHookCall).
const foundCallServes = true

// releaseHookCallThread lets nothing go off Windows: the goroutine holds no
// thread for its call, and its key does not change with the thread it runs on.
func releaseHookCallThread() *hookCall { return nil }

// retakeHookCallThread has nothing to take back off Windows.
func retakeHookCallThread(*hookCall) {}

// goroutineID is the runtime's number of the calling goroutine (0: not
// read), from the first line of its stack: "goroutine N [...". Numbers are
// not reused while the process runs.
func goroutineID() uint64 {
	var buf [64]byte
	line, ok := bytes.CutPrefix(buf[:runtime.Stack(buf[:], false)], []byte("goroutine "))
	if !ok {
		return 0
	}
	digits, _, _ := bytes.Cut(line, []byte(" "))
	id, err := strconv.ParseUint(string(digits), 10, 64)
	if err != nil {
		return 0
	}
	return id
}
