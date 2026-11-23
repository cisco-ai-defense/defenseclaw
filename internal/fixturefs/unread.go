// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package fixturefs

import (
	"bytes"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
)

// A decision that judges a call by its words alone reads no file system: a
// Substrate actor's call in copy mode names files of the actor, which this
// host does not have, and the gateway never opens a host path for it
// (substrate-1 GAP-0922, TestSandboxIngressCopyModeNeverTouchesHostFS).
// Unread runs such a decision. While it runs, Map hands every read of its
// goroutine, and of the goroutines it starts through Go, the empty name,
// which every read answers "does not exist"; nothing reaches the file
// system and nothing is observed. Other goroutines read as before.
//
// The scope is the goroutine: the readers of one decision call Map in the
// goroutine that runs it, or in one started through Go. The check costs one
// atomic load while no Unread runs anywhere in the process; while one runs,
// a check reads the goroutine's number and a lock-free map, and takes no
// lock that other goroutines' reads wait on (substrate-1 GAP-0997).

var (
	unreadActive atomic.Int64
	// unreadIDs counts, by goroutine number, the Unread calls that goroutine
	// is inside. Only the goroutine itself changes its entry.
	unreadIDs sync.Map // uint64 -> int
)

// Unread runs fn with no file system for the goroutine that runs it.
func Unread(fn func()) {
	leave := enterUnread(goroutineID())
	defer leave()
	fn()
}

// Unreadable reports whether the calling goroutine runs inside Unread.
func Unreadable() bool {
	if unreadActive.Load() == 0 {
		return false
	}
	depth, _ := unreadIDs.Load(goroutineID())
	n, _ := depth.(int)
	return n > 0
}

// Go starts fn in a new goroutine that reads as its caller does: inside
// Unread when the caller is.
func Go(fn func()) {
	if !Unreadable() {
		go fn()
		return
	}
	go Unread(fn)
}

func enterUnread(id uint64) (leave func()) {
	depth, _ := unreadIDs.Load(id)
	n, _ := depth.(int)
	unreadIDs.Store(id, n+1)
	unreadActive.Add(1)
	return func() {
		if n <= 0 {
			unreadIDs.Delete(id)
		} else {
			unreadIDs.Store(id, n)
		}
		unreadActive.Add(-1)
	}
}

// goroutineID is the runtime's number of the calling goroutine (0: unknown,
// which no Unread registers, so such a goroutine reads as before).
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
