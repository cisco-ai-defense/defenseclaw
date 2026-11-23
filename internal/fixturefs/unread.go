// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package fixturefs

import (
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
// a check reads the key of the calling goroutine (unreadKey) and a lock-free
// map, and takes no lock that other goroutines' reads wait on (substrate-1
// GAP-0997). On Linux and Windows Unread holds its goroutine on its thread
// and the key is the thread's id: the goroutine's number is read from a
// traceback of its whole stack, which took 79% of a by-name decision, 1.4
// to 13 ms for an ordinary call (substrate-1 GAP-0999).

var (
	unreadActive atomic.Int64
	// unreadIDs counts, by key (unreadKey), the Unread calls the goroutine
	// of that key is inside. Only the goroutine itself changes its entry.
	unreadIDs sync.Map // uint64 -> int
)

// Unread runs fn with no file system for the goroutine that runs it.
func Unread(fn func()) {
	// Keep the thread pinned until its entry is removed. Register the unlock
	// immediately so even a panic while setting up the entry releases it.
	unlock := lockUnreadKey()
	defer unlock()
	id := unreadKey()
	depth, _ := unreadIDs.Load(id)
	n, _ := depth.(int)
	unreadIDs.Store(id, n+1)
	unreadActive.Add(1)
	defer func() {
		if n <= 0 {
			unreadIDs.Delete(id)
		} else {
			unreadIDs.Store(id, n)
		}
		unreadActive.Add(-1)
	}()
	fn()
}

// Unreadable reports whether the calling goroutine runs inside Unread.
func Unreadable() bool {
	if unreadActive.Load() == 0 {
		return false
	}
	depth, _ := unreadIDs.Load(unreadKey())
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
