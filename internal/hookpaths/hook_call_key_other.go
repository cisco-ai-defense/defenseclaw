// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookpaths

// lockHookCallKey keeps nothing off Windows: hookCallKey names the goroutine
// itself, whatever thread it runs on.
func lockHookCallKey() (unlock func()) { return func() {} }

// hookCallKey is the key of the calling goroutine's hook call off Windows
// (goroutineKey; 0: not read).
func hookCallKey() uint64 { return goroutineKey() }

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
