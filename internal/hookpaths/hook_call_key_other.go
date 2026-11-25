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

// releaseHookCallThread lets nothing go off Windows: the goroutine holds no
// thread for its call, and its key does not change with the thread it runs on.
func releaseHookCallThread() *hookCall { return nil }

// retakeHookCallThread has nothing to take back off Windows.
func retakeHookCallThread(*hookCall) {}
