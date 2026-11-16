// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import "testing"

func setFileLockContendedHookForTest(t *testing.T, fn func(lockPath string)) {
	t.Helper()
	windowsLockContendedHookForTest.Store(&fn)
	t.Cleanup(func() { windowsLockContendedHookForTest.Store(nil) })
}
