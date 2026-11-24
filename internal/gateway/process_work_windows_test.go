// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package gateway

import (
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// processWork is the CPU time (user and kernel, every thread) this test
// process has used so far: the work a call did. A busy box stretches the
// wall-clock time of the same work several times over and its CPU time
// hardly at all
// (rel-1-0-10:GAP-2129). The test fails when the clock cannot be read.
func processWork(t testing.TB) time.Duration {
	t.Helper()
	var creation, exit, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(windows.CurrentProcess(), &creation, &exit, &kernel, &user); err != nil {
		t.Fatalf("process CPU time: %v", err)
	}
	ticks := func(f windows.Filetime) int64 { return int64(f.HighDateTime)<<32 | int64(f.LowDateTime) }
	return time.Duration((ticks(kernel) + ticks(user)) * 100)
}
