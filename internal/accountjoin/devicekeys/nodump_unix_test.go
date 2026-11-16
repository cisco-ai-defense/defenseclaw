// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package devicekeys

import (
	"testing"

	"golang.org/x/sys/unix"
)

// The process that reads the tenant secret writes no core file.
func TestDisableCrashDumpsSetsTheCoreLimitToZero(t *testing.T) {
	disableCrashDumps()
	var limit unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_CORE, &limit); err != nil {
		t.Fatal(err)
	}
	if limit.Cur != 0 || limit.Max != 0 {
		t.Fatalf("RLIMIT_CORE = %d/%d, want 0/0", limit.Cur, limit.Max)
	}
}
