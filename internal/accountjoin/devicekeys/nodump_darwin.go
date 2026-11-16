// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package devicekeys

import "golang.org/x/sys/unix"

// disableCrashDumps sets RLIMIT_CORE to 0 (soft and hard): no core file in
// /cores. ReportCrash writes a crash report without process memory.
func disableCrashDumps() {
	_ = unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0})
}
