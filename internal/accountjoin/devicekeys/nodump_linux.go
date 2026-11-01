// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package devicekeys

import (
	"os"

	"golang.org/x/sys/unix"
)

// disableCrashDumps sets RLIMIT_CORE to 0 (soft and hard) and, as root,
// clears the dumpable flag: no core file, no core through a core_pattern
// pipe (systemd-coredump, abrt), and no ptrace or /proc/<pid>/mem read by
// another process of the same uid. The callers are short-lived CLI runs;
// their child processes start dumpable again when they execute.
func disableCrashDumps() {
	_ = unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0})
	if os.Geteuid() == 0 {
		_ = unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0)
	}
}
