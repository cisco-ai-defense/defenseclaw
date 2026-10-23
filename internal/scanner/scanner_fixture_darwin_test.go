// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package scanner

import (
	"errors"
	"testing"

	"golang.org/x/sys/unix"
)

// darwinZombie is SZOMB from XNU's sys/proc.h.
const darwinZombie = 5

// scannerFixtureRunning reports whether pid exists and is not a zombie. It
// asks the kernel, so it needs no external tool; a check that fails for any
// reason other than a missing process fails the test.
func scannerFixtureRunning(t *testing.T, pid int) bool {
	t.Helper()
	if err := unix.Kill(pid, 0); errors.Is(err, unix.ESRCH) {
		return false
	} else if err != nil && !errors.Is(err, unix.EPERM) {
		t.Fatalf("signal 0 to %d: %v", pid, err)
	}
	info, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil {
		// kern.proc.pid returns no record once the process is reaped.
		if killErr := unix.Kill(pid, 0); errors.Is(killErr, unix.ESRCH) {
			return false
		}
		t.Fatalf("read state of %d: %v", pid, err)
	}
	return info.Proc.P_stat != darwinZombie
}
