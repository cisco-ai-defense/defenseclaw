// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookexec

import (
	"errors"
	"syscall"
)

// installLockOwnerExited reports a pid that names no process (ESRCH). A
// process of another account (EPERM) or any other answer keeps the lock.
func installLockOwnerExited(pid int) bool {
	return errors.Is(syscall.Kill(pid, 0), syscall.ESRCH)
}
