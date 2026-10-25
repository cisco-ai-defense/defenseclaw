// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookexec

import (
	"errors"
	"syscall"

	"github.com/defenseclaw/defenseclaw/internal/procidentity"
)

// installLockOwnerExited reports a pid that names no process (ESRCH) or one
// that has exited but is not reaped (a zombie keeps its pid and its start,
// but runs nothing). A process of another account (EPERM) or any other
// answer keeps the lock.
func installLockOwnerExited(pid int) bool {
	return errors.Is(syscall.Kill(pid, 0), syscall.ESRCH) || procidentity.Ended(pid)
}
