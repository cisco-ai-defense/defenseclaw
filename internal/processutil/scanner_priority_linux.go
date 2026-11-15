// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package processutil

import "golang.org/x/sys/unix"

// currentNice is the nice value of the calling thread. The getpriority
// system call returns 20 minus it, so that it is never negative.
func currentNice() int {
	prio, err := unix.Getpriority(unix.PRIO_PROCESS, 0)
	if err != nil {
		return 0
	}
	return 20 - prio
}
