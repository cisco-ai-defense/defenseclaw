// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package processutil

import "golang.org/x/sys/unix"

// currentNice is the nice value of this process.
func currentNice() int {
	nice, err := unix.Getpriority(unix.PRIO_PROCESS, 0)
	if err != nil {
		return 0
	}
	return nice
}
