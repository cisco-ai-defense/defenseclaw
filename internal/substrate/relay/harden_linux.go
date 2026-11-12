// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package relay

import "golang.org/x/sys/unix"

// hardenProcess makes the relay non-dumpable: a process of the agent's user
// (the same user) can then neither trace it nor read its memory or open its
// descriptors (/proc/<pid>/fd), so it cannot reach the agent's PTY master
// (GAP-0048). The agent itself is exec'd and dumpable again.
func hardenProcess() error {
	return unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0)
}

// dumpable reports the process's dumpable flag (tests).
func dumpable() (bool, error) {
	v, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
	return v != 0, err
}
