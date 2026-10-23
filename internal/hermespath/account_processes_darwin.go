// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package hermespath

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// runningProcessEvidence reads HERMES_HOME from the environment of every
// running process of uid: the process list (kern.proc.uid) and each one's
// arguments and environment (kern.procargs2). A HERMES_HOME exported from a
// file a startup file sources, a terminal profile or an IDE shows there and
// in no file read. The kernel bounds the buffer (kern.argmax). A process
// that exits or cannot be read is skipped, as on Linux; a caller that is neither root nor uid can read none, which
// fails.
func runningProcessEvidence(uid int) ([]homeEvidence, error) {
	if err := canReadProcessesOf(uid); err != nil {
		return nil, err
	}
	processes, err := unix.SysctlKinfoProcSlice("kern.proc.uid", uid)
	if err != nil {
		return nil, fmt.Errorf("list the processes of uid %d: %w", uid, err)
	}
	var out []homeEvidence
	for _, process := range processes {
		pid := int(process.Proc.P_pid)
		args, err := unix.SysctlRaw("kern.procargs2", pid)
		if err != nil {
			// The process exited, or the kernel withholds it.
			continue
		}
		out = append(out, environEvidence(procargs2Environment(args), func() string {
			return fmt.Sprintf("running process %d (%s)", pid, unix.ByteSliceToString(process.Proc.P_comm[:]))
		})...)
	}
	return out, nil
}
