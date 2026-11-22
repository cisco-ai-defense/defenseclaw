// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package testenv

import (
	"errors"
	"os/exec"
	"syscall"
	"time"
)

// StartWritten starts the command newCmd builds for an executable the test
// has just written. A fork anywhere else in the process (a parallel test, a
// worker of the same test) that lands while the executable's write
// descriptor is open keeps a copy of that descriptor until the child execs,
// and an exec of the file fails with ETXTBSY ("text file busy") meanwhile
// (golang/go#22315). Writing to a temporary name and renaming does not help:
// the copied descriptor names the same file. The bytes are final once
// written, so a fresh command for the same file starts the same program;
// StartWritten retries for up to five seconds on ETXTBSY only and returns
// any other error at once (rel-1-0-10:GAP-1208). Windows has no ETXTBSY,
// so there the first error is returned.
func StartWritten(newCmd func() *exec.Cmd) (*exec.Cmd, error) {
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		cmd := newCmd()
		err := cmd.Start()
		if err == nil || !errors.Is(err, syscall.ETXTBSY) || time.Now().After(deadline) {
			return cmd, err
		}
	}
}
