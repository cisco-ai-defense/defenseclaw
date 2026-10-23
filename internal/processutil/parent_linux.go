// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package processutil

import (
	"errors"
	"os/exec"
	"syscall"

	"golang.org/x/sys/unix"
)

// exitWithParent asks the kernel to kill the child with its parent
// (GAP-0418) and starts it in a process group of its own (startInOwnGroup).
// The parent-death signal reaches the direct child only.
func exitWithParent(cmd *exec.Cmd) {
	startInOwnGroup(cmd)
	cmd.SysProcAttr.Pdeathsig = syscall.SIGKILL
}

// waitExitedUnreaped blocks until child pid has exited and leaves it
// unreaped (WNOWAIT). It reports false when the wait fails.
func waitExitedUnreaped(pid int) bool {
	var info unix.Siginfo
	for {
		err := unix.Waitid(unix.P_PID, pid, &info, unix.WEXITED|unix.WNOWAIT, nil)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		return err == nil
	}
}
