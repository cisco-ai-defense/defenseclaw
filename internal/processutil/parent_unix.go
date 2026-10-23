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

//go:build linux || darwin

package processutil

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"syscall"
)

// startInOwnGroup starts the child in a process group of its own, so the
// child and whatever it starts end together: a canceled command kills the
// group, and killDescendantsAtExit kills what is left of it when the child
// exits. An LLM helper a scanner started outlived the gateway (p0
// GAP-1156); a Hermes hook that Verify probed left the child it started
// running, one more for each check (r104 W5b).
func startInOwnGroup(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
	if cmd.Cancel != nil {
		cmd.Cancel = func() error { return killGroup(cmd.Process.Pid) }
	}
}

// killDescendantsAtExit waits, without reaping it, for the child to exit and
// kills the rest of its process group. The child is not reaped yet, so its
// pid, which is the group id, cannot have been reused. Until then a
// watchdog (groupWatchdog) kills the group if this process dies first.
func killDescendantsAtExit(cmd *exec.Cmd) {
	if cmd.Process == nil || cmd.SysProcAttr == nil || !cmd.SysProcAttr.Setpgid {
		return
	}
	defer groupWatchdog(cmd.Process.Pid)()
	if waitExitedUnreaped(cmd.Process.Pid) {
		_ = killGroup(cmd.Process.Pid)
	}
}

// groupWatchdog starts a shell that kills process group pgid when this
// process ends, however it ends. It reads a pipe whose only write end this
// process holds (close-on-exec, so no child inherits it); the kernel closes
// that end when this process dies, even by SIGKILL, and the read returns.
// The parent-death signal (Linux only) ends the direct child only: a helper
// the scanner started (an MCP server) outlived a killed gateway. The
// returned release ends the watchdog, which then kills the group too; call
// it before the group leader is reaped. Without a pipe or a shell nothing is
// watched.
func groupWatchdog(pgid int) (release func()) {
	release, err := armGroupWatchdog(pgid)
	if err != nil {
		return func() {}
	}
	return release
}

// armGroupWatchdog reports an arming failure to callers that must not start
// the command until gateway-death cleanup is ready.
func armGroupWatchdog(pgid int) (release func(), err error) {
	r, w, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("create process-group watchdog pipe: %w", err)
	}
	watchdog := exec.Command("/bin/sh", "-c", `read -r _; kill -9 "-$1" 2>/dev/null; exit 0`,
		"defenseclaw-group-watchdog", strconv.Itoa(pgid))
	watchdog.Stdin = r
	watchdog.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	startErr := watchdog.Start()
	_ = r.Close()
	if startErr != nil {
		_ = w.Close()
		return nil, fmt.Errorf("start process-group watchdog: %w", startErr)
	}
	return func() {
		_ = w.Close()
		_ = watchdog.Wait()
	}, nil
}

func killGroup(pid int) error {
	err := syscall.Kill(-pid, syscall.SIGKILL)
	if errors.Is(err, syscall.ESRCH) {
		return os.ErrProcessDone
	}
	return err
}
