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

//go:build darwin

package processutil

import (
	"errors"
	"os/exec"
	"time"

	"golang.org/x/sys/unix"
)

// exitWithParent starts the child in a process group of its own
// (startInOwnGroup). macOS has no parent-death signal; the group watchdog
// of killDescendantsAtExit ends the tree when this process dies.
func exitWithParent(cmd *exec.Cmd) {
	startInOwnGroup(cmd)
}

// darwinZombie is SZOMB in <sys/proc.h>: exited, not reaped yet.
const darwinZombie = 5

// darwinExitPoll bounds each kqueue wait; between waits the process state
// is read, so an exit the NOTE_EXIT registration missed still ends the wait.
const darwinExitPoll = 100 * time.Millisecond

// waitExitedUnreaped blocks until child pid has exited and leaves it
// unreaped, so its pid, the group id, stays reserved until cmd.Wait. A
// kqueue NOTE_EXIT fires at exit without reaping; ESRCH at registration
// means the child has exited already (it is this process's unreaped child).
// It reports false when neither kqueue nor the process table can tell.
func waitExitedUnreaped(pid int) bool {
	kq, err := unix.Kqueue()
	if err != nil {
		return false
	}
	defer unix.Close(kq)
	change := unix.Kevent_t{
		Ident:  uint64(pid),
		Filter: unix.EVFILT_PROC,
		Flags:  unix.EV_ADD | unix.EV_ONESHOT,
		Fflags: unix.NOTE_EXIT,
	}
	for {
		_, err = unix.Kevent(kq, []unix.Kevent_t{change}, nil, nil)
		if !errors.Is(err, unix.EINTR) {
			break
		}
	}
	if err != nil {
		return errors.Is(err, unix.ESRCH)
	}
	events := make([]unix.Kevent_t, 1)
	poll := unix.NsecToTimespec(darwinExitPoll.Nanoseconds())
	for {
		n, err := unix.Kevent(kq, nil, events, &poll)
		switch {
		case errors.Is(err, unix.EINTR):
		case err != nil:
			return false
		case n > 0:
			return true
		}
		info, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
		if err != nil {
			return false
		}
		if info.Proc.P_stat == darwinZombie {
			return true
		}
	}
}
