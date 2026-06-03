// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package daemon

import (
	"os"
	"os/exec"
	"syscall"

	"golang.org/x/sys/windows"
)

func setSysProcAttr(cmd *exec.Cmd) {
	// Detach the gateway so it outlives the launching process and console.
	// CREATE_NEW_PROCESS_GROUP puts the gateway in its own group, so a
	// Ctrl+C/Ctrl+Break aimed at the launcher's group is not inherited, and
	// it becomes addressable by GenerateConsoleCtrlEvent for graceful stop.
	// DETACHED_PROCESS drops the inherited console so a closing terminal
	// cannot deliver CTRL_CLOSE and take the gateway down with it.
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: windows.CREATE_NEW_PROCESS_GROUP | windows.DETACHED_PROCESS,
	}
}

func sendTermSignal(proc *os.Process) error {
	// Prefer a graceful stop: deliver Ctrl+Break to the gateway's own
	// process group. Go's runtime turns a console Ctrl+Break into
	// os.Interrupt, which the sidecar handles by cancelling its context and
	// calling http.Server.Shutdown. When the gateway was started detached
	// (no shared console), this returns an error; fall back to
	// TerminateProcess so `stop` does not block for the full timeout. The
	// caller still waits for exit and force-kills on timeout.
	if err := windows.GenerateConsoleCtrlEvent(windows.CTRL_BREAK_EVENT, uint32(proc.Pid)); err == nil {
		return nil
	}
	return proc.Kill()
}

func sendKillSignal(proc *os.Process) error {
	return proc.Kill()
}

func processExists(pid int) bool {
	// On Windows, os.FindProcess always succeeds regardless of whether the
	// PID is live. Use OpenProcess with PROCESS_QUERY_LIMITED_INFORMATION to
	// obtain a real handle: if the process is dead (or access is denied due
	// to a different user), OpenProcess returns an error.
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return false
	}
	_ = windows.CloseHandle(h)
	return true
}

// killStaleProcesses is a no-op on Windows. pgrep is not available and
// process group semantics differ; stale process cleanup relies on the
// PID file only.
func (d *Daemon) killStaleProcesses() {}
