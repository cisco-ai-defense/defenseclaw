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

	"golang.org/x/sys/windows"
)

func setSysProcAttr(cmd *exec.Cmd) {
	// Windows does not support Setpgid; processes are already in their own job.
}

func sendTermSignal(proc *os.Process) error {
	// Windows has no SIGTERM; kill the process directly.
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
