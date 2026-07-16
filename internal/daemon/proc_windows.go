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
	"strconv"
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
	// The managed gateway is always launched with DETACHED_PROCESS (see
	// setSysProcAttr), so it shares no console with the CLI invoking stop /
	// restart. GenerateConsoleCtrlEvent therefore cannot deliver a graceful
	// Ctrl+Break to it: in practice the call returns success while signaling
	// nothing, so Stop's graceful wait burned the full timeout and then
	// reported ErrStopTimeout even though the process was reachable. Because a
	// detached daemon can never receive a console control event, terminate
	// directly — TerminateProcess is the only reliable stop here and was
	// already the existing fallback. (A future graceful path would need an
	// out-of-band shutdown channel, e.g. a named event or an HTTP endpoint.)
	return proc.Kill()
}

func sendKillSignal(proc *os.Process) error {
	return proc.Kill()
}

func processExists(pid int) bool {
	// On Windows, os.FindProcess always succeeds regardless of whether the
	// PID is live, so we open a real handle. OpenProcess succeeding is not by
	// itself proof of life: a terminated process whose kernel object is still
	// referenced by an open handle (e.g. the os.FindProcess handle Stop holds
	// across a TerminateProcess) remains openable as a "zombie". That made
	// Stop's post-kill liveness check a false positive and surfaced as
	// ErrStopTimeout. Confirm the process has not exited by inspecting its
	// exit code: STILL_ACTIVE (259) means running; any real exit code means
	// gone. Mirrors the CLI-side check in
	// cli/defenseclaw/process_liveness.py so both agree on "running".
	const stillActive = 259
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return false
	}
	defer windows.CloseHandle(h)
	var code uint32
	if err := windows.GetExitCodeProcess(h, &code); err != nil {
		// Handle opened but exit code unavailable: treat as alive so we never
		// drop a genuinely running daemon from tracking on a transient query
		// failure.
		return true
	}
	return code == stillActive
}

// processStartIdentity returns an opaque string that uniquely identifies a
// process for its lifetime, used by verifyProcess() to detect a stale
// gateway.pid that now points at an unrelated process which reused the PID.
//
// On Windows the process creation time (GetProcessTimes) is fixed for the
// life of the process and differs after PID reuse, so the raw FILETIME is a
// stable opaque identity. Mirrors the Unix contract: returns ("", err) when
// the process can't be queried (dead PID or access denied), and callers
// treat a captured-vs-live mismatch as "not the same process".
func processStartIdentity(pid int) (string, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(h)
	var creation, exit, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(h, &creation, &exit, &kernel, &user); err != nil {
		return "", err
	}
	return strconv.FormatInt(creation.Nanoseconds(), 10), nil
}

// killStaleProcesses cannot discover untracked processes on Windows because
// pgrep and Unix process identity metadata are unavailable. It still performs
// the same identity-file preflight as Unix so malformed or unreadable state
// cannot authorize launching another child.
func (d *Daemon) killStaleProcesses() error {
	_, _, err := d.protectedDaemonPIDs()
	return err
}
