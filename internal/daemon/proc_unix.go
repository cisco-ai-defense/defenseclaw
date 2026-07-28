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

//go:build !windows

package daemon

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func setSysProcAttr(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}
}

func daemonChildRegistersPID() bool { return false }

func sendTermSignal(proc *os.Process) error {
	return proc.Signal(syscall.SIGTERM)
}

func sendKillSignal(proc *os.Process) error {
	return proc.Signal(syscall.SIGKILL)
}

func processExists(pid int) bool {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	err = proc.Signal(syscall.Signal(0))
	return err == nil
}

func waitForProcessExit(_ *os.Process, pid int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for {
		if !processExists(pid) {
			return true
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return false
		}
		if remaining > 100*time.Millisecond {
			remaining = 100 * time.Millisecond
		}
		time.Sleep(remaining)
	}
}

// processStartIdentity returns an opaque string that uniquely identifies a
// process for the lifetime of that process. After PID reuse it will not match
// the previous process's value. Used by verifyProcess() to detect that a
// stale gateway.pid is now pointing at an unrelated process that happened to
// reuse the same PID.
//
// Closes avarice F-0942 (second half of chain F-3399). The returned string is
// platform-defined and only meaningful when compared to a value previously
// captured by writePIDInfo() for the same PID.
//
//   - Linux: field 22 of /proc/<pid>/stat (starttime in clock ticks since
//     boot). Stable for the lifetime of the process; resets after PID reuse.
//   - Darwin: `ps -p <pid> -o lstart=` ("Sun May 10 12:34:56 2026"). The
//     1-second granularity creates a tiny theoretical collision window
//     immediately after PID reuse, but the executable check in verifyProcess
//     covers that — both signals must agree.
//
// Returns ("", nil) on platforms where we can't read a stable identity (e.g.
// FreeBSD); callers should treat that as "skip the start-time check" rather
// than "process is dead".
func processStartIdentity(pid int) (string, error) {
	switch runtime.GOOS {
	case "linux":
		data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
		if err != nil {
			return "", err
		}
		// /proc/<pid>/stat fields are space-separated, but field 2 (the
		// process command) can contain spaces and is wrapped in
		// parentheses. Find the LAST `)` and split the tail. Field 22 is
		// the starttime; tail field index = 22 - 2 = 20.
		idx := strings.LastIndex(string(data), ")")
		if idx < 0 || idx+2 > len(data) {
			return "", fmt.Errorf("daemon: malformed /proc/%d/stat", pid)
		}
		tail := strings.Fields(string(data[idx+2:]))
		// Index 19 == field 22 of the original (we have skipped pid + comm).
		if len(tail) < 20 {
			return "", fmt.Errorf("daemon: /proc/%d/stat has only %d tail fields", pid, len(tail))
		}
		return tail[19], nil
	case "darwin":
		out, err := exec.Command("ps", "-p", strconv.Itoa(pid), "-o", "lstart=").Output()
		if err != nil {
			return "", err
		}
		s := strings.TrimSpace(string(out))
		if s == "" {
			return "", fmt.Errorf("daemon: ps returned empty lstart for pid %d", pid)
		}
		return s, nil
	default:
		return "", nil
	}
}

// killStaleProcesses finds and kills any defenseclaw-gateway processes that
// are not tracked by the PID file. This prevents orphaned daemons from
// accumulating across restarts. The watchdog PID is preserved.
func (d *Daemon) killStaleProcesses() error {
	trackedPID, watchdogPID, err := d.protectedDaemonPIDs()
	if err != nil {
		return err
	}

	// Linux exposes both the executable and the NUL-delimited environment
	// through /proc, which lets us prove a candidate is one of our daemon
	// children for this exact data directory.  Other Unix platforms do not
	// provide an equivalent race-bounded proof here, so stale cleanup remains
	// best-effort and deliberately does nothing there.
	if runtime.GOOS != "linux" {
		return nil
	}

	self, _ := os.Executable()
	binName := filepath.Base(self)
	if binName == "" || binName == "." {
		binName = "defenseclaw-gateway"
	}

	out, err := exec.Command("pgrep", "-f", binName).Output()
	if err != nil {
		return nil
	}
	myPID := os.Getpid()

	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		pid, err := strconv.Atoi(strings.TrimSpace(line))
		if err != nil || pid <= 0 || pid == myPID || pid == trackedPID || pid == watchdogPID {
			continue
		}
		startIdentity, proven := d.proveStaleDaemonProcess(pid, self)
		if !proven {
			continue
		}
		// Re-read the kernel process identity immediately before signalling.
		// If the inspected process exited and its PID was reused, fail closed.
		currentIdentity, err := processStartIdentity(pid)
		if err != nil || currentIdentity == "" || currentIdentity != startIdentity {
			continue
		}
		proc, err := os.FindProcess(pid)
		if err != nil {
			continue
		}
		fmt.Fprintf(os.Stderr, "[daemon] killing stale gateway process (PID %d)\n", pid)
		_ = proc.Signal(syscall.SIGTERM)
	}
	return nil
}

// proveStaleDaemonProcess returns the Linux start identity only after proving
// that pid is the exact gateway executable running as a daemon child for this
// Daemon's data directory.  pgrep -f candidates are untrusted: a phase-two
// mutator wrapper legitimately contains "defenseclaw-gateway start" in its
// argv, and signalling it would race the real child against upgrade rollback.
func (d *Daemon) proveStaleDaemonProcess(pid int, executable string) (string, bool) {
	if runtime.GOOS != "linux" || pid <= 0 || executable == "" {
		return "", false
	}
	startIdentity, err := processStartIdentity(pid)
	if err != nil || startIdentity == "" {
		return "", false
	}

	actualExecutable, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return "", false
	}
	// A replaced gateway can remain alive on its deleted inode.  Linux marks
	// that link with " (deleted)"; it is still the stale instance we intend to
	// stop when every other identity signal agrees.
	actualExecutable = strings.TrimSuffix(actualExecutable, " (deleted)")
	expectedExecutable := executable
	if resolved, resolveErr := filepath.EvalSymlinks(expectedExecutable); resolveErr == nil {
		expectedExecutable = resolved
	}
	if filepath.Clean(actualExecutable) != filepath.Clean(expectedExecutable) {
		return "", false
	}

	environment, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid))
	if err != nil || len(environment) == 0 || len(environment) > 4*1024*1024 {
		return "", false
	}
	markerCount := 0
	dataDirCount := 0
	for _, entry := range strings.Split(string(environment), "\x00") {
		switch entry {
		case EnvDaemon + "=1":
			markerCount++
		case EnvDataDir + "=" + d.dataDir:
			dataDirCount++
		}
	}
	if markerCount != 1 || dataDirCount != 1 {
		return "", false
	}
	return startIdentity, true
}
