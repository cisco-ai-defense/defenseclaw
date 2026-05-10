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
)

func setSysProcAttr(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}
}

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
func (d *Daemon) killStaleProcesses() {
	self, _ := os.Executable()
	binName := filepath.Base(self)
	if binName == "" || binName == "." {
		binName = "defenseclaw-gateway"
	}

	out, err := exec.Command("pgrep", "-f", binName).Output()
	if err != nil {
		return
	}

	trackedPID := 0
	if info, err := d.readPIDInfo(); err == nil {
		trackedPID = info.PID
	}
	myPID := os.Getpid()
	watchdogPID := d.readWatchdogPID()

	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		pid, err := strconv.Atoi(strings.TrimSpace(line))
		if err != nil || pid <= 0 || pid == myPID || pid == trackedPID || pid == watchdogPID {
			continue
		}
		proc, err := os.FindProcess(pid)
		if err != nil {
			continue
		}
		fmt.Fprintf(os.Stderr, "[daemon] killing stale gateway process (PID %d)\n", pid)
		_ = proc.Signal(syscall.SIGTERM)
	}
}

// readWatchdogPID reads the watchdog PID from watchdog.pid in the data dir.
func (d *Daemon) readWatchdogPID() int {
	data, err := os.ReadFile(filepath.Join(d.dataDir, "watchdog.pid"))
	if err != nil {
		return 0
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 0 {
		return 0
	}
	return pid
}
