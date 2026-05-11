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
// The returned string is platform-defined and only meaningful when compared
// to a value previously captured by writePIDInfo() for the same PID.
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

// killStaleProcesses finds and kills orphaned defenseclaw-gateway processes
// that share THIS daemon's data directory but are no longer tracked by the
// PID file.
//
// The previous implementation pgrep -f'd on the bare binary basename and
// signalled every match. That:
//
//   - sent SIGTERM to other DefenseClaw daemons running from a DIFFERENT
//     data directory (different profile), causing cross-profile outages,
//   - sent SIGTERM to any user shell command whose argv merely contained
//     the basename string, and
//   - did not validate /proc/<pid>/exe so a process that happened to share
//     a name was killed regardless of who actually owned that PID.
//
// The fix triple-verifies every candidate before signalling:
//
//  1. /proc/<pid>/exe (Linux) MUST resolve to the same path as
//     os.Executable(). On macOS we fall back to the existing
//     processExecutableDarwin name comparison.
//  2. /proc/<pid>/environ (Linux) MUST contain DEFENSECLAW_DAEMON=1 AND
//     DEFENSECLAW_DATA_DIR=<this daemon's data dir>. macOS has no readable
//     environ for other PIDs so we conservatively skip the cleanup there.
//  3. The PID is not the current process, the tracked PID, or the
//     watchdog PID.
//
// If any check fails the process is left alone. Verification is reliable on
// Linux through /proc, so we keep the cleanup for that platform but make it
// surgical. Combined with processStartIdentity above, verifyProcess can also
// detect that a stale gateway.pid now points at an unrelated PID-reuse
// process.
func (d *Daemon) killStaleProcesses() {
	self, _ := os.Executable()
	if self == "" {
		// Cannot verify anything reliably; refuse to kill anything.
		return
	}

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

		// VERIFICATION GATE 1: executable identity. On Linux the
		// /proc/<pid>/exe symlink resolves to the absolute path that
		// the kernel started the process with, regardless of how argv
		// was assembled. A foreign process with our basename in argv
		// will resolve to its own real binary and be rejected.
		exePath, exeErr := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
		if exeErr != nil || exePath == "" {
			// /proc not readable or pid gone — refuse to signal.
			continue
		}
		if exePath != self {
			continue
		}

		// VERIFICATION GATE 2: data-dir identity. The daemon child
		// inherits DEFENSECLAW_DAEMON=1 + DEFENSECLAW_DATA_DIR=<dir>
		// from Daemon.Start. /proc/<pid>/environ is a NUL-separated
		// list of key=value entries. Without this gate, a sibling
		// daemon running from a different profile (== different data
		// dir) would still match the exe check and get killed.
		envBytes, envErr := os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid))
		if envErr != nil {
			continue
		}
		if !daemonEnvMatchesDataDir(envBytes, d.dataDir) {
			continue
		}

		proc, err := os.FindProcess(pid)
		if err != nil {
			continue
		}
		fmt.Fprintf(os.Stderr, "[daemon] killing verified stale gateway process (PID %d, exe=%s, data_dir=%s)\n", pid, exePath, d.dataDir)
		_ = proc.Signal(syscall.SIGTERM)
	}
}

// daemonEnvMatchesDataDir parses a NUL-separated /proc/<pid>/environ blob
// and reports whether it contains BOTH DEFENSECLAW_DAEMON=1 AND
// DEFENSECLAW_DATA_DIR=<dataDir>. Both must be present; either alone is
// insufficient (a daemon child without the data-dir marker is from an
// older binary, and we conservatively leave those alone).
func daemonEnvMatchesDataDir(environ []byte, dataDir string) bool {
	if len(environ) == 0 || dataDir == "" {
		return false
	}
	wantDaemon := EnvDaemon + "=1"
	wantDataDir := EnvDataDir + "=" + dataDir

	hasDaemon := false
	hasDataDir := false
	for _, kv := range strings.Split(string(environ), "\x00") {
		switch kv {
		case wantDaemon:
			hasDaemon = true
		case wantDataDir:
			hasDataDir = true
		}
		if hasDaemon && hasDataDir {
			return true
		}
	}
	return false
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
