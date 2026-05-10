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
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const (
	PIDFileName = "gateway.pid"
	LogFileName = "gateway.log"
	EnvDaemon   = "DEFENSECLAW_DAEMON"
	// EnvDataDir is set by Daemon.Start in the spawned child's
	// environment so killStaleProcesses can verify that a candidate
	// process belongs to THIS data directory before signalling it.
	// Required for the DeepSec S3.HIGH_BUG fix
	// "killStaleProcesses can terminate unrelated processes": without
	// a per-data-dir marker, two legitimate DefenseClaw daemons
	// running from different profiles cannot tell each other apart by
	// executable name alone.
	EnvDataDir = "DEFENSECLAW_DATA_DIR"
)

var (
	ErrAlreadyRunning = errors.New("daemon is already running")
	ErrNotRunning     = errors.New("daemon is not running")
	ErrStopTimeout    = errors.New("daemon did not stop within timeout")
)

type Daemon struct {
	dataDir string
	pidFile string
	logFile string
}

func New(dataDir string) *Daemon {
	return &Daemon{
		dataDir: dataDir,
		pidFile: filepath.Join(dataDir, PIDFileName),
		logFile: filepath.Join(dataDir, LogFileName),
	}
}

func (d *Daemon) PIDFile() string { return d.pidFile }
func (d *Daemon) LogFile() string { return d.logFile }

// openLogFileForChild opens the textual daemon log as an append-mode *os.File
// suitable for the child process's stdout/stderr. Returning a real file (not
// an io.Writer) lets os/exec inherit the fd directly into the child — there
// is NO parent-side pipe or goroutine, so writes to stderr from the child
// continue to land on disk even after the spawning CLI exits.
//
// That's the fix for the symptom "gateway.log stops updating once the daemon
// detaches" / "no [guardrail] ← lines ever appear": previously Stdout/Stderr
// were a *lumberjack.Logger, which os/exec handles via a pipe + a goroutine
// inside the *parent*. When the parent exited the goroutine died, the pipe's
// read end closed, and every fmt.Fprintf(os.Stderr, ...) in the gateway was
// silently discarded with EPIPE.
//
// Size-based rotation of gateway.log is tracked as a follow-up; the naive
// approach (re-wrapping in lumberjack) is what caused the EPIPE regression,
// so rotation needs a SIGUSR1-reopen or supervised sidecar instead.
func (d *Daemon) openLogFileForChild() (*os.File, error) {
	return os.OpenFile(d.logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
}

type pidInfo struct {
	PID        int    `json:"pid"`
	Executable string `json:"executable"`
	StartTime  int64  `json:"start_time"`
}

func (d *Daemon) IsRunning() (bool, int) {
	info, err := d.readPIDInfo()
	if err != nil {
		return false, 0
	}
	if !processExists(info.PID) {
		_ = os.Remove(d.pidFile)
		return false, 0
	}
	if !d.verifyProcess(info) {
		_ = os.Remove(d.pidFile)
		return false, 0
	}
	return true, info.PID
}

func (d *Daemon) verifyProcess(info pidInfo) bool {
	switch runtime.GOOS {
	case "linux":
		return d.verifyProcessLinux(info)
	case "darwin":
		return d.verifyProcessDarwin(info)
	default:
		return true
	}
}

func (d *Daemon) verifyProcessLinux(info pidInfo) bool {
	exePath, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", info.PID))
	if err != nil {
		return true
	}
	if info.Executable != "" && exePath != info.Executable {
		return false
	}
	return true
}

func (d *Daemon) verifyProcessDarwin(info pidInfo) bool {
	comm, err := processExecutableDarwin(info.PID)
	if err != nil {
		// Match the Linux behavior: if process metadata is unavailable in the
		// current environment, fall back to the liveness check done by IsRunning.
		return processExists(info.PID)
	}
	if info.Executable != "" {
		exeBase := filepath.Base(info.Executable)
		if !strings.HasSuffix(comm, exeBase) && comm != exeBase {
			return false
		}
	}
	return true
}

// stripTokenArgs removes any --token / -token argv pairs (both the
// `--token <value>` two-arg form and the `--token=<value>` one-arg
// form) from args. The matching is case-insensitive and applies to
// both the single- and double-dash spellings since cobra accepts
// both. This is a defence-in-depth helper used by Daemon.Start to
// guarantee the gateway token never leaks into the long-lived child
// process command line, regardless of how the caller assembled the
// argv slice. Tested in daemon_test.go::TestStripTokenArgs.
func stripTokenArgs(args []string) []string {
	if len(args) == 0 {
		return args
	}
	out := make([]string, 0, len(args))
	skipNext := false
	for _, a := range args {
		if skipNext {
			skipNext = false
			continue
		}
		lower := strings.ToLower(a)
		if lower == "--token" || lower == "-token" {
			// Eat the flag and its value (if any). If the user
			// passed a bare `--token` with no follow-up, no value
			// gets eaten and the loop just continues.
			skipNext = true
			continue
		}
		if strings.HasPrefix(lower, "--token=") || strings.HasPrefix(lower, "-token=") {
			continue
		}
		out = append(out, a)
	}
	return out
}

func processExecutableDarwin(pid int) (string, error) {
	out, err := exec.Command("ps", "-p", strconv.Itoa(pid), "-o", "comm=").Output()
	if err != nil {
		return "", err
	}
	comm := strings.TrimSpace(string(out))
	if comm == "" {
		return "", fmt.Errorf("daemon: ps returned empty command for pid %d", pid)
	}
	return comm, nil
}

func (d *Daemon) Start(args []string) (int, error) {
	if running, pid := d.IsRunning(); running {
		return pid, ErrAlreadyRunning
	}

	d.killStaleProcesses()

	if err := os.MkdirAll(d.dataDir, 0700); err != nil {
		return 0, fmt.Errorf("daemon: create data dir: %w", err)
	}

	logFile, err := d.openLogFileForChild()
	if err != nil {
		return 0, fmt.Errorf("daemon: open log file: %w", err)
	}

	executable, err := os.Executable()
	if err != nil {
		_ = logFile.Close()
		return 0, fmt.Errorf("daemon: get executable: %w", err)
	}

	// Open /dev/null for stdin
	devNull, err := os.Open(os.DevNull)
	if err != nil {
		_ = logFile.Close()
		return 0, fmt.Errorf("daemon: open /dev/null: %w", err)
	}

	// Defensive scrub: strip any --token / --token=<secret> argv pairs
	// before exec'ing the long-lived child. Even though
	// `internal/cli/daemon.go::collectDaemonArgs` no longer emits
	// these, we strip them here too so any future caller (or stale
	// systemd unit, supervisord script, etc.) cannot regress and
	// leave the gateway token visible via `ps` / /proc/<pid>/cmdline
	// for the lifetime of the daemon. See DeepSec finding "daemon
	// start propagates gateway token on the child process command
	// line".
	args = stripTokenArgs(args)

	// Strip any inherited DEFENSECLAW_DATA_DIR before re-setting so a
	// caller that already had it in their environment cannot trick the
	// child into recording a different data dir than the daemon
	// actually uses.
	parentEnv := os.Environ()
	cleanEnv := make([]string, 0, len(parentEnv)+2)
	for _, kv := range parentEnv {
		if strings.HasPrefix(kv, EnvDataDir+"=") || strings.HasPrefix(kv, EnvDaemon+"=") {
			continue
		}
		cleanEnv = append(cleanEnv, kv)
	}
	env := append(cleanEnv, EnvDaemon+"=1", EnvDataDir+"="+d.dataDir)
	cmd := exec.Command(executable, args...)
	cmd.Env = env
	cmd.Stdin = devNull
	// Pass *os.File so os/exec dup2's these directly into the child (fd 1/2).
	// No pipe, no goroutine — writes survive after we (the parent CLI) exit.
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.Dir = d.dataDir

	// Detach from parent process group (platform-specific)
	setSysProcAttr(cmd)

	if err := cmd.Start(); err != nil {
		devNull.Close()
		_ = logFile.Close()
		return 0, fmt.Errorf("daemon: start process: %w", err)
	}

	pid := cmd.Process.Pid

	if err := d.writePIDInfo(pid, executable); err != nil {
		_ = cmd.Process.Kill()
		devNull.Close()
		_ = logFile.Close()
		return 0, fmt.Errorf("daemon: write pid: %w", err)
	}

	// Close our copy of the file descriptors — the child holds its own dup'd
	// fds now, and keeping these open in the parent only delays GC once the
	// parent CLI exits.
	devNull.Close()
	_ = logFile.Close()

	// We do NOT cmd.Wait() from a parent goroutine anymore: on process exit
	// that goroutine dies too, and there's no pipe to drain. The child is
	// reparented to init, which reaps it.

	// Give the child a moment to start and verify it's running
	time.Sleep(100 * time.Millisecond)
	if !processExists(pid) {
		_ = os.Remove(d.pidFile)
		return 0, fmt.Errorf("daemon: process exited immediately (check %s for errors)", d.logFile)
	}

	return pid, nil
}

func (d *Daemon) Stop(timeout time.Duration) error {
	running, pid := d.IsRunning()
	if !running {
		return ErrNotRunning
	}

	proc, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("daemon: find process %d: %w", pid, err)
	}

	// Send termination signal for graceful shutdown
	if err := sendTermSignal(proc); err != nil {
		if errors.Is(err, os.ErrProcessDone) {
			_ = os.Remove(d.pidFile)
			return nil
		}
		return fmt.Errorf("daemon: send term signal: %w", err)
	}

	// Wait for process to exit
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if !processExists(pid) {
			_ = os.Remove(d.pidFile)
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}

	// Force kill if still running
	_ = sendKillSignal(proc)
	time.Sleep(100 * time.Millisecond)

	if processExists(pid) {
		return ErrStopTimeout
	}

	_ = os.Remove(d.pidFile)
	return nil
}

func (d *Daemon) Restart(args []string, timeout time.Duration) (int, error) {
	if running, _ := d.IsRunning(); running {
		if err := d.Stop(timeout); err != nil && !errors.Is(err, ErrNotRunning) {
			return 0, fmt.Errorf("daemon: stop for restart: %w", err)
		}
	}
	return d.Start(args)
}

func (d *Daemon) readPIDInfo() (pidInfo, error) {
	data, err := os.ReadFile(d.pidFile)
	if err != nil {
		return pidInfo{}, err
	}

	var info pidInfo
	if err := json.Unmarshal(data, &info); err != nil {
		pid, parseErr := strconv.Atoi(strings.TrimSpace(string(data)))
		if parseErr != nil || pid <= 0 {
			return pidInfo{}, fmt.Errorf("daemon: pid file is neither JSON nor a valid PID number: %w", err)
		}
		return pidInfo{PID: pid}, nil
	}
	return info, nil
}

func (d *Daemon) writePIDInfo(pid int, executable string) error {
	info := pidInfo{
		PID:        pid,
		Executable: executable,
		StartTime:  time.Now().Unix(),
	}
	data, err := json.Marshal(info)
	if err != nil {
		return err
	}
	return os.WriteFile(d.pidFile, data, 0600)
}

func IsDaemonChild() bool {
	return os.Getenv(EnvDaemon) == "1"
}
