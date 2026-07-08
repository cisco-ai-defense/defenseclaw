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
	// Required for the S3.HIGH_BUG fix
	// "killStaleProcesses can terminate unrelated processes": without
	// a per-data-dir marker, two legitimate DefenseClaw daemons
	// running from different profiles cannot tell each other apart by
	// executable name alone.
	EnvDataDir = "DEFENSECLAW_DATA_DIR"
)

var gatewayTokenEnvNames = []string{
	"DEFENSECLAW_GATEWAY_TOKEN",
	"OPENCLAW_GATEWAY_TOKEN",
}

var (
	ErrAlreadyRunning = errors.New("daemon is already running")
	ErrNotRunning     = errors.New("daemon is not running")
	ErrStopTimeout    = errors.New("daemon did not stop within timeout")
)

type Daemon struct {
	dataDir string
	pidFile string
	logFile string
	started pidInfo
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
	// StartTime is the wall-clock time the parent recorded when the
	// child was spawned. Kept for human/log diagnostics only — DO NOT
	// use this for PID-reuse detection, since it has no relationship
	// to the kernel's view of the process. Use StartIdentity instead.
	StartTime int64 `json:"start_time"`
	// StartIdentity is an opaque per-process token captured immediately
	// after spawn (Linux: /proc/<pid>/stat field 22 starttime; Darwin:
	// `ps -o lstart=`). Compared against the live process's identity in
	// verifyProcess() to detect PID reuse — i.e. "this PID exists and
	// the executable matches, but the kernel says the process started
	// at a different time, so it's a DIFFERENT process that happens to
	// have inherited our PID". Empty when the platform doesn't support
	// the lookup (e.g. FreeBSD), in which case the check is skipped.
	// Closes the second half of chain .
	StartIdentity string `json:"start_identity,omitempty"`
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
		// Closes (chain ): a stale gateway.pid
		// pointing at a reused PID must NOT keep status/stop/restart
		// pinned to the unrelated process. Treat the file as garbage
		// and remove it so the next operation gets a clean slate.
		_ = os.Remove(d.pidFile)
		return false, 0
	}
	return true, info.PID
}

// HasManagedProcessIdentity requires the complete PID record written by current
// daemon versions and revalidates both executable and kernel start identity.
// Legacy bare-PID records remain usable for stop/status compatibility but are
// not strong enough to prove that an occupied API port is the expected daemon.
func (d *Daemon) HasManagedProcessIdentity(pid int) bool {
	info, err := d.readPIDInfo()
	if err != nil || info.PID != pid || info.Executable == "" || info.StartIdentity == "" {
		return false
	}
	return d.verifyProcess(info)
}

// verifyProcess returns true when the live process at info.PID is the SAME
// process recorded in the PID file (executable AND start identity match),
// false when either signal indicates PID reuse, and true when neither signal
// is available on this platform (best-effort backwards compatibility).
//
// Both the executable check and the start-identity check have been hardened
// to fail-CLOSED when their respective metadata is genuinely unavailable for
// a process we *can* signal: the previous implementation fell back to "true"
// on `os.Readlink` errors (Linux) and on `ps` errors (Darwin), which let any
// unreaped zombie pass verification.
func (d *Daemon) verifyProcess(info pidInfo) bool {
	if !d.verifyExecutable(info) {
		return false
	}
	if !d.verifyStartIdentity(info) {
		return false
	}
	return true
}

func (d *Daemon) verifyExecutable(info pidInfo) bool {
	switch runtime.GOOS {
	case "linux":
		exePath, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", info.PID))
		if err != nil {
			// /proc/<pid>/exe should be readable for any LIVE process the
			// caller can signal (we already passed processExists). Failing
			// here means the process is a zombie or has a permission
			// barrier (kernel namespacing); treat as unverified rather
			// than the old fail-OPEN behavior.
			return false
		}
		if info.Executable != "" && exePath != info.Executable {
			return false
		}
		return true
	case "darwin":
		comm, err := processExecutableDarwin(info.PID)
		if err != nil {
			// Same fail-closed posture as Linux: ps must succeed for any
			// process we can signal; if it fails, do NOT trust the PID.
			return false
		}
		if info.Executable != "" {
			exeBase := filepath.Base(info.Executable)
			if !strings.HasSuffix(comm, exeBase) && comm != exeBase {
				return false
			}
		}
		return true
	case "windows":
		exePath, err := processExecutableWindows(info.PID)
		if err != nil {
			return false
		}
		if info.Executable != "" && !strings.EqualFold(filepath.Clean(exePath), filepath.Clean(info.Executable)) {
			return false
		}
		return true
	default:
		return true
	}
}

func (d *Daemon) verifyStartIdentity(info pidInfo) bool {
	// Empty StartIdentity means the PID file was written by an older
	// daemon binary that didn't capture the identity. Skip the check
	// for backwards compatibility — the executable check above is the
	// only signal in that case. New PID files always include identity.
	if info.StartIdentity == "" {
		return true
	}
	live, err := processStartIdentity(info.PID)
	if err != nil {
		// Same fail-closed posture as the executable check: identity
		// must be readable for a live process; if not, do not trust
		// the PID file.
		return false
	}
	if live == "" {
		// Platform doesn't support start-identity (e.g. FreeBSD on a
		// PID file written by Linux). Fall back to the executable check.
		return true
	}
	return live == info.StartIdentity
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
	// for the lifetime of the daemon. See finding "daemon
	// start propagates gateway token on the child process command
	// line".
	args = stripTokenArgs(args)

	env := d.childEnv(os.Environ())
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

	// Spawn an exit-watcher BEFORE writing the PID file so we can
	// detect immediate-exit children and avoid leaving a stale
	// gateway.pid behind. Closes the first half of chain
	// processExists() alone returned true for
	// unreaped zombies, so the previous startup verification
	// recorded a stale PID file for a process that had already died.
	exitCh := make(chan error, 1)
	go func() {
		exitCh <- cmd.Wait()
	}()

	// Capture the kernel's view of the process start identity right
	// after spawn so verifyProcess() can detect PID reuse later.
	// Closes the second half of chain . Errors are
	// not fatal — falling back to executable-only matching mirrors
	// the legacy behavior on platforms without /proc.
	startIdentity, _ := processStartIdentity(pid)

	if err := d.writePIDInfo(pid, executable, startIdentity); err != nil {
		_ = cmd.Process.Kill()
		<-exitCh // reap the child so it doesn't become a zombie
		devNull.Close()
		_ = logFile.Close()
		return 0, fmt.Errorf("daemon: write pid: %w", err)
	}
	d.started = pidInfo{PID: pid, Executable: executable, StartIdentity: startIdentity}

	// Close our copy of the file descriptors — the child holds its own dup'd
	// fds now, and keeping these open in the parent only delays GC once the
	// parent CLI exits.
	devNull.Close()
	_ = logFile.Close()

	// Give the child a 100 ms grace window for its first syscall, then
	// either confirm it's still alive or detect that it crashed. A
	// crashed-during-startup child shows up here as cmd.Wait() returning
	// with the exit status. The previous implementation slept blindly
	// and called processExists(), which returned true for zombies — so
	// fast-fail config errors (bind-in-use, missing config) silently
	// left a stale PID file ().
	select {
	case waitErr := <-exitCh:
		_ = os.Remove(d.pidFile)
		if waitErr != nil {
			return 0, fmt.Errorf("daemon: process exited immediately (check %s for errors): %w", d.logFile, waitErr)
		}
		return 0, fmt.Errorf("daemon: process exited immediately with status 0 (check %s for errors)", d.logFile)
	case <-time.After(100 * time.Millisecond):
		// Child is still alive after the grace window. The exitCh
		// goroutine will continue to run until the child eventually
		// exits and reaps it (no FD leak because we already closed
		// our copies of stdin/stdout/stderr).
	}

	return pid, nil
}

func (d *Daemon) childEnv(parentEnv []string) []string {
	dotenv := readGatewayTokenDotenv(filepath.Join(d.dataDir, ".env"))
	hasDotenvToken := len(dotenv) > 0
	tokenKeys := make(map[string]struct{}, len(gatewayTokenEnvNames))
	for _, key := range gatewayTokenEnvNames {
		tokenKeys[key] = struct{}{}
	}

	cleanEnv := make([]string, 0, len(parentEnv)+2+len(dotenv))
	for _, kv := range parentEnv {
		key, _, ok := strings.Cut(kv, "=")
		if !ok {
			cleanEnv = append(cleanEnv, kv)
			continue
		}
		if key == EnvDataDir || key == EnvDaemon {
			continue
		}
		if _, isToken := tokenKeys[key]; isToken {
			if hasDotenvToken {
				continue
			}
		}
		cleanEnv = append(cleanEnv, kv)
	}
	cleanEnv = append(cleanEnv, EnvDaemon+"=1", EnvDataDir+"="+d.dataDir)
	for _, key := range gatewayTokenEnvNames {
		if value := dotenv[key]; value != "" {
			cleanEnv = append(cleanEnv, key+"="+value)
		}
	}
	return cleanEnv
}

func readGatewayTokenDotenv(path string) map[string]string {
	values := map[string]string{}
	data, err := os.ReadFile(path)
	if err != nil {
		return values
	}
	wanted := make(map[string]struct{}, len(gatewayTokenEnvNames))
	for _, key := range gatewayTokenEnvNames {
		wanted[key] = struct{}{}
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		if _, ok := wanted[key]; !ok {
			continue
		}
		value = strings.TrimSpace(value)
		if len(value) >= 2 && ((value[0] == '"' && value[len(value)-1] == '"') || (value[0] == '\'' && value[len(value)-1] == '\'')) {
			value = value[1 : len(value)-1]
		}
		if value != "" {
			values[key] = value
		}
	}
	return values
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

// StopStarted terminates only the child launched by this Daemon value. It is
// used for failed startup rollback so a replaced PID file can never redirect
// cleanup toward a foreign process.
func (d *Daemon) StopStarted(pid int, timeout time.Duration) error {
	info := d.started
	if info.PID != pid || !d.verifyProcess(info) {
		return ErrNotRunning
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("daemon: find started process %d: %w", pid, err)
	}
	if err := sendTermSignal(proc); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return fmt.Errorf("daemon: stop started process: %w", err)
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if !d.verifyProcess(info) {
			d.removePIDFileIfStarted(info)
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !d.verifyProcess(info) {
		d.removePIDFileIfStarted(info)
		return nil
	}
	_ = sendKillSignal(proc)
	time.Sleep(100 * time.Millisecond)
	if d.verifyProcess(info) {
		return ErrStopTimeout
	}
	d.removePIDFileIfStarted(info)
	return nil
}

func (d *Daemon) removePIDFileIfStarted(started pidInfo) {
	current, err := d.readPIDInfo()
	if err != nil || current.PID != started.PID {
		return
	}
	if started.StartIdentity != "" && current.StartIdentity != started.StartIdentity {
		return
	}
	_ = os.Remove(d.pidFile)
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

func (d *Daemon) writePIDInfo(pid int, executable string, startIdentity string) error {
	info := pidInfo{
		PID:           pid,
		Executable:    executable,
		StartTime:     time.Now().Unix(),
		StartIdentity: startIdentity,
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
