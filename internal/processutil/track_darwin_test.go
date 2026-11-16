// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package processutil

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// trackDetach starts its arguments in a new session with every stream and
// inherited descriptor closed.
const trackDetach = `perl -MPOSIX -e 'POSIX::setsid() >= 0 or die; POSIX::close($_) for 3..64; open(STDIN, "<", "/dev/null"); open(STDOUT, ">", "/dev/null"); open(STDERR, ">", "/dev/null"); exec @ARGV or die'`

func requirePerl(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("perl"); err != nil {
		t.Skip("perl is not installed")
	}
}

func trackQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}

func trackedPID(t *testing.T, path string) int {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		raw, err := os.ReadFile(path)
		if err == nil {
			pid, convErr := strconv.Atoi(strings.TrimSpace(string(raw)))
			if convErr == nil && pid > 0 {
				t.Cleanup(func() { _ = syscall.Kill(pid, syscall.SIGKILL) })
				return pid
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("no PID in %s", path)
	return 0
}

func trackedRunning(pid int) bool {
	info, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	return err == nil && info.Proc.P_pid == int32(pid) && info.Proc.P_stat != darwinZombie
}

func trackedGone(pid int) bool {
	deadline := time.Now().Add(3 * time.Second)
	for trackedRunning(pid) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	return !trackedRunning(pid)
}

// The skill-scanner starts helpers on every scan; the no-fork launcher
// failed them all.
func TestRunTrackedDarwinAllowsSubprocesses(t *testing.T) {
	var output strings.Builder
	cmd := CommandContext(context.Background(), "/bin/sh", "-c", `x=$(/bin/echo proof); /bin/sleep 0 & wait; printf '%s\n' "$x"`)
	cmd.Stdout = &output
	if err := RunTracked(cmd); err != nil || output.String() != "proof\n" {
		t.Fatalf("RunTracked = %v, output %q; want the subprocess output", err, output.String())
	}
}

func TestRunTrackedDarwinKeepsExitCode(t *testing.T) {
	err := RunTracked(CommandContext(context.Background(), "/bin/sh", "-c", "exit 7"))
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 7 {
		t.Fatalf("RunTracked = %v, want exit status 7", err)
	}
}

// A child in a session of its own with every descriptor closed escaped the
// process-group kill and the lifeline (GAP-0456).
func TestRunTrackedDarwinEndsDetachedChild(t *testing.T) {
	requirePerl(t)
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	script := trackDetach + ` /bin/sh -c 'echo $$ > "$0"; exec sleep 60' ` + trackQuote(pidFile) + ` &
while [ ! -s ` + trackQuote(pidFile) + ` ]; do sleep 0.01; done`
	err := RunTracked(CommandContext(context.Background(), "/bin/sh", "-c", script))
	pid := trackedPID(t, pidFile)
	if !trackedGone(pid) {
		t.Fatalf("RunTracked = %v; detached child %d is still running", err, pid)
	}
	if err != nil {
		t.Fatalf("RunTracked = %v, want a contained run", err)
	}
}

// The daemon pattern: fork, the parent exits, the child starts a session,
// forks again and exits, and the grandchild closes every descriptor.
func TestRunTrackedDarwinEndsDoubleForkedDaemon(t *testing.T) {
	requirePerl(t)
	pidFile := filepath.Join(t.TempDir(), "daemon.pid")
	script := `perl -MPOSIX -e 'exit 0 if fork; sleep 1; POSIX::setsid(); exit 0 if fork; sleep 1; POSIX::close($_) for 0..64; open(my $f, ">", $ARGV[0]) or die; print $f "$$\n"; close $f; exec "sleep", "60"' ` + trackQuote(pidFile) + `
while [ ! -s ` + trackQuote(pidFile) + ` ]; do sleep 0.01; done`
	err := RunTracked(CommandContext(context.Background(), "/bin/sh", "-c", script))
	pid := trackedPID(t, pidFile)
	if !trackedGone(pid) {
		t.Fatalf("RunTracked = %v; daemon %d is still running", err, pid)
	}
	if err != nil {
		t.Fatalf("RunTracked = %v, want a contained run", err)
	}
}

// A tree that keeps starting detached children while it is being killed:
// killing a parent before its newest child is seen would orphan that child.
func TestRunTrackedDarwinEndsTreeThatForksDuringKill(t *testing.T) {
	requirePerl(t)
	pidFile := filepath.Join(t.TempDir(), "children.pid")
	script := `(while :; do ` + trackDetach + ` /bin/sh -c 'echo $$ >> "$0"; exec sleep 60' ` + trackQuote(pidFile) + ` & done) &
sleep 0.5`
	err := RunTracked(CommandContext(context.Background(), "/bin/sh", "-c", script))
	raw, readErr := os.ReadFile(pidFile)
	if readErr != nil {
		t.Fatalf("no detached children were started: %v", readErr)
	}
	pids := strings.Fields(string(raw))
	for _, field := range pids {
		pid, _ := strconv.Atoi(field)
		t.Cleanup(func() { _ = syscall.Kill(pid, syscall.SIGKILL) })
	}
	for _, field := range pids {
		pid, _ := strconv.Atoi(field)
		if pid > 0 && !trackedGone(pid) {
			t.Fatalf("RunTracked = %v; detached child %d of %d is still running", err, pid, len(pids))
		}
	}
	if err != nil && !errors.Is(err, ErrNotContained) {
		t.Fatalf("RunTracked = %v", err)
	}
}

// A process the command did not start is not touched, even one that starts
// while the command runs.
func TestRunTrackedDarwinLeavesUnrelatedProcesses(t *testing.T) {
	ready := filepath.Join(t.TempDir(), "ready")
	cmd := CommandContext(context.Background(), "/bin/sh", "-c", `: > "$0"; sleep 1; sleep 0 & wait`, ready)
	done := make(chan error, 1)
	go func() { done <- RunTracked(cmd) }()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if _, err := os.Stat(ready); err == nil {
			break
		}
	}
	other := exec.Command("sleep", "30")
	if err := other.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = other.Process.Kill(); _ = other.Wait() })
	if err := <-done; err != nil {
		t.Fatalf("RunTracked = %v", err)
	}
	if !trackedRunning(other.Process.Pid) {
		t.Fatalf("RunTracked killed unrelated process %d", other.Process.Pid)
	}
}

func TestRunTrackedDarwinCancelEndsTree(t *testing.T) {
	requirePerl(t)
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd := CommandContext(ctx, "/bin/sh", "-c", trackDetach+` /bin/sh -c 'echo $$ > "$0"; exec sleep 60' `+trackQuote(pidFile)+` & sleep 60`)
	cmd.WaitDelay = 5 * time.Second
	done := make(chan error, 1)
	go func() { done <- RunTracked(cmd) }()
	pid := trackedPID(t, pidFile)
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("RunTracked = nil after cancellation")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("RunTracked did not return after cancellation")
	}
	if !trackedGone(pid) {
		t.Fatalf("detached child %d survived cancellation", pid)
	}
}

// The gateway dies by SIGKILL and runs no cleanup; the supervisor sees it
// through kqueue and ends the tree (GAP-0492).
func TestRunTrackedDarwinGatewayDeathEndsTree(t *testing.T) {
	if os.Getenv("PROCESSUTIL_TRACK_GATEWAY") == "1" {
		_ = RunTracked(exec.Command("/bin/sh", "-c", trackDetach+` /bin/sh -c 'echo $$ > "$0"; exec sleep 60' "$1" & sleep 60`,
			"sh", os.Getenv("PROCESSUTIL_TRACK_PIDFILE")))
		return
	}
	requirePerl(t)
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	gateway := exec.Command(os.Args[0], "-test.run=^TestRunTrackedDarwinGatewayDeathEndsTree$")
	gateway.Env = append(os.Environ(), "PROCESSUTIL_TRACK_GATEWAY=1", "PROCESSUTIL_TRACK_PIDFILE="+pidFile)
	if err := gateway.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = gateway.Process.Kill(); _ = gateway.Wait() })
	pid := trackedPID(t, pidFile)
	if err := gateway.Process.Signal(syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	_ = gateway.Wait()
	if !trackedGone(pid) {
		t.Fatalf("detached child %d survived gateway death", pid)
	}
}

// When the supervisor itself is killed, the gateway ends the processes it
// reported and the run fails. The tree holds the command's output pipe, so
// a gateway that waited for the streams first would hang here.
func TestRunTrackedDarwinSupervisorDeathFailsClosed(t *testing.T) {
	requirePerl(t)
	dir := t.TempDir()
	pidFile, supervisorFile := filepath.Join(dir, "child.pid"), filepath.Join(dir, "supervisor.pid")
	var output strings.Builder
	cmd := exec.Command("/bin/sh", "-c", `echo $PPID > "$1"; `+trackDetach+` /bin/sh -c 'echo $$ > "$0"; exec sleep 60' "$2" & sleep 60`,
		"sh", supervisorFile, pidFile)
	cmd.Stdout = &output
	done := make(chan error, 1)
	go func() { done <- RunTracked(cmd) }()
	pid := trackedPID(t, pidFile)
	if err := syscall.Kill(trackedPID(t, supervisorFile), syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, ErrNotContained) {
			t.Fatalf("RunTracked = %v, want ErrNotContained", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("RunTracked did not return after its supervisor died")
	}
	if !trackedGone(pid) {
		t.Fatalf("detached child %d survived its supervisor", pid)
	}
}

// A command may exit with the supervisor's own status codes; only the
// supervisor's report decides containment.
func TestRunTrackedDarwinCommandExit125IsNotAContainmentFailure(t *testing.T) {
	err := RunTracked(CommandContext(context.Background(), "/bin/sh", "-c", "exit 125"))
	var exitErr *exec.ExitError
	if errors.Is(err, ErrNotContained) || !errors.As(err, &exitErr) || exitErr.ExitCode() != 125 {
		t.Fatalf("RunTracked = %v, want the command's exit status 125", err)
	}
}

func TestRunTrackedDarwinReportsMissingCommand(t *testing.T) {
	var stderr strings.Builder
	cmd := exec.Command(filepath.Join(t.TempDir(), "missing-scanner"))
	cmd.Stderr = &stderr
	err := RunTracked(cmd)
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != containExitNotStarted || !strings.Contains(stderr.String(), "missing-scanner") {
		t.Fatalf("RunTracked = %v, stderr %q; want exit 127 naming the command", err, stderr.String())
	}
}
