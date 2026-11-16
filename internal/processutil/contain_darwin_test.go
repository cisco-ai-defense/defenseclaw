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

func TestRunContainedDarwinAllowsForkFreeProof(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("a root process cannot be confined by RLIMIT_NPROC")
	}
	var output strings.Builder
	cmd := CommandContext(context.Background(), "/bin/sh", "-c", "printf 'proof\\n'")
	cmd.Stdout = &output
	if err := RunContained(cmd); err != nil || output.String() != "proof\n" {
		t.Fatalf("RunContained = %v, output %q; want a current fork-free proof", err, output.String())
	}
}

// A detached process that closes every inherited descriptor escaped the old
// lifeline. Under the forkless launcher it cannot be born at all.
func TestRunContainedDarwinCannotStartDetachedClosedFDChild(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("a root process cannot be confined by RLIMIT_NPROC")
	}
	if _, err := exec.LookPath("perl"); err != nil {
		t.Skip("perl not installed")
	}
	pidFile := filepath.Join(t.TempDir(), "escaped.pid")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	const script = `perl -MPOSIX -e 'POSIX::setsid() >= 0 or die; exec @ARGV or die' sh -c 'echo $$ > "$0"; exec sleep 60 3>&- 4>&- 5>&-' "$1" </dev/null >/dev/null 2>&1 &
end=$((SECONDS+1))
while [ ! -s "$1" ] && [ "$SECONDS" -lt "$end" ]; do :; done
exit 0`
	cmd := CommandContext(ctx, "/bin/bash", "-c", script, "sh", pidFile)
	cmd.WaitDelay = time.Second
	_ = RunContained(cmd)
	if raw, err := os.ReadFile(pidFile); err == nil {
		pid, _ := strconv.Atoi(strings.TrimSpace(string(raw)))
		if pid > 0 {
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
		t.Fatalf("forkless probe started detached child %d", pid)
	} else if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("inspect detached child PID: %v", err)
	}
}

func TestRunContainedDarwinIgnoresInheritedBashStartup(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("a root process cannot be confined by RLIMIT_NPROC")
	}
	root := t.TempDir()
	startup := filepath.Join(root, "startup.sh")
	if err := os.WriteFile(startup, []byte("printf 'proof\\n'; exit 0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var output strings.Builder
	cmd := CommandContext(context.Background(), "/bin/bash", "-c", "printf 'ordinary\\n'; exit 9")
	cmd.Env = append(os.Environ(), "BASH_ENV="+startup,
		"BASH_FUNC_printf%%=() { builtin printf 'proof\\n'; exit 0; }")
	cmd.Stdout = &output
	err := RunContained(cmd)
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 9 || output.String() != "ordinary\n" {
		t.Fatalf("RunContained = %v, output %q; want registered script exit 9", err, output.String())
	}
}

func TestRunContainedDarwinDoesNotExecuteWithoutWatchdog(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("a root process cannot be confined by RLIMIT_NPROC")
	}
	previous := armContainedDarwinWatchdog
	armContainedDarwinWatchdog = func(int) (func(), error) {
		return nil, errors.New("watchdog could not start")
	}
	t.Cleanup(func() { armContainedDarwinWatchdog = previous })
	marker := filepath.Join(t.TempDir(), "scanner-ran")
	cmd := CommandContext(context.Background(), "/bin/sh", "-c", `printf 'ran' > "$1"`, "sh", marker)
	if err := RunContained(cmd); !errors.Is(err, ErrNotContained) {
		t.Fatalf("RunContained = %v, want ErrNotContained", err)
	}
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("scanner ran before the watchdog was armed: %v", err)
	}
}

// Gateway death while the watchdog is being armed closes the launch gate.
// The scanner must not execute in that interval or survive as a paused child.
func TestRunContainedDarwinGatewayDiesBeforeWatchdogArmed(t *testing.T) {
	if os.Getenv("PROCESSUTIL_DARWIN_GATE_HELPER") == "1" {
		armContainedDarwinWatchdog = func(pid int) (func(), error) {
			_ = os.WriteFile(os.Getenv("PROCESSUTIL_DARWIN_GATE_READY"),
				[]byte(strconv.Itoa(pid)), 0o600)
			time.Sleep(time.Minute)
			return nil, errors.New("gateway helper should have died")
		}
		_ = RunContained(CommandContext(context.Background(), "/bin/sh", "-c",
			`printf 'ran' > "$1"; exec sleep 60`, "sh", os.Getenv("PROCESSUTIL_DARWIN_GATE_MARKER")))
		return
	}
	if os.Geteuid() == 0 {
		t.Skip("a root process cannot be confined by RLIMIT_NPROC")
	}
	dir := t.TempDir()
	ready := filepath.Join(dir, "ready")
	marker := filepath.Join(dir, "scanner-ran")
	gateway := exec.Command(os.Args[0], "-test.run=^TestRunContainedDarwinGatewayDiesBeforeWatchdogArmed$")
	gateway.Env = append(os.Environ(), "PROCESSUTIL_DARWIN_GATE_HELPER=1",
		"PROCESSUTIL_DARWIN_GATE_READY="+ready, "PROCESSUTIL_DARWIN_GATE_MARKER="+marker)
	if err := gateway.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = gateway.Process.Kill(); _ = gateway.Wait() })
	deadline := time.Now().Add(5 * time.Second)
	pid := 0
	for time.Now().Before(deadline) {
		raw, err := os.ReadFile(ready)
		if err == nil {
			pid, _ = strconv.Atoi(string(raw))
			if pid > 0 {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	if pid == 0 {
		t.Fatal("launcher did not reach the watchdog arm point")
	}
	t.Cleanup(func() { _ = syscall.Kill(pid, syscall.SIGKILL) })
	if err := gateway.Process.Signal(syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	_ = gateway.Wait()
	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		info, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
		if err != nil || info.Proc.P_stat == darwinZombie {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if info, err := unix.SysctlKinfoProc("kern.proc.pid", pid); err == nil && info.Proc.P_stat != darwinZombie {
		t.Fatalf("launcher %d survived gateway death before the watchdog armed", pid)
	}
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("scanner ran before the watchdog armed: %v", err)
	}
}
