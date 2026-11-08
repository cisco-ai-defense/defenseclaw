// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package enterprisehooks

import (
	"context"
	"fmt"
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

const gap0540VersionWorker = "GAP0540_VERSION_WORKER"

func TestGAP0540VersionProbeWorker(t *testing.T) {
	pidFile := os.Getenv(gap0540VersionWorker)
	if pidFile == "" {
		t.Skip("helper process")
	}
	home := filepath.Dir(pidFile)
	if err := os.Setenv("TMPDIR", home); err != nil {
		t.Fatal(err)
	}
	_, _ = runUnixAgentVersion(context.Background(), filepath.Join(home, "hermes"), home, "HERMES_HOME")
	t.Fatal("version command returned before the worker was stopped")
}

func versionProbeAlive(pid int) bool {
	stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if os.IsNotExist(err) {
		return false
	}
	if err != nil {
		return true
	}
	end := strings.LastIndexByte(string(stat), ')')
	if end < 0 {
		return true
	}
	fields := strings.Fields(string(stat[end+1:]))
	return len(fields) == 0 || (fields[0] != "Z" && fields[0] != "X")
}

// A stopped apply worker must not leave its short-lived Hermes version
// command running after its parent lineage is gone.
func TestGAP0540VersionProbeEndsWithApplyWorker(t *testing.T) {
	home := t.TempDir()
	pidFile := filepath.Join(home, "version.pid")
	script := filepath.Join(home, "hermes")
	body := fmt.Sprintf("#!/bin/sh\nprintf '%%s\\n' \"$$\" > %s\nexec sleep 600\n", strconv.Quote(pidFile))
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	worker := exec.Command(os.Args[0], "-test.run=^TestGAP0540VersionProbeWorker$", "-test.count=1")
	worker.Env = append(os.Environ(), gap0540VersionWorker+"="+pidFile)
	if err := worker.Start(); err != nil {
		t.Fatal(err)
	}
	// The worker is waited for once; the test follows events (the pid file,
	// the worker ending, the version command ending), never a time limit that
	// a loaded host can exceed (GAP-0859).
	workerEnded := make(chan error, 1)
	go func() { workerEnded <- worker.Wait() }()
	workerReaped := false
	t.Cleanup(func() {
		if !workerReaped {
			_ = worker.Process.Kill()
			<-workerEnded
		}
	})
	var pid int
	for pid == 0 {
		select {
		case err := <-workerEnded:
			workerReaped = true
			t.Fatalf("worker ended before the version command started: %v", err)
		case <-time.After(10 * time.Millisecond):
		}
		data, err := os.ReadFile(pidFile)
		if err != nil || !strings.HasSuffix(string(data), "\n") {
			continue // not written yet
		}
		pid, err = strconv.Atoi(strings.TrimSpace(string(data)))
		if err != nil || pid <= 1 {
			t.Fatalf("version pid: %q (%v)", data, err)
		}
	}
	if !versionProbeAlive(pid) {
		t.Fatal("version command did not start")
	}
	gone, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		t.Fatalf("pidfd of the version command: %v", err)
	}
	defer unix.Close(gone)
	t.Cleanup(func() {
		if versionProbeAlive(pid) {
			_ = syscall.Kill(-pid, syscall.SIGKILL)
		}
	})
	if err := worker.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	err = <-workerEnded
	workerReaped = true
	if err == nil {
		t.Fatal("worker unexpectedly exited normally")
	}
	// The version command ends with the worker: its descriptor becomes
	// readable the moment it ends, however long a loaded host takes. It
	// would end by itself only after its 10 minute sleep, so the wait below
	// is a guard against a hang, not a speed assertion.
	pollFds := []unix.PollFd{{Fd: int32(gone), Events: unix.POLLIN}}
	for waited := 0; ; waited++ {
		n, err := unix.Poll(pollFds, 1000)
		if err == nil && n > 0 {
			break
		}
		if err != nil && err != unix.EINTR {
			t.Fatalf("waiting for the version command to end: %v", err)
		}
		if waited >= 120 {
			t.Fatal("version command outlived its apply worker")
		}
	}
}

func TestGAP0540VersionProbeStillReportsInstalledVersion(t *testing.T) {
	home := t.TempDir()
	script := filepath.Join(home, "hermes")
	if err := os.WriteFile(script, []byte("#!/bin/sh\necho 'Hermes Agent v0.21.5' >&2\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := execUnixAgentVersion(context.Background(), script, home, "HERMES_HOME"); got != "0.21.5" {
		t.Fatalf("ordinary version command = %q", got)
	}
}
