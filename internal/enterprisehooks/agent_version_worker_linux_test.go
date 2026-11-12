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
	// The command says it runs by publishing its pid whole (write, then
	// rename), so the test never reads a half-written file.
	body := fmt.Sprintf("#!/bin/sh\nprintf '%%s\\n' \"$$\" > %s.tmp && mv %s.tmp %s\nexec sleep 60\n", strconv.Quote(pidFile), strconv.Quote(pidFile), strconv.Quote(pidFile))
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	worker := exec.Command(os.Args[0], "-test.run=^TestGAP0540VersionProbeWorker$", "-test.count=1")
	worker.Env = append(os.Environ(), gap0540VersionWorker+"="+pidFile)
	if err := worker.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan error, 1)
	go func() { exited <- worker.Wait() }()
	workerReaped := false
	t.Cleanup(func() {
		if !workerReaped {
			_ = worker.Process.Kill()
			<-exited
		}
	})
	// The pid file is the version command saying it runs: the wait is for
	// that event, not for a wall-clock time, so a host that is slow to load the
	// worker binary or to start the command does not fail the test (GAP-0889).
	// A worker that ends first fails it at once; the cap only keeps a hung
	// worker from holding the test for ever.
	var pid int
	for hung := time.Now().Add(2 * time.Minute); pid == 0; time.Sleep(10 * time.Millisecond) {
		if data, err := os.ReadFile(pidFile); err == nil {
			pid, err = strconv.Atoi(strings.TrimSpace(string(data)))
			if err != nil || pid <= 1 {
				t.Fatalf("version pid: %q (%v)", data, err)
			}
			break
		}
		select {
		case err := <-exited:
			workerReaped = true
			t.Fatalf("the apply worker ended before the version command ran: %v", err)
		default:
		}
		if time.Now().After(hung) {
			t.Fatal("version command did not start")
		}
	}
	if !versionProbeAlive(pid) {
		t.Fatal("version command did not stay running")
	}
	t.Cleanup(func() {
		if versionProbeAlive(pid) {
			_ = syscall.Kill(-pid, syscall.SIGKILL)
		}
	})
	if err := worker.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	err := <-exited
	workerReaped = true
	if err == nil {
		t.Fatal("worker unexpectedly exited normally")
	}
	// The command ends with its worker when the kernel has carried that out,
	// which is the event this waits for (GAP-0889): the kernel gives that no
	// time contract, so a host that is slow to schedule the command cannot
	// fail it. A command that is not tied to its worker keeps running for its
	// whole 60 s, so the 30 s cap tells the two apart on any host.
	for killed := time.Now(); versionProbeAlive(pid); time.Sleep(20 * time.Millisecond) {
		if time.Since(killed) > 30*time.Second {
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
