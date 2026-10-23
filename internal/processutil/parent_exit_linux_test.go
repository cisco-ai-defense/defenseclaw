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

//go:build linux

package processutil

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

const runTreeExitHelperEnv = "DC_PROCESSUTIL_EXIT_HELPER"

// runTreeExitHelperStatus is the status the helper ends with, as a hook ends
// with os.Exit once its answer is out.
const runTreeExitHelperStatus = 3

// TestRunTreeExitHelper is the helper process of
// TestRunTreeChildDiesWhenItsParentExits: it starts a child that stalls
// through RunTree on another goroutine, waits until the child runs, and ends
// with os.Exit while RunTree still waits on it.
func TestRunTreeExitHelper(t *testing.T) {
	pidFile := os.Getenv(runTreeExitHelperEnv)
	if pidFile == "" {
		t.Skip("helper process of TestRunTreeChildDiesWhenItsParentExits")
	}
	go func() {
		_ = RunTree(exec.Command("/bin/sh", "-c", `echo $$ > "$0.tmp" && mv "$0.tmp" "$0" && exec sleep 60`, pidFile))
	}()
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if _, err := os.Stat(pidFile); err == nil {
			os.Exit(runTreeExitHelperStatus)
		}
	}
	os.Exit(1)
}

// G-small: a managed hook ends with os.Exit as soon as its answer is out,
// while tools it started (getent for its failure row, systemctl for the
// gateway watch) can still run. A child RunTree started dies with the process
// that started it, whatever goroutine started it.
func TestRunTreeChildDiesWhenItsParentExits(t *testing.T) {
	if os.Getenv(runTreeExitHelperEnv) != "" {
		t.Skip("running as the helper")
	}
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	helper := exec.Command(os.Args[0], "-test.run=^TestRunTreeExitHelper$", "-test.count=1")
	helper.Env = append(os.Environ(), runTreeExitHelperEnv+"="+pidFile)
	var output bytes.Buffer
	helper.Stdout, helper.Stderr = &output, &output
	err := helper.Run()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != runTreeExitHelperStatus {
		t.Fatalf("helper = %v, want exit %d once its child ran:\n%s", err, runTreeExitHelperStatus, output.String())
	}
	pid := readChildPID(t, pidFile)
	for deadline := time.Now().Add(5 * time.Second); sleepRunning(pid); time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("the stalled child (pid %d) outlived the process that started it", pid)
		}
	}
}

func readChildPID(t *testing.T, pidFile string) int {
	t.Helper()
	raw, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil || pid <= 1 {
		t.Fatalf("child pid %q: %v", raw, err)
	}
	t.Cleanup(func() {
		if sleepRunning(pid) {
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
	})
	return pid
}

// sleepRunning reports whether pid is still the helper's sleep and has not
// exited (a zombie waiting for its new parent's reap has).
func sleepRunning(pid int) bool {
	stat, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return false
	}
	end := bytes.LastIndexByte(stat, ')')
	start := bytes.IndexByte(stat, '(')
	if start < 0 || end < start || end+2 >= len(stat) {
		return false
	}
	return string(stat[start+1:end]) == "sleep" && stat[end+2] != 'Z' && stat[end+2] != 'X'
}
