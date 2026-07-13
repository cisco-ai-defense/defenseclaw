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

//go:build windows

package daemon

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestManagedGatewayCreationFlagsHonorJobBreakawayPolicy(t *testing.T) {
	base := uint32(windows.CREATE_NEW_PROCESS_GROUP | windows.DETACHED_PROCESS)
	tests := []struct {
		name       string
		queryErr   error
		limitFlags uint32
		want       uint32
	}{
		{name: "outside job", queryErr: windows.ERROR_INVALID_HANDLE, want: base | windows.CREATE_BREAKAWAY_FROM_JOB},
		{name: "restricted job", want: base},
		{name: "explicit breakaway", limitFlags: windows.JOB_OBJECT_LIMIT_BREAKAWAY_OK, want: base | windows.CREATE_BREAKAWAY_FROM_JOB},
		{name: "silent breakaway", limitFlags: windows.JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK, want: base},
		{name: "unknown query failure", queryErr: windows.ERROR_ACCESS_DENIED, want: base},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := daemonCreationFlagsForJob(tc.queryErr, tc.limitFlags); got != tc.want {
				t.Fatalf("gateway creation flags = %#x, want %#x", got, tc.want)
			}
		})
	}

	cmd := &exec.Cmd{}
	setSysProcAttr(cmd)
	if cmd.SysProcAttr == nil {
		t.Fatal("setSysProcAttr left SysProcAttr nil")
	}
	if got := cmd.SysProcAttr.CreationFlags; got&base != base {
		t.Fatalf("gateway creation flags = %#x, missing required detachment %#x", got, base)
	}
}

func TestWindowsDaemonChildSelfRegistersStrongIdentity(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv(EnvDaemon, "1")
	t.Setenv(EnvDataDir, dataDir)

	if err := RegisterCurrentProcess(); err != nil {
		t.Fatal(err)
	}
	d := New(dataDir)
	info, err := d.readPIDInfo()
	if err != nil {
		t.Fatal(err)
	}
	wantExecutable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if info.PID != os.Getpid() {
		t.Fatalf("registered PID = %d, want %d", info.PID, os.Getpid())
	}
	if !filepath.IsAbs(info.Executable) || !filepath.IsAbs(wantExecutable) {
		t.Fatalf("registered executable paths must be absolute: got %q want %q", info.Executable, wantExecutable)
	}
	if info.Executable != wantExecutable {
		t.Fatalf("registered executable = %q, want %q", info.Executable, wantExecutable)
	}
	if info.StartIdentity == "" || !d.HasManagedProcessIdentity(info.PID) {
		t.Fatalf("registered process identity is not strong: %+v", info)
	}
}

func TestWaitForProcessExitUsesOriginalWindowsHandle(t *testing.T) {
	const helperEnv = "DEFENSECLAW_TEST_WAIT_PROCESS_EXIT"
	if os.Getenv(helperEnv) == "1" {
		time.Sleep(150 * time.Millisecond)
		os.Exit(0)
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestWaitForProcessExitUsesOriginalWindowsHandle")
	cmd.Env = append(os.Environ(), helperEnv+"=1")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})

	started := time.Now()
	if !waitForProcessExit(cmd.Process, cmd.Process.Pid, 5*time.Second) {
		t.Fatal("process handle did not become signaled")
	}
	if elapsed := time.Since(started); elapsed < 100*time.Millisecond {
		t.Fatalf("wait returned before helper exited: %s", elapsed)
	}
}
