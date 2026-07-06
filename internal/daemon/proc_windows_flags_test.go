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

	"golang.org/x/sys/windows"
)

func TestManagedGatewayCreationFlagsPermitExplicitJobBreakaway(t *testing.T) {
	cmd := &exec.Cmd{}
	setSysProcAttr(cmd)

	want := uint32(windows.CREATE_NEW_PROCESS_GROUP |
		windows.DETACHED_PROCESS |
		windows.CREATE_BREAKAWAY_FROM_JOB)
	if cmd.SysProcAttr == nil {
		t.Fatal("setSysProcAttr left SysProcAttr nil")
	}
	if got := cmd.SysProcAttr.CreationFlags; got != want {
		t.Fatalf("gateway creation flags = %#x, want %#x", got, want)
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
