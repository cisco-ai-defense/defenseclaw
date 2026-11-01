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

package enterprisehooks

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// GAP-1985: whether a setup relax is in progress comes from the record the
// relaxing process writes, not from the folder's change time. A relax made
// just now, and a folder written into after the guardian started, are not a
// live setup without that record; a record whose process ended, an old one,
// or one for another account is no proof either.
func TestWindowsSetupRelaxIsLiveOnlyWithItsRecord(t *testing.T) {
	fixture := newWindowsManagedRuntimeGenerationMissingHooksGCFixture(t)
	runtimeRoot := filepath.Join(t.TempDir(), "per-user-runtime")
	original := windowsPerUserManagedRuntimeDirResolver
	windowsPerUserManagedRuntimeDirResolver = func(name string) (string, error) {
		return filepath.Join(runtimeRoot, name), nil
	}
	t.Cleanup(func() { windowsPerUserManagedRuntimeDirResolver = original })
	if err := ensureWindowsManagedPolicyDirectory(runtimeRoot); err != nil {
		t.Fatal(err)
	}
	for _, name := range WindowsStandalonePerUserConnectorNames() {
		if err := ensureWindowsManagedPolicyDirectory(filepath.Join(runtimeRoot, name)); err != nil {
			t.Fatal(err)
		}
	}
	hooks := filepath.Join(fixture.options.DataDir, "hooks")
	createWindowsManagedRuntimeTestHooksWithDACL(t, hooks, fixture.target, windowsSetupRelaxedDirectorySDDL)
	if !windowsManagedRuntimeDirSetupRelaxed(hooks, fixture.target) {
		t.Fatal("fixture hooks folder is not in the setup relax shape")
	}
	if windowsSetupRelaxByLiveGuardian(hooks, fixture.target) || !windowsSetupRelaxIsStale(hooks, fixture.target) {
		t.Fatal("a relax made just now with no record counted as a live setup")
	}
	if err := settledWindowsManagedRuntimeGenerationRoots(fixture.options.DataDir, fixture.target); err == nil {
		t.Fatal("hooks resolved over a relax no running setup holds")
	}

	writeWindowsSetupRelaxMarker("hermes", fixture.target)
	if !windowsSetupRelaxByLiveGuardian(hooks, fixture.target) || windowsSetupRelaxIsStale(hooks, fixture.target) {
		t.Fatal("the relaxing process's own record is not a live setup")
	}
	other, err := windows.CreateWellKnownSid(windows.WinLocalServiceSid)
	if err != nil {
		t.Fatal(err)
	}
	if windowsSetupRelaxInProgress(other) {
		t.Fatal("one account's record counted for another account")
	}

	path, err := windowsSetupRelaxMarkerPath("hermes", fixture.target)
	if err != nil {
		t.Fatal(err)
	}
	rewrite := func(t *testing.T, marker windowsSetupRelaxMarker) {
		t.Helper()
		data, err := json.Marshal(marker)
		if err != nil {
			t.Fatal(err)
		}
		if err := writeWindowsManagedFile(path, append(data, '\n'), true); err != nil {
			t.Fatal(err)
		}
		if err := setWindowsManagedPolicyProtection(path, false, true); err != nil {
			t.Fatal(err)
		}
	}
	self, ok := windowsProcessStart(windows.CurrentProcess())
	if !ok {
		t.Fatal("read own process start")
	}
	rewrite(t, windowsSetupRelaxMarker{SchemaVersion: windowsSetupRelaxMarkerSchema, SID: fixture.target.String(),
		ProcessID: windows.GetCurrentProcessId(), ProcessStart: self, Since: time.Now().Add(-windowsGuardianSetupRelaxBound).UnixNano()})
	if windowsSetupRelaxInProgress(fixture.target) {
		t.Fatal("a record older than one setup counted as live")
	}
	ended := exec.Command("cmd.exe", "/c", "exit", "0")
	if err := ended.Start(); err != nil {
		t.Fatal(err)
	}
	pid := uint32(ended.Process.Pid)
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		t.Fatal(err)
	}
	endedStart, _ := windowsProcessStart(handle)
	_ = ended.Wait()
	rewrite(t, windowsSetupRelaxMarker{SchemaVersion: windowsSetupRelaxMarkerSchema, SID: fixture.target.String(),
		ProcessID: pid, ProcessStart: endedStart, Since: time.Now().UnixNano()})
	live := windowsSetupRelaxInProgress(fixture.target)
	_ = windows.CloseHandle(handle)
	if live {
		t.Fatal("a record whose process ended counted as live")
	}

	writeWindowsSetupRelaxMarker("hermes", fixture.target)
	clearWindowsSetupRelaxMarkerAsService("hermes", fixture.target)
	if _, err := os.Lstat(path); !os.IsNotExist(err) || windowsSetupRelaxInProgress(fixture.target) {
		t.Fatalf("the record survived its clear: %v", err)
	}
}
