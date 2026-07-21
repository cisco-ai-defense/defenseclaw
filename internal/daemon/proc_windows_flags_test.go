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
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
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

func TestWindowsDaemonStartWaitsForChildOwnedPIDRegistration(t *testing.T) {
	if IsDaemonChild() {
		// Make the ownership contract observable: a parent-side writer would
		// return before this delay, while the real parent must wait for this
		// child's authoritative strong PID record.
		time.Sleep(200 * time.Millisecond)
		if err := RegisterCurrentProcess(); err != nil {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Second)
		return
	}

	t.Setenv(EnvDaemon, "")
	dataDir := t.TempDir()
	d := New(dataDir)
	startedAt := time.Now()
	pid, err := d.Start([]string{"-test.run=^TestWindowsDaemonStartWaitsForChildOwnedPIDRegistration$"})
	if err != nil {
		t.Fatal(err)
	}
	stopped := false
	t.Cleanup(func() {
		if !stopped {
			_ = d.StopStarted(pid, 5*time.Second)
		}
	})
	if elapsed := time.Since(startedAt); elapsed < 200*time.Millisecond {
		t.Fatalf("Start returned before the child registered its PID: %s", elapsed)
	}
	info, err := d.readPIDInfo()
	if err != nil {
		t.Fatal(err)
	}
	if info.PID != pid || info.StartIdentity == "" || !d.verifyProcess(info) {
		t.Fatalf("child-owned PID registration is not strong: %+v", info)
	}
	leftovers, err := filepath.Glob(filepath.Join(dataDir, "gateway.pid~RF*.TMP"))
	if err != nil {
		t.Fatal(err)
	}
	if len(leftovers) != 0 {
		t.Fatalf("ReplaceFileW collision artifacts remain: %v", leftovers)
	}
	if err := d.StopStarted(pid, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	stopped = true
}

func TestWindowsConditionalPIDRemovalSerializesReplacement(t *testing.T) {
	dataDir := t.TempDir()
	d := New(dataDir)
	if err := d.writePIDInfo(101, "old-gateway.exe", "old-start"); err != nil {
		t.Fatal(err)
	}
	started, err := d.readPIDInfo()
	if err != nil {
		t.Fatal(err)
	}

	replacement := pidInfo{
		PID:           202,
		Executable:    "new-gateway.exe",
		StartTime:     time.Now().Unix(),
		StartIdentity: "new-start",
	}
	replacementData, err := json.Marshal(replacement)
	if err != nil {
		t.Fatal(err)
	}
	replacementPath := filepath.Join(dataDir, "gateway-replacement.pid")
	if err := os.WriteFile(replacementPath, replacementData, 0o600); err != nil {
		t.Fatal(err)
	}

	var replacementDuringCompareErr error
	var inPlaceWriteDuringCompareErr error
	err = removePIDFileIf(d.pidFile, func(data []byte) bool {
		current, parseErr := parsePIDInfo(data)
		if parseErr != nil || !pidInfoMatchesStarted(current, started) {
			return false
		}
		// This is the old compare/unlink race window. The opened PID-file
		// handle must deny pathname replacement until its exact object has
		// been marked for deletion.
		replacementDuringCompareErr = replaceManagedPIDFileOnce(replacementPath, d.pidFile)
		inPlaceWriteDuringCompareErr = openManagedPIDFileForWrite(d.pidFile)
		return true
	})
	if err != nil {
		t.Fatal(err)
	}
	if replacementDuringCompareErr == nil {
		t.Fatal("PID replacement unexpectedly bypassed the no-share-delete handle")
	}
	if !errors.Is(replacementDuringCompareErr, windows.ERROR_SHARING_VIOLATION) &&
		!errors.Is(replacementDuringCompareErr, windows.ERROR_ACCESS_DENIED) &&
		!errors.Is(replacementDuringCompareErr, windows.ERROR_LOCK_VIOLATION) {
		t.Fatalf("replacement failed for an unexpected reason: %v", replacementDuringCompareErr)
	}
	if inPlaceWriteDuringCompareErr == nil {
		t.Fatal("in-place PID write unexpectedly bypassed the read-only sharing contract")
	}
	if !errors.Is(inPlaceWriteDuringCompareErr, windows.ERROR_SHARING_VIOLATION) &&
		!errors.Is(inPlaceWriteDuringCompareErr, windows.ERROR_ACCESS_DENIED) &&
		!errors.Is(inPlaceWriteDuringCompareErr, windows.ERROR_LOCK_VIOLATION) {
		t.Fatalf("in-place write failed for an unexpected reason: %v", inPlaceWriteDuringCompareErr)
	}
	// The real safefile writer retries sharing violations. Once the old
	// handle closes, its retry publishes the replacement, which must remain.
	if err := replaceManagedPIDFileWithRetry(replacementPath, d.pidFile); err != nil {
		t.Fatalf("publish replacement after conditional deletion: %v", err)
	}
	got, err := d.readPIDInfo()
	if err != nil {
		t.Fatal(err)
	}
	if got.PID != replacement.PID || got.StartIdentity != replacement.StartIdentity {
		t.Fatalf("PID record = %+v, want replacement %+v", got, replacement)
	}
}

func replaceManagedPIDFileOnce(source, destination string) error {
	from, err := winpath.UTF16Ptr(source)
	if err != nil {
		return err
	}
	to, err := winpath.UTF16Ptr(destination)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(
		from,
		to,
		windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH,
	)
}

func replaceManagedPIDFileWithRetry(source, destination string) error {
	var err error
	for attempt := 0; attempt < 100; attempt++ {
		err = replaceManagedPIDFileOnce(source, destination)
		if err == nil {
			return nil
		}
		if !errors.Is(err, windows.ERROR_SHARING_VIOLATION) &&
			!errors.Is(err, windows.ERROR_ACCESS_DENIED) &&
			!errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
			return err
		}
		time.Sleep(5 * time.Millisecond)
	}
	return err
}

func openManagedPIDFileForWrite(path string) error {
	pathPtr, err := winpath.UTF16Ptr(path)
	if err != nil {
		return err
	}
	handle, err := windows.CreateFile(
		pathPtr,
		windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		return err
	}
	return windows.CloseHandle(handle)
}

func TestWindowsConditionalPIDRemovalRejectsReparsePoint(t *testing.T) {
	d := New(t.TempDir())
	outside := filepath.Join(t.TempDir(), "outside.pid")
	contents := []byte(`{"pid":303,"start_identity":"outside"}`)
	if err := os.WriteFile(outside, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, d.pidFile); err != nil {
		t.Skipf("Windows symlink unavailable: %v", err)
	}
	if err := removePIDFileIf(d.pidFile, func([]byte) bool { return true }); err == nil {
		t.Fatal("conditional PID deletion accepted a reparse point")
	}
	got, err := os.ReadFile(outside)
	if err != nil || string(got) != string(contents) {
		t.Fatalf("reparse target changed: contents=%q error=%v", got, err)
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
