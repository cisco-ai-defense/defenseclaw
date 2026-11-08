// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

// lifecycleHelperProcessAlive reports whether pid is a running process. A
// process that has exited stays openable for as long as any handle to its
// kernel object is open (another process, a scanner, a job accounting
// record), and its exit status can be any value, STILL_ACTIVE (259)
// included. Neither opening it nor reading its exit status proves it runs.
// The process object is signaled once the process has ended, so a
// zero-time wait on a handle is the answer. A pid that cannot be opened is
// gone; one that cannot be waited on is not proven gone.
func lifecycleHelperProcessAlive(pid int) bool {
	handle, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(pid))
	if err != nil {
		return false
	}
	defer windows.CloseHandle(handle)
	event, err := windows.WaitForSingleObject(handle, 0)
	if err != nil {
		return true
	}
	return event != windows.WAIT_OBJECT_0
}

// An exited lifecycle child that something else still holds a handle to is
// not alive, whatever its exit status: the timeout test asks whether Setup
// killed the child, not whether the kernel has released its process object.
func TestLifecycleHelperLivenessIgnoresAnExitedProcessThatIsStillOpen(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		mode string
		// end brings a running child to its end; nil lets it end by itself.
		end func(*exec.Cmd) error
		// wantStatus is the exit status the exited child must carry.
		wantStatus uint32
	}{
		{name: "killed", mode: "hang", end: func(c *exec.Cmd) error { return c.Process.Kill() }, wantStatus: 1},
		{name: "exited with the still-active status", mode: "exit-still-active", wantStatus: 259},
	} {
		t.Run(tc.name, func(t *testing.T) {
			child := exec.Command(executable, "-test.run=^TestEnterpriseLifecycleChildHelper$")
			child.Env = append(os.Environ(), lifecycleHelperMode+"="+tc.mode,
				lifecycleHelperPIDFile+"="+filepath.Join(t.TempDir(), "child.pid"))
			if err := child.Start(); err != nil {
				t.Fatal(err)
			}
			pid := child.Process.Pid
			t.Cleanup(func() { _ = child.Process.Kill(); _ = child.Wait() })
			// Held before the child ends, so the process object outlives it.
			held, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
			if err != nil {
				t.Fatal(err)
			}
			defer windows.CloseHandle(held)
			if tc.end != nil {
				// Control: a child that is still running is reported alive.
				if !lifecycleHelperProcessAlive(pid) {
					t.Fatalf("the running helper %d was reported gone", pid)
				}
				if err := tc.end(child); err != nil {
					t.Fatal(err)
				}
			}
			if event, err := windows.WaitForSingleObject(held, 30000); err != nil || event != windows.WAIT_OBJECT_0 {
				t.Fatalf("the helper %d did not end: event %#x, err %v", pid, event, err)
			}
			var status uint32
			if err := windows.GetExitCodeProcess(held, &status); err != nil {
				t.Fatal(err)
			}
			if status != tc.wantStatus {
				t.Fatalf("the helper %d ended with status %d, want %d", pid, status, tc.wantStatus)
			}
			if lifecycleHelperProcessAlive(pid) {
				t.Fatalf("the ended helper %d (status %d) was reported running while a handle to it stayed open", pid, status)
			}
		})
	}
}
