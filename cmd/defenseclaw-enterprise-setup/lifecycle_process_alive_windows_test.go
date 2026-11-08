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
// record), so opening it proves nothing: the exit code does, STILL_ACTIVE
// meaning running. A pid that cannot be opened is gone. Mirrors the
// daemon package check, which met the same exited-but-openable process.
func lifecycleHelperProcessAlive(pid int) bool {
	const stillActive = 259
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return false
	}
	defer windows.CloseHandle(handle)
	var code uint32
	if err := windows.GetExitCodeProcess(handle, &code); err != nil {
		return true
	}
	return code == stillActive
}

// An exited lifecycle child that something else still holds a handle to is
// not alive: the timeout test asks whether Setup killed the child, not
// whether the kernel has released its process object.
func TestLifecycleHelperLivenessIgnoresAnExitedProcessThatIsStillOpen(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	child := exec.Command(executable, "-test.run=^TestEnterpriseLifecycleChildHelper$")
	child.Env = append(os.Environ(), lifecycleHelperMode+"=hang",
		lifecycleHelperPIDFile+"="+filepath.Join(t.TempDir(), "child.pid"))
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	pid := child.Process.Pid
	t.Cleanup(func() { _ = child.Process.Kill() })
	if !lifecycleHelperProcessAlive(pid) {
		t.Fatalf("the running helper %d was reported gone", pid)
	}
	held, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(held)
	if err := child.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = child.Wait()
	if lifecycleHelperProcessAlive(pid) {
		t.Fatalf("the killed helper %d was reported running while a handle to it stayed open", pid)
	}
}
