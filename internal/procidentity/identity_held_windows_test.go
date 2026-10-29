// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package procidentity

import (
	"io"
	"os"
	"os/exec"
	"testing"

	"golang.org/x/sys/windows"
)

// TestHelperProcessReadsStdinUntilClosed is the child of the test below: it
// runs only with DC_PROCIDENTITY_HELPER=1 and exits when its stdin closes.
func TestHelperProcessReadsStdinUntilClosed(t *testing.T) {
	if os.Getenv("DC_PROCIDENTITY_HELPER") != "1" {
		t.Skip("helper process")
	}
	_, _ = io.Copy(io.Discard, os.Stdin)
	os.Exit(0)
}

// GAP-2325: on Windows a process that has exited stays an object while any
// other process holds a handle to it (a CI runner's Defender scan, a
// monitor), and GetProcessTimes still answers for it. Its creation time named
// an exited install-lock owner as live. An exited process has no identity
// while a handle to it is still open.
func TestOfNamesNoExitedProcessWhoseHandleIsStillHeld(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	child := exec.Command(self, "-test.run=^TestHelperProcessReadsStdinUntilClosed$")
	child.Env = append(os.Environ(), "DC_PROCIDENTITY_HELPER=1")
	stdin, err := child.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	pid := child.Process.Pid
	held, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, uint32(pid))
	if err != nil {
		_ = stdin.Close()
		_ = child.Wait()
		t.Fatal(err)
	}
	defer windows.CloseHandle(held)
	if live, ok := Of(pid); !ok || live == "" {
		_ = stdin.Close()
		_ = child.Wait()
		t.Fatal("no identity for the running child")
	}
	_ = stdin.Close()
	if err := child.Wait(); err != nil {
		t.Fatal(err)
	}
	if got, ok := Of(pid); ok {
		t.Fatalf("an exited process whose handle is still held has an identity %q", got)
	}
}
