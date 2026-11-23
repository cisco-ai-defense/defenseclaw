// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package processutil

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// TestStartTreeKillsTheProcessWhenResumeFails (GAP-1017): when the resume
// fails and the job cannot be terminated either, StartTree must still end the
// direct process through its own handle, as runTree does. Otherwise the
// suspended child never exits and cmd.Wait blocks the caller for good.
func TestStartTreeKillsTheProcessWhenResumeFails(t *testing.T) {
	oldResume, oldTerminate := treeResume, treeTerminate
	t.Cleanup(func() { treeResume, treeTerminate = oldResume, oldTerminate })
	treeResume = func(windows.Handle) error { return errors.New("resume refused") }
	var seen atomic.Uintptr
	treeTerminate = func(job windows.Handle, _ uint32) error {
		seen.Store(uintptr(job))
		return errors.New("terminate refused")
	}
	cmd := exec.Command(filepath.Join(os.Getenv("SystemRoot"), "System32", "ping.exe"), "-n", "60", "127.0.0.1")
	done := make(chan error, 1)
	go func() {
		_, err := StartTree(cmd)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "resume refused") {
			t.Fatalf("StartTree error = %v, want the resume failure", err)
		}
	case <-time.After(10 * time.Second):
		if job := seen.Load(); job != 0 {
			_ = windows.TerminateJobObject(windows.Handle(job), 1) // let the blocked Wait return
		}
		<-done
		t.Fatal("StartTree blocked in cmd.Wait: the suspended direct process was not killed")
	}
	if cmd.ProcessState == nil || !cmd.ProcessState.Exited() {
		t.Fatalf("the direct process was not ended: %v", cmd.ProcessState)
	}
}
