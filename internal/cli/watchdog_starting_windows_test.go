// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// GAP-1310: a watchdog that holds its ownership lock but has not published
// its PID yet is starting, not failed or mismatched.
func TestWindowsWatchdogHeldButUnpublishedIsStillStarting(t *testing.T) {
	dataDir := t.TempDir()
	pidPath := filepath.Join(dataDir, watchdogPIDFile)
	info := watchdogPIDInfo{
		PID:           os.Getpid(),
		Executable:    mustWatchdogTestExecutable(t),
		StartIdentity: watchdogProcessStartIdentity(os.Getpid()),
		ControlName:   "still-starting",
	}
	if watchdogStillStarting(pidPath) {
		t.Fatal("no owner reads as starting")
	}
	entered := make(chan struct{})
	release := make(chan struct{})
	watchdogPIDPublicationBeforePublish = func(string) error {
		close(entered)
		<-release
		return nil
	}
	t.Cleanup(func() { watchdogPIDPublicationBeforePublish = nil })
	acquired := make(chan *os.File, 1)
	go func() {
		holder, err := acquireWatchdogPIDFile(pidPath, info)
		if err != nil {
			t.Error(err)
		}
		acquired <- holder
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("start did not reach the publication seam")
	}
	if !watchdogStillStarting(pidPath) {
		t.Fatal("held ownership without a published PID does not read as starting")
	}
	close(release)
	holder := <-acquired
	if holder != nil {
		defer holder.Close()
	}
	if watchdogStillStarting(pidPath) {
		t.Fatal("a published owner still reads as starting")
	}
}
