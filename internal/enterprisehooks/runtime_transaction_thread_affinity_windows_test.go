//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"fmt"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// A Windows mutex belongs to the OS thread that acquired it. The connector
// transaction lock is taken and released by callers on whatever thread their
// goroutine runs on, so this test pins the lock and the unlock to two
// different OS threads and checks that a waiter in another handle gets the
// machine-wide mutex at once.
func TestWindowsUserRuntimeTransactionUnlockFromAnotherOSThreadReleasesTheMachineMutex(t *testing.T) {
	sid := currentWindowsTestSID(t).String()
	name, err := windows.UTF16PtrFromString(`Global\Cisco.DefenseClaw.EnterpriseHooks.` + strings.ToUpper(sid))
	if err != nil {
		t.Fatal(err)
	}
	onPinnedThread := func(fn func() error) error {
		result := make(chan error, 1)
		go func() {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			result <- fn()
		}()
		return <-result
	}
	for i := 0; i < 20; i++ {
		type locked struct {
			unlock func()
			err    error
		}
		got := make(chan locked, 1)
		unpin := make(chan struct{})
		go func() {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			unlock, err := lockWindowsUserRuntimeTransaction(sid)
			got <- locked{unlock, err}
			<-unpin
		}()
		held := <-got
		if held.err != nil {
			close(unpin)
			t.Fatalf("iteration %d: lock: %v", i, held.err)
		}
		waiter, err := windows.OpenMutex(windows.SYNCHRONIZE, false, name)
		if err != nil {
			close(unpin)
			held.unlock()
			t.Fatalf("iteration %d: open the held machine mutex: %v", i, err)
		}
		_ = onPinnedThread(func() error { held.unlock(); return nil })
		err = onPinnedThread(func() error {
			event, waitErr := windows.WaitForSingleObject(waiter, 0)
			if waitErr != nil {
				return waitErr
			}
			if event != windows.WAIT_OBJECT_0 {
				return fmt.Errorf("waiter got wait result %#x after unlock, want a released mutex", event)
			}
			return windows.ReleaseMutex(waiter)
		})
		close(unpin)
		_ = windows.CloseHandle(waiter)
		if err != nil {
			t.Fatalf("iteration %d: %v", i, err)
		}
	}
}
