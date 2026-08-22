//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestManagedWindowsFileLockContentionIsBoundedAndProgressContinues(t *testing.T) {
	originalTimeout := windowsManagedFileLockTimeout
	originalRetry := windowsManagedFileLockRetry
	windowsManagedFileLockTimeout = 150 * time.Millisecond
	windowsManagedFileLockRetry = 10 * time.Millisecond
	t.Cleanup(func() {
		windowsManagedFileLockTimeout = originalTimeout
		windowsManagedFileLockRetry = originalRetry
	})

	dir := t.TempDir()
	blockedPath := filepath.Join(dir, "first", "config.toml")
	if err := os.MkdirAll(filepath.Dir(blockedPath), 0o700); err != nil {
		t.Fatal(err)
	}
	hostile, err := os.OpenFile(blockedPath+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	hostileHandle := windows.Handle(hostile.Fd())
	hostileOverlapped := new(windows.Overlapped)
	if err := windows.LockFileEx(
		hostileHandle,
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0,
		1,
		0,
		hostileOverlapped,
	); err != nil {
		hostile.Close()
		t.Fatalf("hold hostile lock: %v", err)
	}
	held := true
	release := func() {
		if !held {
			return
		}
		_ = windows.UnlockFileEx(hostileHandle, 0, 1, 0, hostileOverlapped)
		_ = hostile.Close()
		held = false
	}
	t.Cleanup(release)

	callbackCalled := false
	started := time.Now()
	err = withFileLockMode(blockedPath, true, func() error {
		callbackCalled = true
		return nil
	})
	elapsed := time.Since(started)
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("managed contended lock error = %v, want bounded timeout", err)
	}
	if callbackCalled {
		t.Fatal("managed callback ran without acquiring the hostile lock")
	}
	if elapsed > time.Second {
		t.Fatalf("managed contention returned after %s, want under one second", elapsed)
	}

	// A failed first target must not strand the guardian: the next target can
	// acquire its independent lock while the hostile first lock remains held.
	secondProgress := false
	secondPath := filepath.Join(dir, "second", "config.toml")
	if err := os.MkdirAll(filepath.Dir(secondPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := withFileLockMode(secondPath, true, func() error {
		secondProgress = true
		return nil
	}); err != nil {
		t.Fatalf("subsequent target lock: %v", err)
	}
	if !secondProgress {
		t.Fatal("subsequent target did not progress after first-target contention")
	}

	// Once the hostile process releases its handle, the next periodic tick can
	// repair the original target using the same bounded acquisition path.
	release()
	tickProgress := false
	if err := withFileLockMode(blockedPath, true, func() error {
		tickProgress = true
		return nil
	}); err != nil {
		t.Fatalf("next-tick original target lock: %v", err)
	}
	if !tickProgress {
		t.Fatal("next tick did not progress after hostile lock release")
	}
}

func TestOrdinaryWindowsFileLockRetainsBlockingSemantics(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	hostile, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	handle := windows.Handle(hostile.Fd())
	overlapped := new(windows.Overlapped)
	if err := windows.LockFileEx(
		handle,
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0,
		1,
		0,
		overlapped,
	); err != nil {
		hostile.Close()
		t.Fatalf("hold ordinary contention fixture: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		done <- withFileLock(path, func() error { return nil })
	}()
	select {
	case err := <-done:
		_ = windows.UnlockFileEx(handle, 0, 1, 0, overlapped)
		_ = hostile.Close()
		t.Fatalf("ordinary lock returned before contention released: %v", err)
	case <-time.After(75 * time.Millisecond):
	}
	if err := windows.UnlockFileEx(handle, 0, 1, 0, overlapped); err != nil {
		hostile.Close()
		t.Fatal(err)
	}
	if err := hostile.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("ordinary lock after release: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("ordinary blocking lock did not progress after contention release")
	}
}
