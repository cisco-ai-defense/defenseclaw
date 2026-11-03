// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"

	"golang.org/x/sys/windows"
)

// A Windows mutex belongs to the OS thread that acquired it, and Go moves a
// goroutine to another thread at any blocking call. These tests pin the
// acquiring and the releasing goroutine to two different OS threads, so a
// release that calls ReleaseMutex from the caller's thread fails every time.

// acquireSetupLockOnPinnedThread takes the setup lock from a goroutine locked
// to its own OS thread and keeps that thread busy until unpin is called, so no
// other goroutine can run on it in between.
func acquireSetupLockOnPinnedThread(t *testing.T) (release func() error, unpin func()) {
	t.Helper()
	type acquired struct {
		release func() error
		err     error
	}
	result := make(chan acquired, 1)
	done := make(chan struct{})
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		release, err := acquireSetupLock()
		result <- acquired{release: release, err: err}
		<-done
	}()
	var once sync.Once
	unpin = func() { once.Do(func() { close(done) }) }
	t.Cleanup(unpin)
	got := <-result
	if got.err != nil {
		t.Fatalf("acquire setup lock: %v", got.err)
	}
	return got.release, unpin
}

// onPinnedThread runs fn on a fresh goroutine locked to its own OS thread.
func onPinnedThread(fn func() error) error {
	result := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		result <- fn()
	}()
	return <-result
}

func TestSetupLockReleasesFromAnotherOSThreadAndHandsOverToAWaiter(t *testing.T) {
	lockName, err := setupLockName()
	if err != nil {
		t.Fatal(err)
	}
	name, err := windows.UTF16PtrFromString(lockName)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 50; i++ {
		release, unpin := acquireSetupLockOnPinnedThread(t)
		waiter, err := windows.OpenMutex(windows.SYNCHRONIZE, false, name)
		if err != nil {
			t.Fatalf("iteration %d: open the held setup mutex: %v", i, err)
		}
		if err := onPinnedThread(release); err != nil {
			_ = windows.CloseHandle(waiter)
			t.Fatalf("iteration %d: release from another OS thread: %v", i, err)
		}
		unpin()
		// The waiter must own the mutex at once: not time out (still held by
		// the acquiring thread) and not see it abandoned (never released).
		if err := onPinnedThread(func() error {
			event, waitErr := windows.WaitForSingleObject(waiter, 0)
			if waitErr != nil {
				return waitErr
			}
			if event != windows.WAIT_OBJECT_0 {
				return errors.New("waiter did not get a released setup mutex")
			}
			return windows.ReleaseMutex(waiter)
		}); err != nil {
			_ = windows.CloseHandle(waiter)
			t.Fatalf("iteration %d: %v", i, err)
		}
		if err := windows.CloseHandle(waiter); err != nil {
			t.Fatalf("iteration %d: close waiter: %v", i, err)
		}
	}
}

func TestSetupLockIsHeldByOneGoroutineAtATimeAcrossThreads(t *testing.T) {
	const goroutines = 8
	const attempts = 200
	var holders, acquisitions atomic.Int32
	errs := make(chan error, goroutines*attempts)
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < attempts; i++ {
				release, err := acquireSetupLock()
				if errors.Is(err, errSetupLockBusy) {
					runtime.Gosched()
					continue
				}
				if err != nil {
					errs <- err
					return
				}
				if n := holders.Add(1); n != 1 {
					errs <- errors.New("two goroutines held the setup lock at once")
				}
				acquisitions.Add(1)
				// Yield so the holder is likely to resume on another thread.
				runtime.Gosched()
				holders.Add(-1)
				if err := release(); err != nil {
					errs <- err
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if acquisitions.Load() == 0 {
		t.Fatal("no goroutine ever acquired the setup lock")
	}
	release, err := acquireSetupLock()
	if err != nil {
		t.Fatalf("acquire after the hammer: %v", err)
	}
	if err := release(); err != nil {
		t.Fatalf("release after the hammer: %v", err)
	}
	if err := release(); err != nil {
		t.Fatalf("second release call: %v", err)
	}
}
