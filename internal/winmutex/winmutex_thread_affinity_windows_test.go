// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package winmutex

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"

	"golang.org/x/sys/windows"
)

func testMutexName(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf(`Local\DefenseClaw.winmutex.test.%d.%s`, os.Getpid(), t.Name())
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

func TestReleaseFromAnotherOSThreadHandsTheMutexToAWaiter(t *testing.T) {
	name := testMutexName(t)
	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 50; i++ {
		// Acquire on a goroutine pinned to thread A and keep A busy, so the
		// release below runs on a different thread.
		type acquired struct {
			release func() error
			err     error
		}
		got := make(chan acquired, 1)
		unpin := make(chan struct{})
		go func() {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			release, err := TryAcquire(name, nil)
			got <- acquired{release, err}
			<-unpin
		}()
		held := <-got
		if held.err != nil {
			close(unpin)
			t.Fatalf("iteration %d: acquire: %v", i, held.err)
		}
		waiter, err := windows.OpenMutex(windows.SYNCHRONIZE, false, namePtr)
		if err != nil {
			close(unpin)
			t.Fatalf("iteration %d: open the held mutex: %v", i, err)
		}
		releaseErr := onPinnedThread(held.release)
		close(unpin)
		if releaseErr != nil {
			_ = windows.CloseHandle(waiter)
			t.Fatalf("iteration %d: release from another OS thread: %v", i, releaseErr)
		}
		// The waiter must own the mutex at once: not time out (still held)
		// and not find it abandoned (never released).
		if err := onPinnedThread(func() error {
			event, waitErr := windows.WaitForSingleObject(waiter, 0)
			if waitErr != nil {
				return waitErr
			}
			if event != windows.WAIT_OBJECT_0 {
				return fmt.Errorf("waiter got wait result %#x, want a released mutex", event)
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

func TestTryAcquireIsBusyWhileHeldAndFreeAfterRelease(t *testing.T) {
	name := testMutexName(t)
	release, err := TryAcquire(name, nil)
	if err != nil {
		t.Fatal(err)
	}
	if second, err := TryAcquire(name, nil); !errors.Is(err, ErrBusy) {
		if second != nil {
			_ = second()
		}
		t.Fatalf("second TryAcquire while held: err = %v, want ErrBusy", err)
	}
	if err := release(); err != nil {
		t.Fatalf("release: %v", err)
	}
	if err := release(); err != nil {
		t.Fatalf("second release call: %v", err)
	}
	again, err := TryAcquire(name, nil)
	if err != nil {
		t.Fatalf("acquire after release: %v", err)
	}
	if err := again(); err != nil {
		t.Fatalf("release after reacquire: %v", err)
	}
}

func TestOneHolderAtATimeAcrossGoroutines(t *testing.T) {
	const goroutines = 8
	const attempts = 200
	name := testMutexName(t)
	var holders, acquisitions atomic.Int32
	errs := make(chan error, goroutines*attempts)
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < attempts; i++ {
				release, err := TryAcquire(name, nil)
				if errors.Is(err, ErrBusy) {
					runtime.Gosched()
					continue
				}
				if err != nil {
					errs <- err
					return
				}
				if n := holders.Add(1); n != 1 {
					errs <- errors.New("two goroutines held the mutex at once")
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
		t.Fatal("no goroutine ever acquired the mutex")
	}
}
