// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package winmutex

import (
	"errors"
	"fmt"
	"runtime"
	"sync"

	"golang.org/x/sys/windows"
)

// ErrBusy reports that the named mutex already exists, so another holder (in
// this process or another one) has it.
var ErrBusy = errors.New("named mutex is already held")

// TryAcquire creates the named mutex as its first owner, without waiting. It
// returns ErrBusy when the mutex already exists.
//
// Only the OS thread that owns a Windows mutex can release it, and Go can move
// a goroutine to another thread at any blocking call. So one goroutine, locked
// to its OS thread for the whole hold, creates, releases and closes the mutex;
// release only asks it to and waits for the result. Release may be called from
// any goroutine, more than once.
func TryAcquire(name string, attrs *windows.SecurityAttributes) (release func() error, err error) {
	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, fmt.Errorf("encode mutex name: %w", err)
	}
	acquired := make(chan error, 1)
	releaseRequested := make(chan struct{})
	released := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		handle, err := windows.CreateMutex(attrs, true, namePtr)
		if err != nil {
			if handle != 0 {
				_ = windows.CloseHandle(handle)
			}
			runtime.UnlockOSThread()
			if errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
				err = ErrBusy
			}
			acquired <- err
			return
		}
		acquired <- nil
		<-releaseRequested
		if err := windows.ReleaseMutex(handle); err != nil {
			_ = windows.CloseHandle(handle)
			// Exit still locked: Go ends this thread and Windows marks the
			// mutex abandoned, so a waiter gets it now, not at process exit.
			released <- fmt.Errorf("release mutex: %w", err)
			return
		}
		runtime.UnlockOSThread()
		released <- windows.CloseHandle(handle)
	}()
	if err := <-acquired; err != nil {
		return nil, err
	}
	var once sync.Once
	var releaseErr error
	return func() error {
		once.Do(func() {
			close(releaseRequested)
			releaseErr = <-released
		})
		return releaseErr
	}, nil
}
