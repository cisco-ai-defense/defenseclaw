// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package safefile

import (
	"errors"
	"syscall"
	"time"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

var (
	replaceFileKernel32 = windows.NewLazySystemDLL("kernel32.dll")
	procReplaceFileW    = replaceFileKernel32.NewProc("ReplaceFileW")
)

const (
	replaceFileMaxAttempts = 100
	replaceFileRetryDelay  = 5 * time.Millisecond
	// ReplaceFileW reports this when a concurrent writer briefly holds the old
	// destination between merge and removal. Microsoft documents that both
	// original names remain intact for this error, so a bounded retry is safe.
	errorUnableToRemoveReplaced = syscall.Errno(1175)
)

func replaceFile(source, destination string) error {
	return replaceFileWith(source, destination, replaceFileOnce, time.Sleep)
}

func replaceFileOnce(source, destination string) error {
	from, err := winpath.UTF16Ptr(source)
	if err != nil {
		return err
	}
	to, err := winpath.UTF16Ptr(destination)
	if err != nil {
		return err
	}
	return replaceFileOnceWith(
		func() error { return replaceExistingWindowsFile(to, from) },
		func() error {
			return windows.MoveFileEx(from, to, windows.MOVEFILE_WRITE_THROUGH)
		},
	)
}

// replaceFileOnceWith uses ReplaceFileW when the destination exists. Unlike a
// replacement MoveFileEx, ReplaceFileW merges the destination's DACL, EFS and
// compression state, creation metadata, and non-conflicting named streams into
// the newly staged data file. A missing destination still needs a first-create
// move; if another writer wins that race, retry ReplaceFileW against it.
func replaceFileOnceWith(replaceExisting, moveNew func() error) error {
	err := replaceExisting()
	if err == nil {
		return nil
	}
	if !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) && !errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
		return err
	}
	if moveErr := moveNew(); moveErr != nil {
		if errors.Is(moveErr, windows.ERROR_ALREADY_EXISTS) || errors.Is(moveErr, windows.ERROR_FILE_EXISTS) {
			return replaceExisting()
		}
		return moveErr
	}
	return nil
}

func replaceExistingWindowsFile(destination, source *uint16) error {
	r, _, callErr := procReplaceFileW.Call(
		uintptr(unsafe.Pointer(destination)),
		uintptr(unsafe.Pointer(source)),
		0, // no backup: the caller already owns rollback/temporary cleanup
		0, // REPLACEFILE_WRITE_THROUGH is explicitly unsupported
		0,
		0,
	)
	if r != 0 {
		return nil
	}
	if callErr == nil || callErr == syscall.Errno(0) {
		return syscall.EINVAL
	}
	return callErr
}

func replaceFileWith(
	source string,
	destination string,
	rename func(string, string) error,
	sleep func(time.Duration),
) error {
	var err error
	for attempt := 0; attempt < replaceFileMaxAttempts; attempt++ {
		err = rename(source, destination)
		if err == nil {
			return nil
		}
		if !errors.Is(err, windows.ERROR_ACCESS_DENIED) &&
			!errors.Is(err, windows.ERROR_SHARING_VIOLATION) &&
			!errors.Is(err, windows.ERROR_LOCK_VIOLATION) &&
			!errors.Is(err, errorUnableToRemoveReplaced) {
			return err
		}
		if attempt+1 == replaceFileMaxAttempts {
			return err
		}
		sleep(replaceFileRetryDelay)
	}
	return err
}
