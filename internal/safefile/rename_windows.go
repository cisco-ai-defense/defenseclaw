// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package safefile

import (
	"errors"
	"fmt"
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
	// ReplaceFileAtomically retries busy errors for longer: where the
	// POSIX-semantics rename is refused, the ordinary rename it uses instead
	// waits for a moment when no reader has the destination open.
	atomicReplaceMaxAttempts = 3000
	atomicReplaceRetryDelay  = time.Millisecond
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
	return retryBusyRename(source, destination, rename, sleep, replaceFileMaxAttempts, replaceFileRetryDelay)
}

// retryBusyRename calls rename up to attempts times while it fails with an
// error that means another handle has a file open for now.
func retryBusyRename(
	source string,
	destination string,
	rename func(string, string) error,
	sleep func(time.Duration),
	attempts int,
	delay time.Duration,
) error {
	var err error
	for attempt := 0; attempt < attempts; attempt++ {
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
		if attempt+1 == attempts {
			return err
		}
		sleep(delay)
	}
	return err
}

// ReplaceFileAtomically renames source over destination in one step, so a
// reader that opens destination meanwhile finds the old file or the new one,
// never no file. ReplaceFile (ReplaceFileW) moves an existing destination
// aside while it merges metadata, and for that moment the name is missing: a
// policy file another file names (Cursor's hooks.json names the machine
// adapter) must not go missing (GAP-2572). The rename uses POSIX semantics,
// so readers that share deletion (Cursor, Codex) keep reading; the new file
// keeps its own access list, so a caller sets the protection of source first.
//
// Where the POSIX-semantics rename is refused (a volume without it, or a
// filter driver that refuses FileRenameInfoEx), an ordinary replacing rename
// is used. It also swaps the name in one step, but Windows refuses it while
// any handle has the destination open, so it is retried while readers come
// and go. If they never let go within the budget, the error is returned and
// the old file stays in place; the caller's next ensure writes it again.
// ReplaceFile is never the fallback: a reader would find no file (GAP-2644).
func ReplaceFileAtomically(source, destination string) error {
	refused := false
	err := retryBusyRename(source, destination, func(source, destination string) error {
		err := atomicRenameReplace(source, destination)
		if !errors.Is(err, windows.ERROR_INVALID_PARAMETER) &&
			!errors.Is(err, windows.ERROR_NOT_SUPPORTED) &&
			!errors.Is(err, windows.ERROR_INVALID_FUNCTION) {
			return err
		}
		refused = true
		return moveFileReplace(source, destination)
	}, time.Sleep, atomicReplaceMaxAttempts, atomicReplaceRetryDelay)
	if err != nil && refused {
		return fmt.Errorf("%w (the volume refuses the POSIX-semantics rename; %s is unchanged)", err, destination)
	}
	return err
}

// atomicRenameReplace is the POSIX-semantics rename.
var atomicRenameReplace = func(source, destination string) error {
	return renameReplace(source, destination, windows.FileRenameInfoEx,
		fileRenameReplaceIfExists|fileRenamePOSIXSemantics)
}

// RefusePOSIXRenameForTest makes ReplaceFileAtomically run as on a volume or
// a filter driver that refuses the POSIX-semantics rename, until restore runs.
// For tests only.
func RefusePOSIXRenameForTest() (restore func()) {
	previous := atomicRenameReplace
	atomicRenameReplace = func(string, string) error { return windows.ERROR_NOT_SUPPORTED }
	return func() { atomicRenameReplace = previous }
}

// moveFileReplace renames source over destination with an ordinary replacing
// rename.
func moveFileReplace(source, destination string) error {
	from, err := winpath.UTF16Ptr(source)
	if err != nil {
		return err
	}
	to, err := winpath.UTF16Ptr(destination)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(from, to, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}
