// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package safefile

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

var (
	replaceFileKernel32  = windows.NewLazySystemDLL("kernel32.dll")
	procReplaceFileW     = replaceFileKernel32.NewProc("ReplaceFileW")
	procCopyFileW        = replaceFileKernel32.NewProc("CopyFileW")
	classicRenameWarning sync.Once
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
		func() error { return replaceExistingThroughPublishedStage(destination, from, to) },
		func() error {
			return windows.MoveFileEx(from, to, windows.MOVEFILE_WRITE_THROUGH)
		},
	)
}

// Prepare the replacement's metadata under a temporary name. ReplaceFileW
// merges named streams and file protection there, while the published name
// continues to identify the old file. Only the final rename changes it.
func replaceExistingThroughPublishedStage(destination string, from, to *uint16) error {
	stage, err := os.CreateTemp(filepath.Dir(destination), ".safefile-metadata-*")
	if err != nil {
		return err
	}
	stagePath := stage.Name()
	if err := stage.Close(); err != nil {
		_ = os.Remove(stagePath)
		return err
	}
	if err := os.Remove(stagePath); err != nil {
		return err
	}
	defer os.Remove(stagePath)
	stageName, err := winpath.UTF16Ptr(stagePath)
	if err != nil {
		return err
	}
	if err := copyExistingWindowsFile(to, stageName); err != nil {
		return err
	}
	// CopyFileW copies the body and streams, but the staged file can inherit a
	// different DACL. ReplaceFileW merges the staged file's DACL into the new
	// body, so restore the original protection before that merge.
	if err := copyExistingWindowsDACL(destination, stagePath); err != nil {
		return err
	}
	if err := replaceExistingWindowsFile(stageName, from); err != nil {
		return err
	}
	if err := ReplaceFileAtomically(stagePath, destination); err != nil {
		// ReplaceFileW consumed source. The caller can regenerate it, but
		// retrying this operation with the old source name cannot succeed.
		return &replacementStageError{err: err}
	}
	return nil
}

type replacementStageError struct{ err error }

func (e *replacementStageError) Error() string { return e.err.Error() }
func (e *replacementStageError) Unwrap() error { return e.err }

func copyExistingWindowsFile(source, destination *uint16) error {
	r, _, callErr := procCopyFileW.Call(
		uintptr(unsafe.Pointer(source)), uintptr(unsafe.Pointer(destination)), 1,
	)
	if r != 0 {
		return nil
	}
	if callErr == nil || callErr == syscall.Errno(0) {
		return syscall.EINVAL
	}
	return callErr
}

func copyExistingWindowsDACL(source, destination string) error {
	from, err := winpath.UTF16Ptr(source)
	if err != nil {
		return err
	}
	current, err := windows.CreateFile(from, windows.READ_CONTROL,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(current)
	descriptor, err := windows.GetSecurityInfo(current, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	if descriptor == nil {
		return fmt.Errorf("safefile: original file has no security descriptor")
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return err
	}
	if dacl == nil {
		return fmt.Errorf("safefile: original file has no DACL")
	}
	control, _, err := descriptor.Control()
	if err != nil {
		return err
	}
	to, err := winpath.UTF16Ptr(destination)
	if err != nil {
		return err
	}
	stage, err := windows.CreateFile(to, windows.READ_CONTROL|windows.WRITE_DAC,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(stage)
	information := windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION)
	if control&windows.SE_DACL_PROTECTED != 0 {
		information |= windows.PROTECTED_DACL_SECURITY_INFORMATION
	} else {
		information |= windows.UNPROTECTED_DACL_SECURITY_INFORMATION
	}
	err = windows.SetSecurityInfo(stage, windows.SE_FILE_OBJECT, information, nil, nil, dacl, nil)
	runtime.KeepAlive(descriptor)
	return err
}

// replaceFileOnceWith prepares metadata when the destination exists. A missing
// destination still needs a first-create move; if another writer wins that
// race, prepare a replacement against the newly published destination.
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
		var staged *replacementStageError
		if errors.As(err, &staged) {
			return err
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

// ReplaceFileAtomically renames source over destination in one step. Windows
// can briefly report a missing name to a concurrent opener during a rename,
// so callers should avoid replacing identical content and retry owned reads
// when the file is expected. POSIX semantics let readers that share deletion
// keep an already-open handle. The new file keeps its own access list, so a
// caller sets the protection of source first.
//
// Where the POSIX-semantics rename is refused (a volume without it, or a
// filter driver that refuses FileRenameInfoEx), a FileRenameInfo replacement
// is used. It swaps the name in one operation, but Windows refuses it while
// any handle has the destination open, so it is retried while readers come
// and go. If they never let go within the budget, the error is returned and
// the old file stays in place; the caller's next ensure writes it again.
// Neither ReplaceFileW nor MoveFileEx is the fallback: both have exposed a
// missing destination to a concurrent reader (GAP-2644, GAP-0546).
func ReplaceFileAtomically(source, destination string) error {
	refused := false
	err := retryBusyRename(source, destination, func(source, destination string) error {
		err := atomicRenameReplace(source, destination)
		if !posixRenameUnsupported(err) {
			return err
		}
		refused = true
		warnClassicRenameFallback()
		return renameReplace(source, destination, windows.FileRenameInfo, fileRenameReplaceIfExists)
	}, time.Sleep, atomicReplaceMaxAttempts, atomicReplaceRetryDelay)
	if err != nil && refused {
		return fmt.Errorf("%w (the volume refuses the POSIX-semantics rename; %s is unchanged)", err, destination)
	}
	return err
}

func posixRenameUnsupported(err error) bool {
	return errors.Is(err, windows.ERROR_INVALID_PARAMETER) ||
		errors.Is(err, windows.ERROR_NOT_SUPPORTED)
}

func warnClassicRenameFallback() {
	classicRenameWarning.Do(func() {
		log.Printf("defenseclaw: WARNING: this volume does not support POSIX file replacement; concurrent readers may need to retry")
	})
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
