// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// heldConversionReadLimit bounds the bytes read from a file about to be
// rewritten; a larger file cannot be the one the conversion read.
const heldConversionReadLimit = 64 << 20

// atomicFileHeldWriteHook runs while a rollback conversion holds the file and
// has confirmed its bytes, just before it writes; tests try to save the file
// here to prove they cannot.
var atomicFileHeldWriteHook func(path string)

// publishHeldConversion rewrites writePath, which a rollback conversion found
// holding the bytes with hash found, to data. Windows has no exchange of two
// files, and a rename over a file is a check followed by a replacement that
// loses a save made in between; moving the file aside exposes a missing name
// to a concurrent reader (GAP-2644, GAP-0546). So the file is opened with no
// sharing: nobody can write, rename or delete it while its bytes are compared
// with found and replaced, and an editor that tries meanwhile gets a sharing
// violation instead of having its save overwritten. A file that is not the
// bytes the conversion read is left as it is (errManagedTargetMoved). The
// staged tmpPath is removed. The new bytes are written before the file is cut
// to their length, so a file is never empty to a reader that waits for the
// hold, and the original bytes are put back if the write fails part-way.
func publishHeldConversion(tmpPath, writePath, found string, data []byte) error {
	defer os.Remove(tmpPath)
	var err error
	for attempt := 0; attempt < atomicFileRenameMaxAttempts; attempt++ {
		err = rewriteHeldFile(writePath, found, data)
		if err == nil || !atomicFileRenameBusy(err) {
			return err
		}
		time.Sleep(atomicFileRenameRetryDelay)
	}
	return err
}

func rewriteHeldFile(path, found string, data []byte) (err error) {
	name, err := winpath.UTF16Ptr(path)
	if err != nil {
		return &os.PathError{Op: "open", Path: path, Err: err}
	}
	handle, err := windows.CreateFile(
		name,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		0, // no sharing
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
			// A conversion starts on a file it read, so one that is gone was
			// removed or moved since; nothing is created in its place.
			return errManagedTargetMoved
		}
		return &os.PathError{Op: "open", Path: path, Err: err}
	}
	file := os.NewFile(uintptr(handle), path)
	defer func() {
		if closeErr := file.Close(); err == nil && closeErr != nil {
			err = closeErr
		}
	}()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errManagedTargetMoved
	}
	current, err := io.ReadAll(io.LimitReader(file, heldConversionReadLimit+1))
	if err != nil {
		return err
	}
	if len(current) > heldConversionReadLimit || managedFileSnapshotHash(current, true) != found {
		return errManagedTargetMoved
	}
	if atomicFileHeldWriteHook != nil {
		atomicFileHeldWriteHook(path)
	}
	if err := writeHeldBytes(file, data); err != nil {
		if restoreErr := writeHeldBytes(file, current); restoreErr != nil {
			return fmt.Errorf("rewrite %s: %w (and the original bytes could not be put back: %v)", path, err, restoreErr)
		}
		return fmt.Errorf("rewrite %s: %w", path, err)
	}
	return nil
}

func writeHeldBytes(file *os.File, data []byte) error {
	if _, err := file.WriteAt(data, 0); err != nil {
		return err
	}
	if err := file.Truncate(int64(len(data))); err != nil {
		return err
	}
	return file.Sync()
}
