// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/pathidentity"
)

// A gateway, guardian or CLI writer publishes native state (for example
// active_connector.json) by atomic replacement. On Windows the publisher keeps
// its own handle on the new file for a short validation step, and an indexer
// or antivirus scan can hold it briefly too. Setup waits a bounded time for
// such a holder instead of failing an install or upgrade on a transient lock
// (rel-1-0-3 GAP-0300), and fails closed after that.
const (
	nativeStateReadAttempts   = 10
	nativeStateReadRetryDelay = 100 * time.Millisecond
)

// nativeStateReadSleep is the wait between attempts; tests replace it.
var nativeStateReadSleep = time.Sleep

var (
	errNativeStateChangedWhileOpening = errors.New("native state changed while opening")
	errNativeStateChangedWhileReading = errors.New("native state changed while reading")
)

// nativeStateFileBusyError reports native state that stayed locked for the
// whole retry window. It names the holder when Windows can tell.
type nativeStateFileBusyError struct {
	Path    string
	Holders []string
	Err     error
}

func (e *nativeStateFileBusyError) Error() string {
	holder := "another process"
	if len(e.Holders) > 0 {
		holder = strings.Join(e.Holders, ", ")
	}
	cause := e.Err
	var pathErr *os.PathError
	if errors.As(cause, &pathErr) && pathErr.Err != nil {
		cause = pathErr.Err
	}
	return fmt.Sprintf(
		"%s is in use by %s and stayed locked for %s: %v; wait for that process to finish (or close it), then run Setup again",
		e.Path, holder, nativeStateReadWindow(), cause,
	)
}

func (e *nativeStateFileBusyError) Unwrap() error { return e.Err }

func nativeStateReadWindow() time.Duration {
	return time.Duration(nativeStateReadAttempts-1) * nativeStateReadRetryDelay
}

// readBoundedNativeStateFile reads one regular, non-reparse native state file
// of at most limit bytes. A file that is locked, or replaced between the open
// and the read, is read again a bounded number of times; anything else fails
// at once.
func readBoundedNativeStateFile(path string, limit int64) ([]byte, bool, error) {
	for attempt := 1; ; attempt++ {
		data, exists, err := readBoundedNativeStateFileOnce(path, limit)
		if err == nil || !nativeStateReadRetryable(err) {
			return data, exists, err
		}
		if attempt >= nativeStateReadAttempts {
			if nativeStateFileBusy(err) {
				return nil, false, &nativeStateFileBusyError{
					Path:    path,
					Holders: nativeStateFileHolders(path),
					Err:     err,
				}
			}
			return nil, false, err
		}
		nativeStateReadSleep(nativeStateReadRetryDelay)
	}
}

func nativeStateReadRetryable(err error) bool {
	return nativeStateFileBusy(err) ||
		errors.Is(err, errNativeStateChangedWhileOpening) ||
		errors.Is(err, errNativeStateChangedWhileReading)
}

func readBoundedNativeStateFileOnce(path string, limit int64) ([]byte, bool, error) {
	if err := rejectReparseAncestors(path); err != nil {
		return nil, false, err
	}
	before, err := pathidentity.LstatPinned(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if !before.Mode().IsRegular() {
		return nil, false, fmt.Errorf("native state path is not a regular file")
	}
	if before.Size() > limit {
		return nil, false, fmt.Errorf("native state exceeds %d bytes", limit)
	}

	file, err := openNativeStateFile(path)
	if errors.Is(err, os.ErrNotExist) {
		// Replaced or removed between the Lstat and the open.
		return nil, false, errNativeStateChangedWhileOpening
	}
	if err != nil {
		return nil, false, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return nil, false, err
	}
	if !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		return nil, false, errNativeStateChangedWhileOpening
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(data)) > limit {
		return nil, false, fmt.Errorf("native state exceeds %d bytes", limit)
	}
	after, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, errNativeStateChangedWhileReading
	}
	if err != nil {
		return nil, false, err
	}
	if !after.Mode().IsRegular() || !os.SameFile(opened, after) {
		return nil, false, errNativeStateChangedWhileReading
	}
	if err := rejectReparseAncestors(path); err != nil {
		return nil, false, err
	}
	return data, true, nil
}
