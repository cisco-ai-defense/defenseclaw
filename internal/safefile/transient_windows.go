// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package safefile

import (
	"errors"
	"time"

	"golang.org/x/sys/windows"
)

// transientRetryDelays is the wait before each repeat of a read that failed
// for a moment: about 50 ms in all. A rename replacement can briefly hide
// its destination; another process can also hold a file for a few milliseconds.
var transientRetryDelays = []time.Duration{
	time.Millisecond, 2 * time.Millisecond, 4 * time.Millisecond,
	8 * time.Millisecond, 16 * time.Millisecond, 19 * time.Millisecond,
}

var transientRetrySleep = time.Sleep

// SetTransientRetrySleepForTest replaces the wait between attempts. Tests can
// publish a file at that boundary without relying on scheduler timing.
// Call restore after a test that uses it; concurrent use is unsupported.
func SetTransientRetrySleepForTest(sleep func(time.Duration)) (restore func()) {
	previous := transientRetrySleep
	transientRetrySleep = sleep
	return func() { transientRetrySleep = previous }
}

// RetryTransientRead runs read and repeats it, for about 50 ms at most, while
// it fails because the file is missing from a folder that exists
// (ERROR_FILE_NOT_FOUND: a rename replacing it at that moment) or because
// another handle holds it (a sharing or lock violation). A file that is
// really absent still fails with its not-found error, after that window; a
// missing folder (ERROR_PATH_NOT_FOUND) fails at once, so a host where the
// folder was never made pays nothing. Use it for a file DefenseClaw replaces
// and the reader needs (absence fails closed or changes a decision), not for
// a marker whose absence is the normal state. Elsewhere read runs once.
func RetryTransientRead(read func() error) error {
	err := read()
	for _, delay := range transientRetryDelays {
		if !transientReadError(err) {
			return err
		}
		transientRetrySleep(delay)
		err = read()
	}
	return err
}

func transientReadError(err error) bool {
	return errors.Is(err, windows.ERROR_FILE_NOT_FOUND) ||
		errors.Is(err, windows.ERROR_SHARING_VIOLATION) ||
		errors.Is(err, windows.ERROR_LOCK_VIOLATION)
}
