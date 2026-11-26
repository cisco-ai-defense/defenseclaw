// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package safefile

import (
	"errors"
	"time"

	"golang.org/x/sys/windows"
)

// Repeated Windows replacements can change the name between every lookup,
// protection check and open. Sample through that burst; a read that takes
// absence as an answer does not spend it on a name that is missing from the
// start (RetryOptionalRead). Callers retain their path and opened-file checks
// on every attempt.
var transientRetryDelays = func() [31]time.Duration {
	var delays [31]time.Duration
	for i := range delays {
		delays[i] = time.Millisecond
	}
	delays[len(delays)-1] = 20 * time.Millisecond
	return delays
}()

const publishedReadRetryWindow = 250 * time.Millisecond

// RetryPublishedRead keeps sampling a validated read while a published name
// is changing. A busy writer can consume a fixed number of attempts before
// the name settles, so this variant uses elapsed time as its bound. Permanent
// errors still return after one attempt.
func RetryPublishedRead(read func() error) error {
	var retry transientRetry
	deadline := time.Now().Add(publishedReadRetryWindow)
	for {
		err := read()
		remaining := time.Until(deadline)
		if !retry.again(err) || remaining <= 0 {
			return err
		}
		if remaining > time.Millisecond {
			remaining = time.Millisecond
		}
		transientRetrySleep(remaining)
	}
}

// SetTransientRetrySleepForTest replaces the wait between attempts. Tests can
// publish a file at that boundary without relying on scheduler timing.
// Call restore after a test that uses it; concurrent use is unsupported.
func SetTransientRetrySleepForTest(sleep func(time.Duration)) (restore func()) {
	previous := transientRetrySleep
	transientRetrySleep = sleep
	return func() { transientRetrySleep = previous }
}

// transientReadError reports the results that prove the name exists while a
// writer holds or swaps it.
func transientReadError(err error) bool {
	return errors.Is(err, ErrReadIdentityChanged) ||
		errors.Is(err, windows.ERROR_SHARING_VIOLATION) ||
		errors.Is(err, windows.ERROR_LOCK_VIOLATION)
}

// nameMissing reports a lookup or open that found no file under the name. A
// rename by a writer that does not use the POSIX-semantics replacement (for
// example MoveFileEx) can show this to a concurrent opener for a moment.
// DefenseClaw's own writers (ReplaceFileAtomically, and on NTFS its classic
// rename-replace fallback) never show a missing name on a first look.
func nameMissing(err error) bool { return errors.Is(err, windows.ERROR_FILE_NOT_FOUND) }
