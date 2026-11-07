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
// protection check and open. Sample through that burst without increasing the
// nominal wait budget of a genuinely absent file. Each read still validates
// the whole path and opened file before returning its body.
var transientRetryDelays = func() [31]time.Duration {
	var delays [31]time.Duration
	for i := range delays {
		delays[i] = time.Millisecond
	}
	return delays
}()

// SetTransientRetrySleepForTest replaces the wait between attempts. Tests can
// publish a file at that boundary without relying on scheduler timing.
// Call restore after a test that uses it; concurrent use is unsupported.
func SetTransientRetrySleepForTest(sleep func(time.Duration)) (restore func()) {
	previous := transientRetrySleep
	transientRetrySleep = sleep
	return func() { transientRetrySleep = previous }
}

func transientReadError(err error) bool {
	return errors.Is(err, ErrReadIdentityChanged) ||
		errors.Is(err, windows.ERROR_FILE_NOT_FOUND) ||
		errors.Is(err, windows.ERROR_SHARING_VIOLATION) ||
		errors.Is(err, windows.ERROR_LOCK_VIOLATION)
}
