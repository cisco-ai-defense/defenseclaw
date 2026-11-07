// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package safefile

import (
	"errors"
	"time"

	"golang.org/x/sys/windows"
)

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
