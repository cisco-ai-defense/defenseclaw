// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package safefile

import (
	"errors"
	"time"
)

// ErrReadIdentityChanged asks RetryTransientRead to repeat a validated read
// when a replacement changes the file between its name and handle checks.
var ErrReadIdentityChanged = errors.New("file identity changed during read")

var transientRetrySleep = time.Sleep

// IsTransientReadError reports the short-lived name, sharing, or identity
// results that can occur while a validated file is being replaced.
func IsTransientReadError(err error) bool { return transientReadError(err) }

// RetryTransientRead repeats a validated read after a transient name or
// identity change. Platform-specific errors are selected by transientReadError.
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
