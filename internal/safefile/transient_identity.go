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

// transientRetryDelays bounds a validated read to about 50 ms while a
// replacement finishes. The same budget applies on every platform.
var transientRetryDelays = []time.Duration{
	time.Millisecond, 2 * time.Millisecond, 4 * time.Millisecond,
	8 * time.Millisecond, 16 * time.Millisecond, 19 * time.Millisecond,
}

var transientRetrySleep = time.Sleep

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
