// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package safefile

import (
	"errors"
	"fmt"
	"time"
)

// ErrReadIdentityChanged asks RetryTransientRead to repeat a validated read
// when a replacement changes the file between its name and handle checks.
var ErrReadIdentityChanged = errors.New("file identity changed during read")

var transientRetrySleep = time.Sleep

// IsTransientReadError reports the short-lived name, sharing, or identity
// results that can occur while a validated file is being replaced. A missing
// name is one of them only for a reader that saw the name earlier: such a
// reader repeats with RetryPublishedRead.
func IsTransientReadError(err error) bool { return transientReadError(err) || nameMissing(err) }

// NameVanished marks a missing-name result of a read that already saw the
// name, during this attempt or an earlier one, as a replacement in flight:
// the read repeats with the whole budget and the result is never reported as
// absence alone. Elsewhere than Windows a rename keeps the name, and err is
// returned unchanged.
func NameVanished(err error) error {
	if !nameMissing(err) || errors.Is(err, ErrReadIdentityChanged) {
		return err
	}
	return fmt.Errorf("%w: %w", err, ErrReadIdentityChanged)
}

// transientRetry decides whether one more attempt of a validated read can
// change its result. Sharing, lock and identity results prove the name exists
// and repeat with the whole budget. A missing name repeats with the whole
// budget too, unless the read is optional (absence is an answer) and no
// attempt has seen the name yet: then it is absence, not a replacement, and
// gets one confirming look after the first wait, so a file that is not there
// costs one wait instead of the whole budget (GAP-2184).
type transientRetry struct{ optional, named, confirmed bool }

func (r *transientRetry) again(err error) bool {
	switch {
	case transientReadError(err):
		r.named = true
		return true
	case !nameMissing(err):
		return false
	case !r.optional || r.named:
		return true
	case !r.confirmed:
		r.confirmed = true
		return true
	}
	return false
}

// RetryTransientRead repeats a validated read of a file that is expected to
// exist after a transient name or identity change. Platform-specific errors
// are selected by transientReadError and nameMissing.
func RetryTransientRead(read func() error) error {
	return retryTransientRead(read, transientRetry{})
}

// RetryOptionalRead is RetryTransientRead for a read whose caller takes a
// missing file as an answer (an optional policy, a file not written yet). A
// name missing from the start is looked up once more after the first wait and
// then reported; a name that a step of the read saw and then lost must be
// returned through NameVanished, and repeats as in RetryTransientRead.
func RetryOptionalRead(read func() error) error {
	return retryTransientRead(read, transientRetry{optional: true})
}

func retryTransientRead(read func() error, retry transientRetry) error {
	err := read()
	for _, delay := range transientRetryDelays {
		if !retry.again(err) {
			return err
		}
		transientRetrySleep(delay)
		err = read()
	}
	return err
}
