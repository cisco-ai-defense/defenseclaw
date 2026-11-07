// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package safefile

import (
	"errors"
	"time"
)

var transientRetryDelays = []time.Duration{
	time.Millisecond, 2 * time.Millisecond, 4 * time.Millisecond,
	8 * time.Millisecond, 16 * time.Millisecond, 19 * time.Millisecond,
}

// Non-Windows publication already keeps a name present through rename.
func RetryPublishedRead(read func() error) error { return RetryTransientRead(read) }

// A non-Windows rename does not drop the name, but validation can still
// observe the old and new file identities in one read attempt.
func transientReadError(err error) bool { return errors.Is(err, ErrReadIdentityChanged) }
