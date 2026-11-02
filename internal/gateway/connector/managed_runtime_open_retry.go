// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"os"
	"time"
)

// managedRuntimeOpenRetryDelays bound the hook-side wait for a runtime file
// another process holds for a moment: the Guardian keeps a freshly published
// file open with write and delete access until it is in place, and retiring
// a generation opens it for delete. 325 ms in total stays well inside the
// hook's request budget.
var managedRuntimeOpenRetryDelays = []time.Duration{
	25 * time.Millisecond,
	50 * time.Millisecond,
	100 * time.Millisecond,
	150 * time.Millisecond,
}

// openManagedRuntimeFile opens path for reading, retrying a transient sharing
// or lock violation (Windows only; elsewhere it is a plain os.Open).
func openManagedRuntimeFile(path string) (*os.File, error) {
	return retryManagedRuntimeOpen(
		func() (*os.File, error) { return os.Open(path) },
		managedRuntimeOpenTransient,
		time.Sleep,
	)
}

// retryManagedRuntimeOpen calls open until it succeeds, fails with an error
// transient does not accept, or managedRuntimeOpenRetryDelays run out, and
// returns the last result.
func retryManagedRuntimeOpen(
	open func() (*os.File, error),
	transient func(error) bool,
	sleep func(time.Duration),
) (*os.File, error) {
	file, err := open()
	for _, delay := range managedRuntimeOpenRetryDelays {
		if err == nil || !transient(err) {
			break
		}
		sleep(delay)
		file, err = open()
	}
	return file, err
}
