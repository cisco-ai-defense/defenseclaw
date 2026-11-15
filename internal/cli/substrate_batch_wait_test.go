// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"github.com/defenseclaw/defenseclaw/internal/cliusage"
	"testing"
	"time"
)

// GAP-0274: a batch task that finds the pool full waits for a worker (a
// finished task frees its own about a minute after it ends) instead of
// failing at once; a pool that stays full still says so, in bounded time.
func TestSubstrateBatchWaitsForAWorker(t *testing.T) {
	full := cliusage.WithExitCode(substrateNoWorkerError{"the cluster has no free worker"}, 1)
	tries, notes := 0, 0
	code, err := substrateWaitForWorker(context.Background(), time.Second, 10*time.Millisecond, func() (int, error) {
		tries++
		if tries < 3 {
			return -1, full
		}
		return 0, nil
	}, func() { notes++ })
	if err != nil || code != 0 || tries != 3 || notes != 1 {
		t.Fatalf("code %d err %v tries %d notes %d", code, err, tries, notes)
	}
	start := time.Now()
	_, err = substrateWaitForWorker(context.Background(), 100*time.Millisecond, 10*time.Millisecond, func() (int, error) { return -1, full }, nil)
	var nw substrateNoWorkerError
	if !errors.As(err, &nw) || time.Since(start) > 2*time.Second {
		t.Fatalf("a pool that stays full: %v after %s", err, time.Since(start))
	}
	tries = 0
	other := errors.New("the template does not exist")
	if _, err := substrateWaitForWorker(context.Background(), time.Second, 10*time.Millisecond, func() (int, error) { tries++; return -1, other }, nil); err != other || tries != 1 {
		t.Fatalf("another error is not retried: %v (%d tries)", err, tries)
	}
}
