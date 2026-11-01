// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"errors"
	"os"
	"testing"
	"time"
)

var errTestSharingViolation = errors.New("sharing violation")

func isTestSharingViolation(err error) bool { return errors.Is(err, errTestSharingViolation) }

// A transient violation is retried until the open succeeds.
func TestRetryManagedRuntimeOpenRecoversFromTransientViolation(t *testing.T) {
	want := os.NewFile(0, "fake")
	calls := 0
	var slept []time.Duration
	file, err := retryManagedRuntimeOpen(func() (*os.File, error) {
		calls++
		if calls < 3 {
			return nil, errTestSharingViolation
		}
		return want, nil
	}, isTestSharingViolation, func(d time.Duration) { slept = append(slept, d) })
	if err != nil || file != want {
		t.Fatalf("open = (%v, %v), want the third attempt's file", file, err)
	}
	if calls != 3 || len(slept) != 2 {
		t.Fatalf("calls = %d slept = %v, want 3 calls and 2 waits", calls, slept)
	}
}

// Contention that outlasts the budget returns the violation, and the total
// wait stays inside the hook's budget.
func TestRetryManagedRuntimeOpenStopsAtBudget(t *testing.T) {
	calls := 0
	var total time.Duration
	_, err := retryManagedRuntimeOpen(func() (*os.File, error) {
		calls++
		return nil, errTestSharingViolation
	}, isTestSharingViolation, func(d time.Duration) { total += d })
	if !errors.Is(err, errTestSharingViolation) {
		t.Fatalf("err = %v, want the sharing violation", err)
	}
	if calls != len(managedRuntimeOpenRetryDelays)+1 {
		t.Fatalf("calls = %d, want %d", calls, len(managedRuntimeOpenRetryDelays)+1)
	}
	if total > 500*time.Millisecond {
		t.Fatalf("total wait = %v, want at most 500ms", total)
	}
}

// Any other error (not found, access denied) returns at once.
func TestRetryManagedRuntimeOpenDoesNotRetryOtherErrors(t *testing.T) {
	calls := 0
	_, err := retryManagedRuntimeOpen(func() (*os.File, error) {
		calls++
		return nil, os.ErrNotExist
	}, isTestSharingViolation, func(time.Duration) { t.Fatal("slept on a non-transient error") })
	if !errors.Is(err, os.ErrNotExist) || calls != 1 {
		t.Fatalf("err = %v calls = %d, want one not-found attempt", err, calls)
	}
}
