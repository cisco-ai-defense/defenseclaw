// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package safefile

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func withoutTransientSleep(t *testing.T) *[]time.Duration {
	t.Helper()
	var slept []time.Duration
	previous := transientRetrySleep
	transientRetrySleep = func(delay time.Duration) { slept = append(slept, delay) }
	t.Cleanup(func() { transientRetrySleep = previous })
	return &slept
}

func TestRetryTransientReadRepeatsAMomentaryMiss(t *testing.T) {
	for _, transient := range []error{
		windows.ERROR_FILE_NOT_FOUND, windows.ERROR_SHARING_VIOLATION, windows.ERROR_LOCK_VIOLATION,
	} {
		t.Run(transient.Error(), func(t *testing.T) {
			slept := withoutTransientSleep(t)
			calls := 0
			err := RetryTransientRead(func() error {
				calls++
				if calls < 3 {
					return &os.PathError{Op: "open", Path: `C:\x`, Err: transient}
				}
				return nil
			})
			if err != nil || calls != 3 || len(*slept) != 2 {
				t.Fatalf("err=%v calls=%d sleeps=%d, want nil, 3, 2", err, calls, len(*slept))
			}
		})
	}
}

func TestRetryPublishedReadSurvivesFastIdentityChanges(t *testing.T) {
	slept := withoutTransientSleep(t)
	calls := 0
	err := RetryPublishedRead(func() error {
		calls++
		if calls <= 64 {
			return ErrReadIdentityChanged
		}
		return nil
	})
	if err != nil || calls != 65 || len(*slept) != 64 {
		t.Fatalf("err=%v calls=%d waits=%d; want nil, 65, 64", err, calls, len(*slept))
	}
}

func TestRetryPublishedReadKeepsStableAndPermanentResults(t *testing.T) {
	slept := withoutTransientSleep(t)
	for _, expected := range []error{nil, windows.ERROR_ACCESS_DENIED} {
		calls := 0
		err := RetryPublishedRead(func() error { calls++; return expected })
		if !errors.Is(err, expected) || calls != 1 {
			t.Fatalf("expected=%v err=%v calls=%d; want one attempt", expected, err, calls)
		}
	}
	if len(*slept) != 0 {
		t.Fatalf("waited for stable or permanent results: %v", *slept)
	}
}

func TestRetryPublishedReadReportsRealAbsenceWithinItsWindow(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent.json")
	started := time.Now()
	err := RetryPublishedRead(func() error {
		_, err := os.Lstat(path)
		return err
	})
	if !errors.Is(err, os.ErrNotExist) || time.Since(started) > time.Second {
		t.Fatalf("err=%v elapsed=%v; want bounded absence", err, time.Since(started))
	}
}

func TestRetryTransientReadReportsARealAbsenceInBoundedTime(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "never-written.json")
	calls := 0
	started := time.Now()
	err := RetryTransientRead(func() error {
		calls++
		_, err := os.Lstat(missing)
		return err
	})
	elapsed := time.Since(started)
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("err = %v, want not-exist", err)
	}
	if calls != len(transientRetryDelays)+1 {
		t.Fatalf("read ran %d times, want %d", calls, len(transientRetryDelays)+1)
	}
	var budget time.Duration
	for _, delay := range transientRetryDelays {
		budget += delay
	}
	if budget > 60*time.Millisecond {
		t.Fatalf("retry budget is %v, want at most 60ms", budget)
	}
	// Windows timer resolution can stretch each sleep to about 16 ms.
	if elapsed > budget+time.Duration(len(transientRetryDelays))*20*time.Millisecond+200*time.Millisecond {
		t.Fatalf("a real absence took %v to report", elapsed)
	}
}

func TestRetryTransientReadFailsAtOnceWithoutTheFolder(t *testing.T) {
	slept := withoutTransientSleep(t)
	missing := filepath.Join(t.TempDir(), "no-folder", "policy.json")
	calls := 0
	err := RetryTransientRead(func() error {
		calls++
		_, err := os.Lstat(missing)
		return err
	})
	if !errors.Is(err, windows.ERROR_PATH_NOT_FOUND) || calls != 1 || len(*slept) != 0 {
		t.Fatalf("err=%v calls=%d sleeps=%d, want path-not-found at once", err, calls, len(*slept))
	}
}

func TestRetryTransientReadDoesNotRepeatOtherErrors(t *testing.T) {
	slept := withoutTransientSleep(t)
	for _, permanent := range []error{
		nil, windows.ERROR_ACCESS_DENIED, errors.New("parse error"),
		fmt.Errorf("wrapped: %w", windows.ERROR_INVALID_PARAMETER),
	} {
		calls := 0
		err := RetryTransientRead(func() error { calls++; return permanent })
		if !errors.Is(err, permanent) || calls != 1 {
			t.Fatalf("%v: err=%v calls=%d, want the error once", permanent, err, calls)
		}
	}
	if len(*slept) != 0 {
		t.Fatalf("slept %d times for errors that are not transient", len(*slept))
	}
}
