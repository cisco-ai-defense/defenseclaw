//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package safefile

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func missingName() error {
	return &os.PathError{Op: "open", Path: `C:\x`, Err: windows.ERROR_FILE_NOT_FOUND}
}

// GAP-2184: an optional read of a name missing from the start looks once
// more after the first wait, then reports absence.
func TestRetryOptionalReadReportsAbsenceAfterOneLook(t *testing.T) {
	slept := withoutTransientSleep(t)
	path := filepath.Join(t.TempDir(), "absent.json")
	calls := 0
	err := RetryOptionalRead(func() error {
		calls++
		_, err := os.Lstat(path)
		return err
	})
	if !errors.Is(err, os.ErrNotExist) || calls != 2 || len(*slept) != 1 {
		t.Fatalf("err=%v calls=%d waits=%d, want absence after 2 reads and 1 wait", err, calls, len(*slept))
	}
}

// A file published during that one wait is read.
func TestRetryOptionalReadReadsAFilePublishedDuringTheLook(t *testing.T) {
	path := filepath.Join(t.TempDir(), "late.json")
	t.Cleanup(SetTransientRetrySleepForTest(func(time.Duration) {
		_ = os.WriteFile(path, []byte("x"), 0o600)
	}))
	err := RetryOptionalRead(func() error {
		_, err := os.Lstat(path)
		return err
	})
	if err != nil {
		t.Fatalf("err=%v, want the published file", err)
	}
}

// A name seen and then missing keeps the whole budget, whether the read says
// so (NameVanished) or an earlier attempt proved the name (a sharing
// violation).
func TestRetryOptionalReadKeepsTheBudgetForASeenName(t *testing.T) {
	for name, first := range map[string]error{
		"vanished":          NameVanished(missingName()),
		"sharing violation": &os.PathError{Op: "open", Path: `C:\x`, Err: windows.ERROR_SHARING_VIOLATION},
	} {
		t.Run(name, func(t *testing.T) {
			slept := withoutTransientSleep(t)
			calls := 0
			err := RetryOptionalRead(func() error {
				calls++
				if calls == 1 {
					return first
				}
				if calls < 20 {
					return missingName()
				}
				return nil
			})
			if err != nil || calls != 20 || len(*slept) != 19 {
				t.Fatalf("err=%v calls=%d waits=%d, want success after 20 reads", err, calls, len(*slept))
			}
		})
	}
}

// NameVanished keeps the missing-name result visible to callers and marks it
// as an identity change; other results pass through.
func TestNameVanishedMarksOnlyAMissingName(t *testing.T) {
	err := NameVanished(missingName())
	if !errors.Is(err, os.ErrNotExist) || !errors.Is(err, ErrReadIdentityChanged) || !IsTransientReadError(err) {
		t.Fatalf("err=%v, want not-exist and identity changed", err)
	}
	for _, other := range []error{nil, windows.ERROR_ACCESS_DENIED, windows.ERROR_PATH_NOT_FOUND} {
		if got := NameVanished(other); got != other {
			t.Fatalf("NameVanished(%v) = %v, want it unchanged", other, got)
		}
	}
}

// RetryTransientRead, for a file that is expected, still waits out the
// whole budget for a missing name.
func TestRetryTransientReadKeepsTheBudgetForAnExpectedFile(t *testing.T) {
	slept := withoutTransientSleep(t)
	calls := 0
	err := RetryTransientRead(func() error { calls++; return missingName() })
	if !errors.Is(err, os.ErrNotExist) || calls != len(transientRetryDelays)+1 || len(*slept) != len(transientRetryDelays) {
		t.Fatalf("err=%v calls=%d waits=%d", err, calls, len(*slept))
	}
}
