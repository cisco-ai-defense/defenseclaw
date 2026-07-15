// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package safefile

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestReplaceFileRetriesTransientWindowsErrors(t *testing.T) {
	for _, transient := range []error{
		windows.ERROR_ACCESS_DENIED,
		windows.ERROR_SHARING_VIOLATION,
		windows.ERROR_LOCK_VIOLATION,
		errorUnableToRemoveReplaced,
	} {
		transient := transient
		t.Run(transient.Error(), func(t *testing.T) {
			wantErr := &os.LinkError{Op: "rename", Old: "old", New: "new", Err: transient}
			calls := 0
			var sleeps []time.Duration
			err := replaceFileWith("old", "new", func(_, _ string) error {
				calls++
				if calls == 1 {
					return wantErr
				}
				return nil
			}, func(delay time.Duration) {
				sleeps = append(sleeps, delay)
			})
			if err != nil {
				t.Fatalf("replaceFileWith: %v", err)
			}
			if calls != 2 {
				t.Fatalf("rename calls=%d, want 2", calls)
			}
			if len(sleeps) != 1 || sleeps[0] != replaceFileRetryDelay {
				t.Fatalf("sleep calls=%v, want [%s]", sleeps, replaceFileRetryDelay)
			}
		})
	}
}

func TestReplaceFileDoesNotRetryPermanentErrors(t *testing.T) {
	for _, permanent := range []error{
		windows.ERROR_FILE_NOT_FOUND,
		windows.ERROR_ALREADY_EXISTS,
		errors.New("permanent rename failure"),
	} {
		permanent := permanent
		t.Run(permanent.Error(), func(t *testing.T) {
			wantErr := &os.LinkError{Op: "rename", Old: "old", New: "new", Err: permanent}
			calls := 0
			sleeps := 0
			got := replaceFileWith("old", "new", func(_, _ string) error {
				calls++
				return wantErr
			}, func(time.Duration) { sleeps++ })
			if got != wantErr {
				t.Fatalf("error=%v, want original %v", got, wantErr)
			}
			if calls != 1 || sleeps != 0 {
				t.Fatalf("calls=%d, sleeps=%d; want 1, 0", calls, sleeps)
			}
		})
	}
}

func TestReplaceFileStopsAtRetryBound(t *testing.T) {
	wantErr := &os.LinkError{
		Op:  "rename",
		Old: "old",
		New: "new",
		Err: windows.ERROR_SHARING_VIOLATION,
	}
	calls := 0
	var sleeps []time.Duration
	got := replaceFileWith("old", "new", func(_, _ string) error {
		calls++
		return wantErr
	}, func(delay time.Duration) {
		sleeps = append(sleeps, delay)
	})
	if got != wantErr || !errors.Is(got, windows.ERROR_SHARING_VIOLATION) {
		t.Fatalf("error=%v, want original sharing-violation error", got)
	}
	if calls != replaceFileMaxAttempts {
		t.Fatalf("rename calls=%d, want %d", calls, replaceFileMaxAttempts)
	}
	if len(sleeps) != replaceFileMaxAttempts-1 {
		t.Fatalf("sleep calls=%d, want %d", len(sleeps), replaceFileMaxAttempts-1)
	}
}

func TestReplaceFileReturnsImmediatelyOnSuccess(t *testing.T) {
	calls := 0
	sleeps := 0
	if err := replaceFileWith("old", "new", func(_, _ string) error {
		calls++
		return nil
	}, func(time.Duration) { sleeps++ }); err != nil {
		t.Fatalf("replaceFileWith: %v", err)
	}
	if calls != 1 || sleeps != 0 {
		t.Fatalf("calls=%d, sleeps=%d; want 1, 0", calls, sleeps)
	}
}

func TestReplaceFileUsesCreateMoveOnlyWhenDestinationIsMissing(t *testing.T) {
	replaces := 0
	moves := 0
	err := replaceFileOnceWith(func() error {
		replaces++
		return windows.ERROR_FILE_NOT_FOUND
	}, func() error {
		moves++
		return nil
	})
	if err != nil || replaces != 1 || moves != 1 {
		t.Fatalf("error=%v replaces=%d moves=%d, want nil/1/1", err, replaces, moves)
	}
}

func TestReplaceFileRetriesMetadataPreservingReplaceWhenCreateLosesRace(t *testing.T) {
	replaces := 0
	moves := 0
	err := replaceFileOnceWith(func() error {
		replaces++
		if replaces == 1 {
			return windows.ERROR_FILE_NOT_FOUND
		}
		return nil
	}, func() error {
		moves++
		return windows.ERROR_ALREADY_EXISTS
	})
	if err != nil || replaces != 2 || moves != 1 {
		t.Fatalf("error=%v replaces=%d moves=%d, want nil/2/1", err, replaces, moves)
	}
}

func TestReplaceFilePreservesExistingNTFSAlternateDataStream(t *testing.T) {
	dir := t.TempDir()
	destination := filepath.Join(dir, "settings.json")
	source := filepath.Join(dir, "staged.json")
	if err := os.WriteFile(destination, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	stream := destination + ":defenseclaw-test"
	if err := os.WriteFile(stream, []byte("owned metadata"), 0o600); err != nil {
		if errors.Is(err, windows.ERROR_INVALID_NAME) || errors.Is(err, windows.ERROR_NOT_SUPPORTED) {
			t.Skipf("test volume does not support NTFS alternate streams: %v", err)
		}
		t.Fatal(err)
	}
	if err := os.WriteFile(source, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ReplaceFile(source, destination); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(destination)
	if err != nil || string(content) != "new" {
		t.Fatalf("destination=%q error=%v, want new", content, err)
	}
	metadata, err := os.ReadFile(stream)
	if err != nil || string(metadata) != "owned metadata" {
		t.Fatalf("alternate stream=%q error=%v, want preserved metadata", metadata, err)
	}
}
