// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package config

import (
	"errors"
	"os"
	"reflect"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestReplaceConfigFileRetriesTransientWindowsErrors(t *testing.T) {
	attempts := 0
	var delays []time.Duration
	err := replaceConfigFileWith(
		"staged",
		"config.yaml",
		func(string, string) error {
			attempts++
			switch attempts {
			case 1:
				return &os.LinkError{Op: "rename", Old: "staged", New: "config.yaml", Err: windows.ERROR_SHARING_VIOLATION}
			case 2:
				return &os.LinkError{Op: "rename", Old: "staged", New: "config.yaml", Err: windows.ERROR_ACCESS_DENIED}
			default:
				return nil
			}
		},
		func(delay time.Duration) { delays = append(delays, delay) },
	)
	if err != nil {
		t.Fatalf("replaceConfigFileWith: %v", err)
	}
	if attempts != 3 {
		t.Fatalf("attempts = %d, want 3", attempts)
	}
	wantDelays := []time.Duration{10 * time.Millisecond, 20 * time.Millisecond}
	if !reflect.DeepEqual(delays, wantDelays) {
		t.Fatalf("delays = %v, want %v", delays, wantDelays)
	}
}

func TestReplaceConfigFileDoesNotRetryPermanentWindowsError(t *testing.T) {
	attempts := 0
	err := replaceConfigFileWith(
		"staged",
		"config.yaml",
		func(string, string) error {
			attempts++
			return &os.LinkError{Op: "rename", Old: "staged", New: "config.yaml", Err: windows.ERROR_FILE_NOT_FOUND}
		},
		func(time.Duration) { t.Fatal("permanent error unexpectedly slept") },
	)
	if !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		t.Fatalf("error = %v, want ERROR_FILE_NOT_FOUND", err)
	}
	if attempts != 1 {
		t.Fatalf("attempts = %d, want 1", attempts)
	}
}

func TestReplaceConfigFileBoundsTransientWindowsRetries(t *testing.T) {
	attempts := 0
	sleeps := 0
	err := replaceConfigFileWith(
		"staged",
		"config.yaml",
		func(string, string) error {
			attempts++
			return &os.LinkError{Op: "rename", Old: "staged", New: "config.yaml", Err: windows.ERROR_ACCESS_DENIED}
		},
		func(time.Duration) { sleeps++ },
	)
	if !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		t.Fatalf("error = %v, want ERROR_ACCESS_DENIED", err)
	}
	if attempts != configReplaceMaxAttempts {
		t.Fatalf("attempts = %d, want %d", attempts, configReplaceMaxAttempts)
	}
	if sleeps != configReplaceMaxAttempts-1 {
		t.Fatalf("sleeps = %d, want %d", sleeps, configReplaceMaxAttempts-1)
	}
}
