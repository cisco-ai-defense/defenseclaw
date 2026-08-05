// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package daemon

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestManagedIdentityReadRetriesWholeStableReadAfterSharingViolation(t *testing.T) {
	attempts := 0
	var sleeps []time.Duration
	data, err := readManagedIdentityFileWith(
		`C:\managed\watchdog.pid`,
		1024,
		func(path string, maxBytes int64) ([]byte, error) {
			attempts++
			if path != `C:\managed\watchdog.pid` || maxBytes != 1024 {
				t.Fatalf("read arguments = (%q, %d)", path, maxBytes)
			}
			if attempts < 3 {
				return nil, fmt.Errorf("transient stable-read open: %w", windows.ERROR_SHARING_VIOLATION)
			}
			return []byte(`{"pid":42}`), nil
		},
		func(delay time.Duration) {
			sleeps = append(sleeps, delay)
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != `{"pid":42}` || attempts != 3 {
		t.Fatalf("stable read = %q after %d attempts", data, attempts)
	}
	if len(sleeps) != 2 {
		t.Fatalf("retry sleeps = %d, want 2", len(sleeps))
	}
	for _, delay := range sleeps {
		if delay != managedIdentityReadRetryDelay {
			t.Fatalf("retry delay = %s, want %s", delay, managedIdentityReadRetryDelay)
		}
	}
}

func TestManagedIdentityReadSharingViolationRetryIsBounded(t *testing.T) {
	attempts := 0
	sleeps := 0
	_, err := readManagedIdentityFileWith(
		`C:\managed\watchdog.pid`,
		1024,
		func(string, int64) ([]byte, error) {
			attempts++
			return nil, windows.ERROR_SHARING_VIOLATION
		},
		func(time.Duration) {
			sleeps++
		},
	)
	if !errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
		t.Fatalf("bounded read error = %v, want sharing violation", err)
	}
	if attempts != managedIdentityReadMaxAttempts {
		t.Fatalf("stable-read attempts = %d, want %d", attempts, managedIdentityReadMaxAttempts)
	}
	if sleeps != managedIdentityReadMaxAttempts-1 {
		t.Fatalf("stable-read sleeps = %d, want %d", sleeps, managedIdentityReadMaxAttempts-1)
	}
}

func TestManagedIdentityReadDoesNotRetryPermanentFailure(t *testing.T) {
	attempts := 0
	_, err := readManagedIdentityFileWith(
		`C:\managed\watchdog.pid`,
		1024,
		func(string, int64) ([]byte, error) {
			attempts++
			return nil, windows.ERROR_ACCESS_DENIED
		},
		func(time.Duration) {
			t.Fatal("permanent failure unexpectedly slept")
		},
	)
	if !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		t.Fatalf("permanent read error = %v, want access denied", err)
	}
	if attempts != 1 {
		t.Fatalf("permanent read attempts = %d, want 1", attempts)
	}
}

func TestStartIdentityPreflightExplainsLegacyWatchdogWriterConflict(t *testing.T) {
	dataDir := t.TempDir()
	d := New(dataDir)
	watchdogPath := filepath.Join(dataDir, WatchdogPIDFileName)
	writer, err := os.OpenFile(watchdogPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	if _, err := writer.WriteString(`{"pid":42}`); err != nil {
		t.Fatal(err)
	}
	if err := writer.Sync(); err != nil {
		t.Fatal(err)
	}

	err = d.ValidateStartIdentityFiles()
	if !errors.Is(err, ErrUnsafeProcessIdentity) ||
		!errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
		t.Fatalf("writer-conflict preflight error = %v", err)
	}
	for _, want := range []string{
		"legacy or live writer",
		"safely stop the previous watchdog",
		"complete the upgrade",
		"do not delete the PID file",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("writer-conflict preflight error = %q, want %q", err, want)
		}
	}
}
